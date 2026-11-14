"""Bitwarden passkeys via the `bw` CLI, kept in memory only."""
import base64
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key

from .model import Credential

log = logging.getLogger(__name__)

PERIODIC_RESYNC = 600.0
NO_MATCH_RESYNC = 60.0
BW_TIMEOUT = 30.0
LOCKED_MARKERS = ("vault is locked", "not logged in", "you are not logged in", "invalid session")


class VaultLocked(Exception):
    pass


class BwError(Exception):
    pass


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_credential_id(s: str) -> bytes:
    if s.startswith("b64."):
        return _b64u(s[4:])
    try:
        return uuid.UUID(s).bytes
    except ValueError:
        return _b64u(s)


def parse_items(items: list[dict]) -> list[Credential]:
    creds = []
    for index, it in enumerate(items):
        for fc in ((it.get("login") or {}).get("fido2Credentials") or []):
            try:
                key = load_der_private_key(_b64u(fc["keyValue"]), None)
                if not (isinstance(key, ec.EllipticCurvePrivateKey)
                        and key.curve.name == "secp256r1"):
                    raise ValueError("not a P-256 key")
                creds.append(Credential(
                    rp_id=fc["rpId"], credential_id=decode_credential_id(fc["credentialId"]),
                    private_key=key, user_handle=_b64u(fc.get("userHandle") or ""),
                    user_name=fc.get("userName") or "", display_name=fc.get("userDisplayName") or "",
                    item_name=it.get("name") or "", created=(fc.get("creationDate") or "")[:10],
                    counter=int(fc.get("counter") or 0)))
            except Exception as e:
                log.warning("skipping a passkey in vault item #%d: %s", index, type(e).__name__)
    return creds


class BwRunner:
    def __init__(self, session_provider: Callable[[], str | None], bw: str = "bw",
                 run=subprocess.run):
        self.session_provider, self.bw, self._run = session_provider, bw, run

    def run(self, args: list[str], extra_env: dict | None = None) -> bytes:
        session = self.session_provider()
        if not session:
            raise VaultLocked("no Bitwarden session stored")
        env = {**os.environ, **(extra_env or {}), "BW_SESSION": session}
        try:
            p = self._run([self.bw, *args, "--nointeraction"], env=env, capture_output=True,
                          timeout=BW_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise BwError(f"bw {args[0]} timed out after {BW_TIMEOUT:.0f}s") from None
        if p.returncode != 0:
            # Only inspect output of a failed call: successful stdout is vault content.
            text = (p.stdout + p.stderr).decode(errors="replace").lower()
            if any(m in text for m in LOCKED_MARKERS):
                raise VaultLocked("Bitwarden vault is locked")
            raise BwError(f"bw {args[0]} failed (exit {p.returncode})")
        return p.stdout


def setup_session(password: str, bw: str = "bw", run=subprocess.run) -> str:
    p = run([bw, "unlock", "--raw", "--passwordenv", "PASSKEYD_PW", "--nointeraction"],
            env={**os.environ, "PASSKEYD_PW": password}, capture_output=True)
    token = p.stdout.decode().strip()
    if p.returncode != 0 or not token:
        raise VaultLocked("bw unlock failed (wrong master password?)")
    return token


class Vault:
    def __init__(self, runner, on_locked: Callable[[], None] = lambda: None,
                 clock: Callable[[], float] = time.monotonic):
        self.runner, self.on_locked, self.clock = runner, on_locked, clock
        self._creds: list[Credential] = []
        self._lock = threading.Lock()          # guards state only, never held during bw I/O
        self._idle = threading.Event()
        self._idle.set()
        self._last_sync: float | None = None
        self._last_no_match: float | None = None
        self._last_locked_notice: float | None = None
        self._locked = False

    @property
    def count(self) -> int:
        return len(self._creds)

    def wait_idle(self, timeout: float | None = None) -> bool:
        return self._idle.wait(timeout)

    def find(self, rp_id: str, allow: set[bytes]) -> list[Credential]:
        with self._lock:
            found = [c for c in self._creds if c.rp_id == rp_id
                     and (not allow or c.credential_id in allow)]
            locked = self._locked
        if not found:
            # Answer now (fail fast); refresh in the background for the next try.
            if locked:
                self._notify_locked()
            self.maybe_resync(no_match=True, background=True)
        return found

    def maybe_resync(self, no_match: bool, background: bool = False) -> None:
        now = self.clock()
        with self._lock:
            if no_match:
                due = self._last_no_match is None or now - self._last_no_match >= NO_MATCH_RESYNC
                if due:
                    self._last_no_match = now
            else:
                due = self._last_sync is None or now - self._last_sync >= PERIODIC_RESYNC
        if not due:
            return
        if background:
            threading.Thread(target=self.sync, daemon=True).start()
        else:
            self.sync()

    def _notify_locked(self) -> None:
        now = self.clock()
        with self._lock:
            if (self._last_locked_notice is not None
                    and now - self._last_locked_notice < NO_MATCH_RESYNC):
                return
            self._last_locked_notice = now
        self.on_locked()

    def sync(self) -> None:
        with self._lock:
            if not self._idle.is_set():
                return  # a sync is already running
            self._idle.clear()
            self._last_sync = self.clock()
        try:
            self._sync_unlocked()
        finally:
            self._idle.set()

    def _sync_unlocked(self) -> None:
        try:
            try:
                self.runner.run(["sync"])
            except VaultLocked:
                raise
            except Exception as e:  # offline etc.: fall back to the local copy
                log.warning("bw sync failed, using local vault copy: %s", e)
            items = json.loads(self.runner.run(["list", "items"]))
        except VaultLocked:
            with self._lock:
                self._creds = []
                was_locked, self._locked = self._locked, True
            if not was_locked:
                log.warning("Bitwarden is locked; passkeys unavailable")
                self._notify_locked()
            return
        except Exception as e:
            log.warning("could not read vault, keeping previous passkeys: %s", e)
            return
        creds = parse_items(items)
        with self._lock:
            self._locked = False
            self._creds = creds
        log.info("loaded %d passkeys", len(creds))
