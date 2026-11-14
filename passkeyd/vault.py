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
    for it in items:
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
                log.warning("skipping a passkey in item %r: %s", it.get("name"), type(e).__name__)
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
        p = self._run([self.bw, *args, "--nointeraction"], env=env, capture_output=True)
        text = (p.stdout + p.stderr).decode(errors="replace").lower()
        if any(m in text for m in LOCKED_MARKERS):
            raise VaultLocked("Bitwarden vault is locked")
        if p.returncode != 0:
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
        self._lock = threading.RLock()
        self._last_sync: float | None = None
        self._last_no_match: float | None = None
        self._locked = False

    @property
    def count(self) -> int:
        return len(self._creds)

    def _filter(self, rp_id, allow):
        return [c for c in self._creds if c.rp_id == rp_id
                and (not allow or c.credential_id in allow)]

    def find(self, rp_id: str, allow: set[bytes]) -> list[Credential]:
        with self._lock:
            found = self._filter(rp_id, allow)
            if not found:
                self.maybe_resync(no_match=True)
                found = self._filter(rp_id, allow)
            return found

    def maybe_resync(self, no_match: bool) -> None:
        with self._lock:
            now = self.clock()
            if no_match:
                if self._last_no_match is None or now - self._last_no_match >= NO_MATCH_RESYNC:
                    self._last_no_match = now
                    self.sync()
            elif self._last_sync is None or now - self._last_sync >= PERIODIC_RESYNC:
                self.sync()

    def sync(self) -> None:
        with self._lock:
            self._last_sync = self.clock()
            try:
                try:
                    self.runner.run(["sync"])
                except VaultLocked:
                    raise
                except Exception as e:  # offline etc.: fall back to the local copy
                    log.warning("bw sync failed, using local vault copy: %s", e)
                items = json.loads(self.runner.run(["list", "items"]))
            except VaultLocked:
                self._creds = []
                if not self._locked:
                    self._locked = True
                    log.warning("Bitwarden is locked; passkeys unavailable")
                    self.on_locked()
                return
            except Exception as e:
                log.warning("could not read vault, keeping previous passkeys: %s", e)
                return
            self._locked = False
            self._creds = parse_items(items)
            log.info("loaded %d passkeys", len(self._creds))
