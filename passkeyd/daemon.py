"""Entry point: `passkeyd run | setup | status`."""
import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable

from .approver import Approver
from .ctap2 import Authenticator
from .ctaphid import CtapHid
from .session import load_session, save_session
from .uhid import UhidDevice
from .vault import BwRunner, Vault, VaultLocked, setup_session

log = logging.getLogger("passkeyd")

LOCKED_HINT = "Bitwarden is locked — run: cd ~/passkeyd && python3 -m passkeyd setup"
RESYNC_TICK = 60.0


def find_bw() -> str:
    return shutil.which("bw") or os.path.expanduser("~/.local/bin/bw")


@dataclass
class Parts:
    vault: Vault
    authenticator: Authenticator
    hid: CtapHid


def build(send: Callable[[bytes], None], session_provider, approver, bw: str) -> Parts:
    vault = Vault(BwRunner(session_provider, bw=bw), on_locked=lambda: approver.notify(LOCKED_HINT))
    auth = Authenticator(vault, approver)
    return Parts(vault, auth, CtapHid(send, auth.handle))


def cmd_run() -> int:
    dev = UhidDevice()
    try:
        dev.open()
    except PermissionError as e:
        log.error("%s", e)
        return 1
    parts = build(dev.send_input, load_session, Approver(), find_bw())
    stop = threading.Event()

    def background():
        parts.vault.sync()
        while not stop.wait(RESYNC_TICK):
            parts.vault.maybe_resync(no_match=False)

    threading.Thread(target=background, daemon=True).start()

    def on_signal(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_signal)
    log.info("virtual security key ready")
    try:
        while True:
            report = dev.read_output()
            if report:
                parts.hid.on_report(report)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        dev.close()
        log.info("virtual security key removed")
    return 0


def cmd_setup() -> int:
    password = Approver().ask_password("Bitwarden master password (stored only as a session in your keyring)")
    if not password:
        print("Cancelled.")
        return 1
    try:
        token = setup_session(password, bw=find_bw())
    except VaultLocked as e:
        print(f"Failed: {e}")
        return 1
    save_session(token)
    print("Saved. Restart the service to load passkeys: systemctl --user restart passkeyd")
    return 0


def cmd_status() -> int:
    print("/dev/uhid access:", "ok" if os.access("/dev/uhid", os.R_OK | os.W_OK) else "DENIED")
    session = load_session()
    print("session in keyring:", "yes" if session else "no")
    bw = find_bw()
    try:
        p = subprocess.run([bw, "status", "--nointeraction"], capture_output=True,
                           env={**os.environ, **({"BW_SESSION": session} if session else {})})
        print("bitwarden:", json.loads(p.stdout).get("status"))
    except Exception as e:
        print("bitwarden: unknown", type(e).__name__)
    if session:
        v = Vault(BwRunner(lambda: session, bw=bw))
        v.sync()
        print("passkeys loaded:", v.count)
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="passkeyd")
    ap.add_argument("command", choices=["run", "setup", "status"])
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return {"run": cmd_run, "setup": cmd_setup, "status": cmd_status}[args.command]()
