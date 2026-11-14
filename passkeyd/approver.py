"""User interaction: account picker (zenity), fingerprint (fprintd-verify), notifications."""
import logging
import re
import subprocess
import threading
import time
import unicodedata

from .model import Cancelled, Credential

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
MATCH_RE = re.compile(r"Verify result: verify-match\b")


def clean(value: str, limit: int = 80) -> str:
    """Make app/site-supplied text safe to show in zenity: no control chars or
    newlines, bounded length, and never parseable as a command-line option."""
    text = "".join(ch if unicodedata.category(ch)[0] != "C" else " " for ch in value)
    text = " ".join(text.split())[:limit]
    return " " + text if text.startswith("-") else text


class Approver:
    def __init__(self, spawn=subprocess.Popen, poll: float = 0.05):
        self.spawn, self.poll = spawn, poll

    # ---- helpers --------------------------------------------------------
    def notify(self, text: str) -> None:
        try:
            self.spawn(["notify-send", "-a", "passkeyd", "passkeyd", text],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            log.warning("could not show notification")

    def ask_password(self, text: str) -> str | None:
        p = self.spawn(["zenity", "--password", "--title", "passkeyd", "--text", text],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out = p.stdout.read()
        p.wait()
        if p.returncode != 0:
            return None
        return out.decode().rstrip("\n") or None

    @staticmethod
    def _kill(*procs) -> None:
        for p in procs:
            if p is not None and p.poll() is None:
                p.kill()
                try:
                    p.wait(timeout=1)
                except Exception:
                    pass

    def _sleep(self):
        if self.poll:
            time.sleep(self.poll)

    # ---- ApproverLike ---------------------------------------------------
    def pick(self, rp_id: str, creds: list[Credential], cancel: threading.Event) -> Credential | None:
        args = ["zenity", "--list", "--title", f"Sign in to {clean(rp_id)}",
                "--text", "Choose the account to sign in with",
                "--column", "#", "--column", "User", "--column", "Name",
                "--column", "Vault item", "--column", "Created",
                "--hide-column", "1", "--print-column", "1", "--width", "640", "--height", "320"]
        for i, c in enumerate(creds, 1):
            args += [str(i), clean(c.user_name), clean(c.display_name), clean(c.item_name),
                     clean(c.created)]
        p = self.spawn(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            while p.poll() is None:
                if cancel.is_set():
                    raise Cancelled()
                self._sleep()
            if p.returncode != 0:
                return None
            choice = p.stdout.read().decode().strip().split("|")[0]
            try:
                return creds[int(choice) - 1]
            except (ValueError, IndexError):
                return None
        finally:
            self._kill(p)

    def verify(self, rp_id: str, cred: Credential, cancel: threading.Event) -> bool:
        dialog = self.spawn(
            ["zenity", "--info", "--title", "passkeyd", "--no-wrap", "--no-markup",
             "--ok-label", "Cancel", "--text",
             f"Touch the fingerprint sensor to sign in to {clean(rp_id)} as {clean(cred.user_name)}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fp = None
        try:
            for attempt in range(1, MAX_ATTEMPTS + 1):
                fp = self.spawn(["fprintd-verify"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                while fp.poll() is None:
                    if cancel.is_set():
                        raise Cancelled()
                    if dialog.poll() is not None:
                        log.info("user closed the fingerprint prompt")
                        return False
                    self._sleep()
                if MATCH_RE.search(fp.stdout.read().decode(errors="replace")):
                    return True
                log.info("fingerprint attempt %d failed", attempt)
                self.notify("Fingerprint not recognised" +
                            (", try again" if attempt < MAX_ATTEMPTS else " — sign-in refused"))
            return False
        finally:
            self._kill(fp, dialog)
