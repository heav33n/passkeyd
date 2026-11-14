import io
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from passkeyd.approver import Approver
from passkeyd.model import Cancelled, Credential

MATCH = b"Using device ...\nVerify started!\nVerify result: verify-match (done)\n"
NO_MATCH = b"Verify started!\nVerify result: verify-no-match (done)\n"
BUSY = b"failed to claim device: Device was already claimed\n"


def cred(user, created):
    return Credential("discord.com", user.encode(), ec.generate_private_key(ec.SECP256R1()),
                      b"h", user, user.title(), "discord.com", created, 0)


class FakeProc:
    def __init__(self, args, out=b"", rc=0, polls=1):
        self.args, self.stdout = args, io.BytesIO(out)
        self._rc, self._polls, self.killed = rc, polls, False
        self.returncode = None

    def poll(self):
        if self.killed:
            return self.returncode
        if self._polls is None:  # runs forever
            return None
        self._polls -= 1
        if self._polls <= 0:
            self.returncode = self._rc
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed, self.returncode = True, -9

    terminate = kill


class Spawner:
    """Hands out scripted processes by kind: 'list', 'info', 'fprintd', 'notify'."""

    def __init__(self, **scripts):
        self.scripts = {k: list(v) for k, v in scripts.items()}
        self.procs = []

    def __call__(self, args, **kw):
        kind = ("fprintd" if args[0] == "fprintd-verify" else
                "notify" if args[0] == "notify-send" else
                "list" if "--list" in args else "info" if "--info" in args else "other")
        spec = self.scripts.get(kind, [{}]).pop(0) if self.scripts.get(kind) else {}
        p = FakeProc(args, **spec)
        self.procs.append((kind, p))
        return p

    def of(self, kind):
        return [p for k, p in self.procs if k == kind]


FOREVER = {"polls": None}


class TestPick(unittest.TestCase):
    def test_pick_returns_selected(self):
        sp = Spawner(list=[{"out": b"2\n"}])
        creds = [cred("a@x", "2025-01-01"), cred("b@x", "2025-02-02")]
        self.assertIs(Approver(spawn=sp, poll=0).pick("discord.com", creds, threading.Event()), creds[1])
        args = sp.of("list")[0].args
        self.assertIn("Sign in to discord.com", args)
        self.assertIn("2025-02-02", args)

    def test_pick_cancel_returns_none(self):
        sp = Spawner(list=[{"rc": 1}])
        self.assertIsNone(Approver(spawn=sp, poll=0).pick("d", [cred("a", "1"), cred("b", "2")],
                                                            threading.Event()))


class TestSanitize(unittest.TestCase):
    def test_hostile_values_cannot_become_options_or_markup(self):
        sp = Spawner(list=[{"out": b"1\n"}], info=[FOREVER], fprintd=[{"out": MATCH}])
        evil = cred("--print-column=ALL", "--width=1")
        evil.display_name = "<b>Bank</b>\nline2\x07"
        ap = Approver(spawn=sp, poll=0)
        ap.pick("--html", [evil, cred("b", "2")], threading.Event())
        ap.verify("x.com\n\nThis is a system dialog", evil, threading.Event())
        list_args = sp.of("list")[0].args
        values = list_args[list_args.index("--height") + 2:]
        self.assertFalse(any(v.startswith("-") for v in values), values)
        self.assertFalse(any("\n" in a or "\x07" in a for a in list_args))
        self.assertNotIn("--html", list_args)
        info_args = sp.of("info")[0].args
        self.assertIn("--no-markup", info_args)
        self.assertFalse(any("\n" in a for a in info_args))


class TestVerify(unittest.TestCase):
    def test_verify_match_first_try(self):
        sp = Spawner(info=[FOREVER], fprintd=[{"out": MATCH, "polls": 3}])
        self.assertTrue(Approver(spawn=sp, poll=0).verify("discord.com", cred("a@x", "1"), threading.Event()))
        self.assertEqual(len(sp.of("fprintd")), 1)
        self.assertTrue(sp.of("info")[0].killed)
        self.assertIn("a@x", " ".join(sp.of("info")[0].args))

    def test_verify_three_failures_returns_false(self):
        sp = Spawner(info=[FOREVER], fprintd=[{"out": NO_MATCH, "rc": 1}] * 3)
        self.assertFalse(Approver(spawn=sp, poll=0).verify("d", cred("a", "1"), threading.Event()))
        self.assertEqual(len(sp.of("fprintd")), 3)
        self.assertGreaterEqual(len(sp.of("notify")), 1)

    def test_verify_device_busy_counts_as_failure(self):
        sp = Spawner(info=[FOREVER], fprintd=[{"out": BUSY, "rc": 1}, {"out": MATCH}])
        self.assertTrue(Approver(spawn=sp, poll=0).verify("d", cred("a", "1"), threading.Event()))
        self.assertEqual(len(sp.of("fprintd")), 2)

    def test_cancel_kills_children(self):
        sp = Spawner(info=[FOREVER], fprintd=[FOREVER])
        cancel = threading.Event()
        ap = Approver(spawn=sp, poll=0.01)
        threading.Timer(0.05, cancel.set).start()
        with self.assertRaises(Cancelled):
            ap.verify("d", cred("a", "1"), cancel)
        self.assertTrue(all(p.killed for k, p in sp.procs if k in ("info", "fprintd")))

    def test_cancel_during_pick_kills_dialog(self):
        sp = Spawner(list=[FOREVER])
        cancel = threading.Event()
        threading.Timer(0.05, cancel.set).start()
        with self.assertRaises(Cancelled):
            Approver(spawn=sp, poll=0.01).pick("d", [cred("a", "1"), cred("b", "2")], cancel)
        self.assertTrue(sp.of("list")[0].killed)

    def test_dialog_closed_aborts(self):
        sp = Spawner(info=[{"rc": 0, "polls": 2}], fprintd=[FOREVER])
        self.assertFalse(Approver(spawn=sp, poll=0).verify("d", cred("a", "1"), threading.Event()))
        self.assertTrue(sp.of("fprintd")[0].killed)


if __name__ == "__main__":
    unittest.main()
