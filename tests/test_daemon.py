import contextlib
import io
import os
import threading
import unittest
from unittest import mock

from fido2 import cbor

from passkeyd import daemon
from passkeyd.ctap2 import ERR_NO_CREDENTIALS


class FakeApprover:
    def __init__(self):
        self.notes = []

    def notify(self, text):
        self.notes.append(text)

    def pick(self, *a):
        raise AssertionError("no picker expected")

    def verify(self, *a):
        raise AssertionError("no fingerprint expected")


class TestDaemon(unittest.TestCase):
    def test_run_without_session_still_answers(self):
        ap = FakeApprover()
        sent = []
        parts = daemon.build(send=sent.append, session_provider=lambda: None, approver=ap, bw="bw")
        parts.vault.sync()
        out = parts.authenticator.handle(
            b"\x02" + cbor.encode({1: "discord.com", 2: os.urandom(32), 5: {"uv": True}}),
            threading.Event())
        self.assertEqual(out, bytes([ERR_NO_CREDENTIALS]))
        self.assertEqual(len(ap.notes), 1)
        self.assertIn("python3 -m passkeyd setup", ap.notes[0])

    def test_setup_saves_without_printing_token(self):
        saved = []
        fake_ap = mock.Mock()
        fake_ap.ask_password.return_value = "hunter2"
        buf = io.StringIO()
        with mock.patch.object(daemon, "Approver", return_value=fake_ap), \
                mock.patch.object(daemon, "setup_session", return_value="TOKEN123") as su, \
                mock.patch.object(daemon, "save_session", side_effect=saved.append), \
                contextlib.redirect_stdout(buf):
            rc = daemon.main(["setup"])
        self.assertEqual(rc, 0)
        self.assertEqual(saved, ["TOKEN123"])
        self.assertEqual(su.call_args.args[0], "hunter2")
        self.assertNotIn("TOKEN123", buf.getvalue())
        self.assertNotIn("hunter2", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
