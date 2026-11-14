import base64
import json
import subprocess
import unittest
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from passkeyd.vault import (BwRunner, Vault, VaultLocked, decode_credential_id, parse_items,
                            setup_session)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pk8(curve=ec.SECP256R1()):
    k = ec.generate_private_key(curve)
    return k, b64u(k.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))


def fido(rp="discord.com", user="me@x", cid=None, key=None):
    return {"credentialId": cid or str(uuid.uuid4()), "keyType": "public-key",
            "keyAlgorithm": "ECDSA", "keyCurve": "P-256", "keyValue": key or pk8()[1],
            "rpId": rp, "userHandle": b64u(b"handle-" + user.encode()), "userName": user,
            "userDisplayName": user.upper(), "counter": "0", "rpName": rp,
            "discoverable": "true", "creationDate": "2025-03-04T05:06:07.000Z"}


def item(name, *creds):
    return {"name": name, "login": {"username": "x", "fido2Credentials": list(creds)}}


class FakeRunner:
    def __init__(self, items):
        self.items, self.calls, self.locked = items, [], False

    def run(self, args, extra_env=None):
        self.calls.append(args)
        if self.locked:
            raise VaultLocked("Vault is locked.")
        if args[:2] == ["list", "items"]:
            return json.dumps(self.items).encode()
        return b""


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TestDecode(unittest.TestCase):
    def test_decode_uuid_id(self):
        s = "0e2d5f4c-1111-2222-3333-444455556666"
        self.assertEqual(decode_credential_id(s), uuid.UUID(s).bytes)
        self.assertEqual(len(decode_credential_id(s)), 16)

    def test_decode_b64_id(self):
        self.assertEqual(decode_credential_id("b64.AQID"), b"\x01\x02\x03")


class TestParse(unittest.TestCase):
    def test_parse_items(self):
        k, kv = pk8()
        items = [item("discord.com", fido(user="a@x", key=kv), fido(user="b@x")),
                 {"name": "no passkeys", "login": {"username": "u"}},
                 {"name": "a note", "login": None}]
        creds = parse_items(items)
        self.assertEqual([c.user_name for c in creds], ["a@x", "b@x"])
        c = creds[0]
        self.assertEqual((c.rp_id, c.item_name, c.display_name, c.counter, c.created),
                         ("discord.com", "discord.com", "A@X", 0, "2025-03-04"))
        self.assertEqual(c.user_handle, b"handle-a@x")
        sig = c.private_key.sign(b"msg", ec.ECDSA(hashes.SHA256()))
        k.public_key().verify(sig, b"msg", ec.ECDSA(hashes.SHA256()))

    def test_bad_key_skipped(self):
        with self.assertLogs("passkeyd.vault", level="WARNING"):
            creds = parse_items([item("d", fido(user="bad", key="garbage"),
                                      fido(user="p384", key=pk8(ec.SECP384R1())[1]),
                                      fido(user="good"))])
        self.assertEqual([c.user_name for c in creds], ["good"])


class TestVault(unittest.TestCase):
    def make(self, items):
        runner, clock, locked = FakeRunner(items), Clock(), []
        return Vault(runner, on_locked=lambda: locked.append(1), clock=clock), runner, clock, locked

    def test_find_filters_rp_and_allowlist(self):
        a, b = fido(user="a"), fido(user="b")
        v, *_ = self.make([item("d", a, b), item("o", fido(rp="other.com"))])
        v.sync()
        self.assertEqual({c.user_name for c in v.find("discord.com", set())}, {"a", "b"})
        bid = uuid.UUID(b["credentialId"]).bytes
        self.assertEqual([c.user_name for c in v.find("discord.com", {bid})], ["b"])

    def test_locked_wipes(self):
        v, runner, _, locked = self.make([item("d", fido())])
        v.sync()
        self.assertEqual(len(v.find("discord.com", set())), 1)
        runner.locked = True
        v.sync()
        self.assertEqual(v.find("discord.com", set()), [])
        self.assertEqual(locked, [1])

    def test_network_failure_keeps_cache(self):
        v, runner, _, locked = self.make([item("d", fido())])
        v.sync()
        orig = runner.run

        def flaky(args, extra_env=None):
            if args[:1] == ["sync"]:
                raise RuntimeError("network down")
            return orig(args, extra_env)
        runner.run = flaky
        v.sync()
        self.assertEqual(len(v.find("discord.com", set())), 1)
        self.assertEqual(locked, [])

    def test_resync_rate_limit(self):
        v, runner, clock, _ = self.make([])
        syncs = lambda: sum(1 for c in runner.calls if c[:1] == ["sync"])
        v.maybe_resync(no_match=True)
        self.assertEqual(syncs(), 1)
        clock.t = 30
        v.maybe_resync(no_match=True)
        self.assertEqual(syncs(), 1)
        clock.t = 61
        v.maybe_resync(no_match=True)
        self.assertEqual(syncs(), 2)
        clock.t = 600
        v.maybe_resync(no_match=False)
        self.assertEqual(syncs(), 2)
        clock.t = 662
        v.maybe_resync(no_match=False)
        self.assertEqual(syncs(), 3)

    def test_find_no_match_triggers_resync(self):
        v, runner, _, _ = self.make([])
        runner.items = [item("d", fido())]
        self.assertEqual(len(v.find("discord.com", set())), 1)


class FakeRun:
    def __init__(self, stdout=b"", returncode=0, stderr=b""):
        self.calls, self.result = [], (stdout, returncode, stderr)

    def __call__(self, args, env=None, capture_output=None, **kw):
        self.calls.append((args, env))
        out, rc, err = self.result
        return subprocess.CompletedProcess(args, rc, out, err)


class TestRunner(unittest.TestCase):
    def test_session_never_in_argv(self):
        fr = FakeRun(stdout=b"[]")
        BwRunner(lambda: "SESSIONTOKEN", bw="bw", run=fr).run(["list", "items"])
        args, env = fr.calls[0]
        self.assertNotIn("SESSIONTOKEN", " ".join(args))
        self.assertEqual(env["BW_SESSION"], "SESSIONTOKEN")
        self.assertIn("--nointeraction", args)

    def test_password_never_in_argv(self):
        fr = FakeRun(stdout=b"NEWTOKEN")
        self.assertEqual(setup_session("hunter2", bw="bw", run=fr), "NEWTOKEN")
        args, env = fr.calls[0]
        self.assertNotIn("hunter2", " ".join(args))
        self.assertEqual(env["PASSKEYD_PW"], "hunter2")

    def test_no_session_is_locked(self):
        with self.assertRaises(VaultLocked):
            BwRunner(lambda: None, run=FakeRun()).run(["list", "items"])

    def test_vault_content_mentioning_lock_is_not_locked(self):
        fr = FakeRun(stdout=b'[{"name": "Vault is locked", "notes": "not logged in"}]', returncode=0)
        self.assertIn(b"Vault is locked", BwRunner(lambda: "t", run=fr).run(["list", "items"]))

    def test_skipped_item_name_not_logged(self):
        with self.assertLogs("passkeyd.vault", level="WARNING") as logs:
            parse_items([item("my-secret-bank", fido(key="garbage"))])
        self.assertFalse(any("my-secret-bank" in line for line in logs.output))

    def test_locked_message_is_locked(self):
        fr = FakeRun(stdout=b"Vault is locked.", returncode=1)
        with self.assertRaises(VaultLocked):
            BwRunner(lambda: "t", run=fr).run(["list", "items"])


if __name__ == "__main__":
    unittest.main()
