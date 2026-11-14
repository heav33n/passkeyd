import os
import threading
import unittest
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor

from passkeyd.ctap2 import (AAGUID, ERR_INVALID_CBOR, ERR_INVALID_COMMAND,
                            ERR_KEEPALIVE_CANCEL, ERR_NO_CREDENTIALS,
                            ERR_OPERATION_DENIED, OK, Authenticator)
from passkeyd.model import Cancelled, Credential


def make_cred(rp="discord.com", user="me@x", n=1):
    return Credential(rp_id=rp, credential_id=os.urandom(16),
                      private_key=ec.generate_private_key(ec.SECP256R1()),
                      user_handle=b"uh%d" % n, user_name=user, display_name="Me",
                      item_name="discord.com", created="2025-01-0%d" % n, counter=7)


class FakeVault:
    def __init__(self, creds):
        self.creds = creds

    def find(self, rp_id, allow):
        return [c for c in self.creds if c.rp_id == rp_id
                and (not allow or c.credential_id in allow)]


class FakeApprover:
    def __init__(self, pick_index=0, verify_result=True, raise_cancel=False):
        self.pick_index, self.verify_result, self.raise_cancel = pick_index, verify_result, raise_cancel
        self.pick_calls, self.verify_calls = [], []

    def pick(self, rp_id, creds, cancel):
        self.pick_calls.append(list(creds))
        return None if self.pick_index is None else creds[self.pick_index]

    def verify(self, rp_id, cred, cancel):
        self.verify_calls.append(cred)
        if self.raise_cancel:
            raise Cancelled()
        return self.verify_result


def call(auth, cmd, req=None):
    data = bytes([cmd]) + (cbor.encode(req) if req is not None else b"")
    out = auth.handle(data, threading.Event())
    return out[0], (cbor.decode(out[1:]) if len(out) > 1 else None)


def ga(rp="discord.com", cdh=None, allow=None, opts=None):
    req = {1: rp, 2: cdh or os.urandom(32)}
    if allow is not None:
        req[3] = [{"type": "public-key", "id": a} for a in allow]
    req[5] = opts if opts is not None else {"uv": True}
    return req


def verify_sig(cred, resp, cdh):
    cred.private_key.public_key().verify(resp[3], resp[2] + cdh, ec.ECDSA(hashes.SHA256()))


class TestCtap2(unittest.TestCase):
    def test_get_info(self):
        status, info = call(Authenticator(FakeVault([]), FakeApprover()), 0x04)
        self.assertEqual(status, OK)
        self.assertEqual(info, {1: ["FIDO_2_0"], 2: [], 3: AAGUID,
                                4: {"rk": True, "up": True, "uv": True, "plat": False},
                                5: 1200})

    def test_single_match_discoverable(self):
        c = make_cred()
        ap = FakeApprover()
        cdh = os.urandom(32)
        status, r = call(Authenticator(FakeVault([c]), ap), 0x02, ga(cdh=cdh))
        self.assertEqual(status, OK)
        self.assertEqual(r[2][:32], sha256(b"discord.com").digest())
        self.assertEqual(r[2][32], 0x1D)
        self.assertEqual(r[2][33:37], (7).to_bytes(4, "big"))
        self.assertIs(r[6], True)
        self.assertEqual(r[4]["id"], c.user_handle)
        self.assertEqual(r[1], {"type": "public-key", "id": c.credential_id})
        verify_sig(c, r, cdh)
        self.assertEqual(ap.pick_calls, [])
        self.assertEqual(len(ap.verify_calls), 1)

    def test_multiple_matches_calls_pick(self):
        a, b = make_cred(n=1), make_cred(n=2)
        ap = FakeApprover(pick_index=1)
        status, r = call(Authenticator(FakeVault([a, b]), ap), 0x02, ga())
        self.assertEqual(status, OK)
        self.assertEqual(ap.pick_calls, [[a, b]])
        self.assertEqual(r[1]["id"], b.credential_id)
        self.assertEqual(ap.verify_calls, [b])

    def test_pick_cancelled_by_user(self):
        ap = FakeApprover(pick_index=None)
        status, _ = call(Authenticator(FakeVault([make_cred(n=1), make_cred(n=2)]), ap), 0x02, ga())
        self.assertEqual(status, ERR_OPERATION_DENIED)
        self.assertEqual(ap.verify_calls, [])

    def test_allowlist_no_user_selected(self):
        c = make_cred()
        status, r = call(Authenticator(FakeVault([c]), FakeApprover()), 0x02,
                         ga(allow=[c.credential_id]))
        self.assertEqual(status, OK)
        self.assertNotIn(6, r)

    def test_up_false_silent(self):
        c = make_cred()
        ap = FakeApprover()
        cdh = os.urandom(32)
        status, r = call(Authenticator(FakeVault([c]), ap), 0x02,
                         ga(cdh=cdh, allow=[c.credential_id], opts={"up": False}))
        self.assertEqual(status, OK)
        self.assertEqual(r[2][32], 0x18)
        verify_sig(c, r, cdh)
        self.assertNotIn(4, r)  # no user identity without the fingerprint
        self.assertEqual((ap.pick_calls, ap.verify_calls), ([], []))

    def test_up_false_discoverable_reveals_nothing(self):
        ap = FakeApprover()
        status, r = call(Authenticator(FakeVault([make_cred()]), ap), 0x02, ga(opts={"up": False}))
        self.assertEqual((status, r), (ERR_NO_CREDENTIALS, None))
        self.assertEqual((ap.pick_calls, ap.verify_calls), ([], []))

    def test_logs_do_not_contain_user_name(self):
        with self.assertLogs("passkeyd.ctap2", level="DEBUG") as logs:
            call(Authenticator(FakeVault([make_cred(user="secret@mail")]), FakeApprover()), 0x02, ga())
        self.assertFalse(any("secret@mail" in line for line in logs.output))

    def test_fingerprint_failed(self):
        status, _ = call(Authenticator(FakeVault([make_cred()]), FakeApprover(verify_result=False)),
                         0x02, ga())
        self.assertEqual(status, ERR_OPERATION_DENIED)

    def test_cancel(self):
        status, _ = call(Authenticator(FakeVault([make_cred()]), FakeApprover(raise_cancel=True)),
                         0x02, ga())
        self.assertEqual(status, ERR_KEEPALIVE_CANCEL)

    def test_no_match(self):
        status, _ = call(Authenticator(FakeVault([make_cred()]), FakeApprover()), 0x02,
                         ga(rp="other.com"))
        self.assertEqual(status, ERR_NO_CREDENTIALS)

    def test_make_credential_denied(self):
        auth = Authenticator(FakeVault([]), FakeApprover())
        req = {1: os.urandom(32), 2: {"id": "discord.com"}, 3: {"id": b"u", "name": "n"},
               4: [{"type": "public-key", "alg": -7}]}
        self.assertEqual(call(auth, 0x01, req)[0], ERR_OPERATION_DENIED)
        self.assertEqual(call(auth, 0x01, {**req, 8: b""})[0], ERR_OPERATION_DENIED)

    def test_unknown_command(self):
        self.assertEqual(call(Authenticator(FakeVault([]), FakeApprover()), 0x07)[0],
                         ERR_INVALID_COMMAND)

    def test_bad_cbor(self):
        out = Authenticator(FakeVault([]), FakeApprover()).handle(b"\x02\xff\xff", threading.Event())
        self.assertEqual(out, bytes([ERR_INVALID_CBOR]))


if __name__ == "__main__":
    unittest.main()
