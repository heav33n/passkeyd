"""CTAP2 command handling: getInfo, getAssertion, makeCredential (denied)."""
import logging
import struct
import threading
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor

from .model import ApproverLike, Cancelled, VaultLike

log = logging.getLogger(__name__)

OK = 0x00
ERR_INVALID_COMMAND = 0x01
ERR_INVALID_CBOR = 0x12
ERR_OPERATION_DENIED = 0x27
ERR_KEEPALIVE_CANCEL = 0x2D
ERR_NO_CREDENTIALS = 0x2E

AAGUID = bytes.fromhex("5061737365796b6420737069b0000001")

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS = 0x01, 0x04, 0x08, 0x10

CMD_MAKE_CREDENTIAL, CMD_GET_ASSERTION, CMD_GET_INFO = 0x01, 0x02, 0x04


class Authenticator:
    def __init__(self, vault: VaultLike, approver: ApproverLike):
        self.vault = vault
        self.approver = approver

    def handle(self, data: bytes, cancel: threading.Event) -> bytes:
        cmd = data[0]
        if cmd not in (CMD_MAKE_CREDENTIAL, CMD_GET_ASSERTION, CMD_GET_INFO):
            log.info("unsupported CTAP2 command 0x%02x", cmd)
            return bytes([ERR_INVALID_COMMAND])
        try:
            req = cbor.decode(data[1:]) if len(data) > 1 else {}
            if not isinstance(req, dict):
                raise ValueError("request is not a map")
        except Exception:
            return bytes([ERR_INVALID_CBOR])

        if cmd == CMD_GET_INFO:
            status, resp = OK, self._info()
        elif cmd == CMD_MAKE_CREDENTIAL:
            log.info("makeCredential for %s denied (v1 is sign-in only)",
                     (req.get(2) or {}).get("id"))
            status, resp = ERR_OPERATION_DENIED, None
        else:
            status, resp = self._get_assertion(req, cancel)
        return bytes([status]) + (cbor.encode(resp) if resp is not None else b"")

    @staticmethod
    def _info():
        return {1: ["FIDO_2_0"], 2: [], 3: AAGUID,
                4: {"rk": True, "up": True, "uv": True, "plat": False},
                5: 1200}

    def _get_assertion(self, req, cancel):
        rp_id, cdh = req[1], req[2]
        allow = {a["id"] for a in req.get(3, [])}
        up = req.get(5, {}).get("up", True)
        creds = self.vault.find(rp_id, allow)
        log.info("getAssertion rp=%s allowList=%d matches=%d up=%s",
                 rp_id, len(allow), len(creds), up)
        if not creds:
            return ERR_NO_CREDENTIALS, None

        if not up:
            # Silent probes are only for checking a site-named key; never reveal
            # which accounts exist for a site without the fingerprint.
            if not allow:
                return ERR_NO_CREDENTIALS, None
            cred, flags = creds[0], FLAG_BE | FLAG_BS
        else:
            try:
                cred = creds[0] if len(creds) == 1 else self.approver.pick(rp_id, creds, cancel)
                if cred is None:
                    return ERR_OPERATION_DENIED, None
                if not self.approver.verify(rp_id, cred, cancel):
                    return ERR_OPERATION_DENIED, None
            except Cancelled:
                log.info("request cancelled by the app")
                return ERR_KEEPALIVE_CANCEL, None
            flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS

        auth_data = sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", cred.counter)
        sig = cred.private_key.sign(auth_data + cdh, ec.ECDSA(hashes.SHA256()))
        resp = {1: {"type": "public-key", "id": cred.credential_id}, 2: auth_data, 3: sig}
        if up:
            resp[4] = {"id": cred.user_handle, "name": cred.user_name,
                       "displayName": cred.display_name}
            log.info("signed in to %s", rp_id)
        if not allow:
            resp[6] = True  # userSelected: we already chose the account
        return OK, resp
