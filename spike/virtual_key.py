#!/usr/bin/env python3
"""THROWAWAY SPIKE: a fake FIDO2 USB security key over /dev/uhid.

Purpose: find out whether Electron apps (Legcord, Vesktop, Discord) will
finish a WebAuthn request when a security key answers, with no dialogs.

- No fingerprint, no Bitwarden: every request is auto-approved.
- Passkeys created by sites are kept in spike_creds.json next to this file
  (private keys in plain text -- test data only, delete afterwards).
- Ctrl+C removes the fake key.
"""
import json
import os
import struct
import sys
import time
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_der_private_key)
from fido2 import cbor

# ---------------------------------------------------------------- uhid ---
UHID_START, UHID_STOP, UHID_OPEN, UHID_CLOSE, UHID_OUTPUT = 2, 3, 4, 5, 6
UHID_CREATE2, UHID_INPUT2, UHID_DESTROY = 11, 12, 1
EVENT_SIZE = 4 + 4372  # sizeof(struct uhid_event)

# FIDO usage page 0xF1D0, 64-byte input and output reports
REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
    0xC0,
])


def uhid_create(fd):
    name = b"passkeyd spike virtual key"
    ev = struct.pack("<I128s64s64sHHIIII4096s", UHID_CREATE2, name, b"", b"",
                     len(REPORT_DESCRIPTOR), 0x03, 0x1209, 0x5070, 1, 0,
                     REPORT_DESCRIPTOR)
    os.write(fd, ev)


def uhid_send(fd, report: bytes):
    os.write(fd, struct.pack("<IH4096s", UHID_INPUT2, len(report), report))


# ------------------------------------------------------------- CTAPHID ---
CMD_PING, CMD_MSG, CMD_INIT, CMD_WINK, CMD_CBOR, CMD_CANCEL = 0x81, 0x83, 0x86, 0x88, 0x90, 0x91
CMD_KEEPALIVE, CMD_ERROR = 0xBB, 0xBF
BROADCAST = 0xFFFFFFFF


def send_message(fd, cid, cmd, data: bytes):
    pkt = struct.pack(">IBH", cid, cmd, len(data)) + data[:57]
    uhid_send(fd, pkt.ljust(64, b"\0"))
    rest, seq = data[57:], 0
    while rest:
        pkt = struct.pack(">IB", cid, seq) + rest[:59]
        uhid_send(fd, pkt.ljust(64, b"\0"))
        rest, seq = rest[59:], seq + 1


# ---------------------------------------------------------------- CTAP2 ---
AAGUID = bytes.fromhex("5061737365796b6420737069b0000001")
OK, ERR_INVALID_CBOR, ERR_UNSUPPORTED_ALG, ERR_CRED_EXCLUDED = 0x00, 0x12, 0x26, 0x19
ERR_NO_CREDENTIALS, ERR_INVALID_COMMAND, ERR_PIN_NOT_SET = 0x2E, 0x01, 0x35
STORE = Path(__file__).with_name("spike_creds.json")


def load_creds():
    return json.loads(STORE.read_text()) if STORE.exists() else []


def save_creds(creds):
    STORE.write_text(json.dumps(creds, indent=1))


def cose_key(pub):
    n = pub.public_numbers()
    return cbor.encode({1: 2, 3: -7, -1: 1,
                        -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})


USER_SELECTED = os.environ.get("SPIKE_NO_USER_SELECTED") != "1"
VERSIONS = ["FIDO_2_0", "FIDO_2_1"] if os.environ.get("SPIKE_FIDO21") == "1" else ["FIDO_2_0"]


def get_info(_req):
    return OK, {1: VERSIONS, 2: [], 3: AAGUID,
                4: {"rk": True, "up": True, "uv": True, "plat": False},
                5: 1200}


def make_credential(req):
    cdh, rp, user, params = req[1], req[2], req[3], req[4]
    if 8 in req and len(req[8]) == 0:  # "touch to select" probe
        return ERR_PIN_NOT_SET, None
    if not any(p.get("alg") == -7 for p in params):
        return ERR_UNSUPPORTED_ALG, None
    creds = load_creds()
    excluded = {bytes.fromhex(c["id"]) for c in creds if c["rpId"] == rp["id"]}
    if any(e["id"] in excluded for e in req.get(5, [])):
        return ERR_CRED_EXCLUDED, None
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = os.urandom(32)
    creds.append({"rpId": rp["id"], "id": cred_id.hex(),
                  "userId": user["id"].hex(), "userName": user.get("name", ""),
                  "displayName": user.get("displayName", ""),
                  "key": key.private_bytes(Encoding.DER, PrivateFormat.PKCS8,
                                           NoEncryption()).hex()})
    save_creds(creds)
    auth_data = (sha256(rp["id"].encode()).digest() + bytes([0x45]) + struct.pack(">I", 0)
                 + AAGUID + struct.pack(">H", len(cred_id)) + cred_id
                 + cose_key(key.public_key()))
    log(f"REGISTERED passkey for {rp['id']} user={user.get('name')!r}")
    return OK, {1: "none", 2: auth_data, 3: {}}


def get_assertion(req):
    rp_id, cdh = req[1], req[2]
    allow = {a["id"] for a in req.get(3, [])}
    opts = req.get(5, {})
    creds = [c for c in load_creds() if c["rpId"] == rp_id
             and (not allow or bytes.fromhex(c["id"]) in allow)]
    log(f"getAssertion rp={rp_id} allowList={len(allow)} matches={len(creds)} opts={opts}")
    if not creds:
        return ERR_NO_CREDENTIALS, None
    c = creds[0]  # the real daemon shows a picker here
    up = opts.get("up", True)
    flags = (0x01 if up else 0) | (0x04 if opts.get("uv") else 0)
    auth_data = sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
    key = load_der_private_key(bytes.fromhex(c["key"]), None)
    sig = key.sign(auth_data + cdh, ec.ECDSA(hashes.SHA256()))
    resp = {1: {"type": "public-key", "id": bytes.fromhex(c["id"])}, 2: auth_data, 3: sig,
            4: {"id": bytes.fromhex(c["userId"]), "name": c["userName"],
                "displayName": c["displayName"]}}
    if not allow and USER_SELECTED:
        resp[6] = True  # CTAP 2.1 userSelected: "account already chosen on the key"
    if up:
        log(f"SIGNED IN as {c['userName']!r} on {rp_id}")
    return OK, resp


HANDLERS = {0x01: make_credential, 0x02: get_assertion, 0x04: get_info}


def handle_cbor(data: bytes) -> bytes:
    cmd = data[0]
    h = HANDLERS.get(cmd)
    if h is None:
        log(f"unsupported CTAP2 command 0x{cmd:02x}")
        return bytes([ERR_INVALID_COMMAND])
    try:
        req = cbor.decode(data[1:]) if len(data) > 1 else {}
    except Exception:
        return bytes([ERR_INVALID_CBOR])
    status, resp = h(req)
    log(f"  ctap 0x{cmd:02x} req keys={sorted(req)} -> status 0x{status:02x}"
        + (f" resp keys={sorted(resp)}" if resp else ""))
    return bytes([status]) + (cbor.encode(resp) if resp is not None else b"")


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ----------------------------------------------------------------- main ---
def main():
    try:
        fd = os.open("/dev/uhid", os.O_RDWR)
    except PermissionError:
        sys.exit("No access to /dev/uhid -- install the udev rule first (see README).")
    uhid_create(fd)
    log("Virtual security key plugged in. Ctrl+C to unplug.")
    next_cid = 1
    pending = {}  # cid -> [cmd, total_len, buffer, next_seq]
    try:
        while True:
            ev = os.read(fd, EVENT_SIZE)
            etype = struct.unpack_from("<I", ev)[0]
            if etype != UHID_OUTPUT:
                continue
            data = ev[4:4 + 4096]
            size = struct.unpack_from("<H", ev, 4 + 4096)[0]
            pkt = data[:size]
            if len(pkt) == 65:  # leading report id 0
                pkt = pkt[1:]
            cid = struct.unpack_from(">I", pkt)[0]
            if pkt[4] & 0x80:  # initialization packet
                cmd, total = pkt[4], struct.unpack_from(">H", pkt, 5)[0]
                pending[cid] = [cmd, total, bytearray(pkt[7:7 + total]), 0]
            elif cid in pending and pkt[4] == pending[cid][3]:
                p = pending[cid]
                p[2] += pkt[5:5 + p[1] - len(p[2])]
                p[3] += 1
            else:
                continue
            cmd, total, buf, _ = pending[cid]
            if len(buf) < total:
                continue
            del pending[cid]
            msg = bytes(buf)
            if cmd == CMD_INIT:
                if cid == BROADCAST:
                    new_cid, next_cid = next_cid, next_cid + 1
                else:
                    new_cid = cid
                send_message(fd, cid, CMD_INIT,
                             msg[:8] + struct.pack(">IBBBBB", new_cid, 2, 0, 1, 0, 0x0D))
            elif cmd == CMD_PING:
                send_message(fd, cid, CMD_PING, msg)
            elif cmd == CMD_WINK:
                send_message(fd, cid, CMD_WINK, b"")
            elif cmd == CMD_CANCEL:
                log("  CANCEL from client")
            elif cmd == CMD_CBOR:
                send_message(fd, cid, CMD_CBOR, handle_cbor(msg))
            else:  # includes CTAP1/U2F MSG, which we don't speak
                send_message(fd, cid, CMD_ERROR, b"\x01")
    except KeyboardInterrupt:
        pass
    finally:
        os.write(fd, struct.pack("<I", UHID_DESTROY))
        os.close(fd)
        log("Unplugged.")


if __name__ == "__main__":
    main()
