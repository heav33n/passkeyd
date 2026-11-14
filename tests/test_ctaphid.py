import struct
import threading
import time
import unittest

from passkeyd.ctaphid import (ERR_CHANNEL_BUSY, ERR_INVALID_SEQ, CtapHid)

BROADCAST = 0xFFFFFFFF
CMD_INIT, CMD_CBOR, CMD_CANCEL, CMD_KEEPALIVE, CMD_ERROR = 0x86, 0x90, 0x91, 0xBB, 0xBF


def packets(cid, cmd, data):
    out = [(struct.pack(">IBH", cid, cmd, len(data)) + data[:57]).ljust(64, b"\0")]
    rest, seq = data[57:], 0
    while rest:
        out.append((struct.pack(">IB", cid, seq) + rest[:59]).ljust(64, b"\0"))
        rest, seq = rest[59:], seq + 1
    return out


class Wire:
    """Collects sent reports and reassembles them into (cid, cmd, payload) messages."""

    def __init__(self):
        self.reports, self.messages = [], []
        self.cond = threading.Condition()
        self._partial = {}

    def send(self, report):
        assert len(report) == 64
        with self.cond:
            self.reports.append(report)
            cid = struct.unpack_from(">I", report)[0]
            if report[4] & 0x80:
                total = struct.unpack_from(">H", report, 5)[0]
                self._partial[cid] = [report[4], total, bytearray(report[7:7 + total]), 0]
            else:
                p = self._partial[cid]
                assert report[4] == p[3], "bad seq in response"
                p[2] += report[5:5 + p[1] - len(p[2])]
                p[3] += 1
            cmd, total, buf, _ = self._partial[cid]
            if len(buf) >= total:
                del self._partial[cid]
                self.messages.append((cid, cmd, bytes(buf)))
                self.cond.notify_all()

    def wait_for(self, pred, timeout=2.0):
        with self.cond:
            ok = self.cond.wait_for(lambda: any(pred(m) for m in self.messages), timeout)
            assert ok, f"timed out; got {self.messages}"
            return next(m for m in self.messages if pred(m))


def init_channel(hid, wire):
    nonce = b"12345678"
    for p in packets(BROADCAST, CMD_INIT, nonce):
        hid.on_report(p)
    _, _, payload = wire.wait_for(lambda m: m[1] == CMD_INIT)
    return payload, struct.unpack_from(">I", payload, 8)[0]


class TestCtapHid(unittest.TestCase):
    def test_init_broadcast_allocates_cid(self):
        wire = Wire()
        hid = CtapHid(wire.send, lambda d, c: b"\x00")
        payload, cid = init_channel(hid, wire)
        self.assertEqual(payload[:8], b"12345678")
        self.assertNotEqual(cid, BROADCAST)
        self.assertNotEqual(cid, 0)
        self.assertEqual(payload[12], 2)
        self.assertEqual(payload[16], 0x0D)

    def test_cbor_multi_packet_roundtrip(self):
        wire, seen = Wire(), []
        reply = bytes(range(256)) + bytes(44)

        def handler(data, cancel):
            seen.append(data)
            return reply

        hid = CtapHid(wire.send, handler)
        _, cid = init_channel(hid, wire)
        req = bytes((i * 7) % 256 for i in range(200))
        for p in packets(cid, CMD_CBOR, req):
            hid.on_report(p)
        _, _, payload = wire.wait_for(lambda m: m[1] == CMD_CBOR)
        self.assertEqual(seen, [req])
        self.assertEqual(payload, reply)

    def test_keepalive_while_busy(self):
        wire = Wire()

        def handler(data, cancel):
            time.sleep(0.35)
            return b"\x00"

        hid = CtapHid(wire.send, handler)
        _, cid = init_channel(hid, wire)
        for p in packets(cid, CMD_CBOR, b"\x02"):
            hid.on_report(p)
        wire.wait_for(lambda m: m[1] == CMD_CBOR)
        cmds = [m[1] for m in wire.messages if m[0] == cid]
        keepalives = [m for m in wire.messages if m[1] == CMD_KEEPALIVE]
        self.assertGreaterEqual(len(keepalives), 2)
        self.assertTrue(all(m[2] == b"\x02" for m in keepalives))
        self.assertEqual(cmds[-1], CMD_CBOR)

    def test_cancel_sets_event(self):
        wire, got = Wire(), {}
        started = threading.Event()

        def handler(data, cancel):
            started.set()
            got["cancelled"] = cancel.wait(2)
            return b"\x2d"

        hid = CtapHid(wire.send, handler)
        _, cid = init_channel(hid, wire)
        for p in packets(cid, CMD_CBOR, b"\x02"):
            hid.on_report(p)
        self.assertTrue(started.wait(1))
        for p in packets(cid, CMD_CANCEL, b""):
            hid.on_report(p)
        _, _, payload = wire.wait_for(lambda m: m[1] == CMD_CBOR)
        self.assertTrue(got["cancelled"])
        self.assertEqual(payload, b"\x2d")

    def test_busy_second_request(self):
        wire = Wire()
        release = threading.Event()

        def handler(data, cancel):
            release.wait(2)
            return b"\x00first"

        hid = CtapHid(wire.send, handler)
        _, cid1 = init_channel(hid, wire)
        wire.messages.clear()
        _, cid2 = init_channel(hid, wire)
        for p in packets(cid1, CMD_CBOR, b"\x02"):
            hid.on_report(p)
        for p in packets(cid2, CMD_CBOR, b"\x02"):
            hid.on_report(p)
        err = wire.wait_for(lambda m: m[1] == CMD_ERROR)
        self.assertEqual(err, (cid2, CMD_ERROR, bytes([ERR_CHANNEL_BUSY])))
        release.set()
        self.assertEqual(wire.wait_for(lambda m: m[1] == CMD_CBOR), (cid1, CMD_CBOR, b"\x00first"))

    def test_bad_sequence(self):
        wire, seen = Wire(), []
        hid = CtapHid(wire.send, lambda d, c: seen.append(d) or b"\x00")
        _, cid = init_channel(hid, wire)
        ps = packets(cid, CMD_CBOR, bytes(100))
        bad = ps[1][:4] + b"\x01" + ps[1][5:]
        hid.on_report(ps[0])
        hid.on_report(bad)
        err = wire.wait_for(lambda m: m[1] == CMD_ERROR)
        self.assertEqual(err, (cid, CMD_ERROR, bytes([ERR_INVALID_SEQ])))
        hid.on_report(ps[1])  # stray continuation after the drop is ignored
        time.sleep(0.05)
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
