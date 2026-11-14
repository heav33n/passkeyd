"""CTAPHID framing: channels, fragmentation, keepalive and cancel."""
import logging
import struct
import threading
from typing import Callable

log = logging.getLogger(__name__)

CMD_PING, CMD_MSG, CMD_INIT, CMD_WINK = 0x81, 0x83, 0x86, 0x88
CMD_CBOR, CMD_CANCEL, CMD_KEEPALIVE, CMD_ERROR = 0x90, 0x91, 0xBB, 0xBF
BROADCAST = 0xFFFFFFFF

ERR_INVALID_CMD = 0x01
ERR_INVALID_SEQ = 0x04
ERR_CHANNEL_BUSY = 0x06

CAPABILITIES = 0x0D  # WINK | CBOR | NMSG
KEEPALIVE_UPNEEDED = b"\x02"


class CtapHid:
    def __init__(self, send: Callable[[bytes], None],
                 handle_cbor: Callable[[bytes, threading.Event], bytes],
                 keepalive_interval: float = 0.1):
        self._send_report = send
        self._handle_cbor = handle_cbor
        self._keepalive_interval = keepalive_interval
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._next_cid = 1
        self._partial: dict[int, list] = {}  # cid -> [cmd, total, buf, next_seq]
        self._busy: tuple[int, threading.Event] | None = None

    # ---- output -------------------------------------------------------
    def send(self, cid: int, cmd: int, data: bytes) -> None:
        with self._send_lock:
            self._send_report((struct.pack(">IBH", cid, cmd, len(data)) + data[:57]).ljust(64, b"\0"))
            rest, seq = data[57:], 0
            while rest:
                self._send_report((struct.pack(">IB", cid, seq) + rest[:59]).ljust(64, b"\0"))
                rest, seq = rest[59:], seq + 1

    def _error(self, cid: int, code: int) -> None:
        self.send(cid, CMD_ERROR, bytes([code]))

    # ---- input --------------------------------------------------------
    def on_report(self, report: bytes) -> None:
        if len(report) < 5:
            return
        cid = struct.unpack_from(">I", report)[0]
        if report[4] & 0x80:
            cmd, total = report[4], struct.unpack_from(">H", report, 5)[0]
            self._partial[cid] = [cmd, total, bytearray(report[7:7 + total]), 0]
        else:
            p = self._partial.get(cid)
            if p is None:
                return  # stray continuation
            if report[4] != p[3]:
                del self._partial[cid]
                self._error(cid, ERR_INVALID_SEQ)
                return
            p[2] += report[5:5 + p[1] - len(p[2])]
            p[3] += 1
        cmd, total, buf, _ = self._partial[cid]
        if len(buf) < total:
            return
        del self._partial[cid]
        self._dispatch(cid, cmd, bytes(buf))

    def _dispatch(self, cid: int, cmd: int, msg: bytes) -> None:
        if cmd == CMD_INIT:
            if cid == BROADCAST:
                with self._state_lock:
                    new_cid, self._next_cid = self._next_cid, self._next_cid + 1
            else:
                new_cid = cid
            self.send(cid, CMD_INIT, msg[:8] + struct.pack(">IBBBBB", new_cid, 2, 0, 1, 0, CAPABILITIES))
        elif cmd == CMD_PING:
            self.send(cid, CMD_PING, msg)
        elif cmd == CMD_WINK:
            self.send(cid, CMD_WINK, b"")
        elif cmd == CMD_CANCEL:
            with self._state_lock:
                if self._busy and self._busy[0] == cid:
                    log.info("cancel from app")
                    self._busy[1].set()
        elif cmd == CMD_CBOR:
            with self._state_lock:
                if self._busy is not None:
                    busy = True
                else:
                    busy = False
                    cancel = threading.Event()
                    self._busy = (cid, cancel)
            if busy:
                self._error(cid, ERR_CHANNEL_BUSY)
                return
            threading.Thread(target=self._run_cbor, args=(cid, msg, cancel), daemon=True).start()
        else:  # CTAP1/U2F MSG and anything unknown
            self._error(cid, ERR_INVALID_CMD)

    def _run_cbor(self, cid: int, msg: bytes, cancel: threading.Event) -> None:
        result: list[bytes] = []

        def work():
            try:
                result.append(self._handle_cbor(msg, cancel))
            except Exception:
                log.exception("CTAP2 handler crashed")
                result.append(b"\x7f")  # CTAP1_ERR_OTHER

        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        while True:
            worker.join(self._keepalive_interval)
            if not worker.is_alive():
                break
            self.send(cid, CMD_KEEPALIVE, KEEPALIVE_UPNEEDED)
        with self._state_lock:
            self._busy = None
        self.send(cid, CMD_CBOR, result[0])
