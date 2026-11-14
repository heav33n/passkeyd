"""Virtual HID device via /dev/uhid that presents itself as a FIDO security key."""
import os
import struct

UHID_DESTROY, UHID_OUTPUT, UHID_CREATE2, UHID_INPUT2 = 1, 6, 11, 12
EVENT_SIZE = 4 + 4372  # sizeof(struct uhid_event)

# FIDO usage page 0xF1D0, 64-byte input and output reports
REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
    0xC0,
])

NO_ACCESS = ("No access to /dev/uhid. Install contrib/60-passkeyd-uhid.rules and make sure "
             "the uhid module is loaded (see README).")


class UhidDevice:
    def __init__(self, path: str = "/dev/uhid"):
        self.path = path
        self.fd: int | None = None

    def open(self) -> None:
        try:
            self.fd = os.open(self.path, os.O_RDWR)
        except PermissionError as e:
            raise PermissionError(NO_ACCESS) from e
        os.write(self.fd, struct.pack(
            "<I128s64s64sHHIIII4096s", UHID_CREATE2, b"passkeyd virtual key", b"", b"",
            len(REPORT_DESCRIPTOR), 0x03, 0x1209, 0x5070, 1, 0, REPORT_DESCRIPTOR))

    def read_output(self) -> bytes | None:
        ev = os.read(self.fd, EVENT_SIZE)
        if struct.unpack_from("<I", ev)[0] != UHID_OUTPUT:
            return None
        size = struct.unpack_from("<H", ev, 4 + 4096)[0]
        report = ev[4:4 + size]
        if len(report) == 65:  # leading report id 0
            report = report[1:]
        return report

    def send_input(self, report: bytes) -> None:
        os.write(self.fd, struct.pack("<IH4096s", UHID_INPUT2, len(report), report))

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.write(self.fd, struct.pack("<I", UHID_DESTROY))
            finally:
                os.close(self.fd)
                self.fd = None
