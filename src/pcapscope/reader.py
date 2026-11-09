"""Stream packets from a pcap or pcapng file, yielding (timestamp, raw_bytes)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator, NamedTuple


class CaptureError(Exception):
    """Raised for missing, empty, or unrecognized capture files."""


# pcap magic numbers (both endiannesses), written as ints for clarity.
_PCAP_MAGICS = {
    0xA1B2C3D4,  # big-endian, microsecond
    0xD4C3B2A1,  # little-endian, microsecond
    0xA1B23C4D,  # big-endian, nanosecond
    0x4D3CB2A1,  # little-endian, nanosecond
}
_PCAPNG_MAGIC = 0x0A0D0D0A

# Link types we care about (from pcap/pcapng linktype registry).
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113


class Packet(NamedTuple):
    timestamp: float
    raw_bytes: bytes
    linktype: int


def _read_magic(path: Path) -> bytes:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except FileNotFoundError as exc:
        raise CaptureError(f"Capture file not found: {path}") from exc
    except OSError as exc:
        raise CaptureError(f"Could not read capture file {path}: {exc}") from exc

    if not head:
        raise CaptureError(f"Capture file is empty: {path}")
    if len(head) < 4:
        raise CaptureError(f"Capture file is too short to be valid: {path}")
    return head


def open_capture(path: str | Path) -> Iterator[Packet]:
    """Open a pcap/pcapng file and yield Packet tuples, streaming from disk.

    Never loads the whole file into memory. For pcapng, the link type is taken
    from the interface description block of each packet.
    """
    path = Path(path)
    head = _read_magic(path)

    # Interpret as both endiannesses; if either matches a known magic, we know.
    be_magic = struct.unpack(">I", head)[0]
    le_magic = struct.unpack("<I", head)[0]

    if be_magic in _PCAP_MAGICS:
        big_endian = True
        return _iter_pcap(path, head, big_endian)
    if le_magic in _PCAP_MAGICS:
        big_endian = False
        return _iter_pcap(path, head, big_endian)
    if be_magic == _PCAPNG_MAGIC or le_magic == _PCAPNG_MAGIC:
        return _iter_pcapng(path)

    raise CaptureError(
        f"Unrecognized capture format in {path}: "
        f"magic bytes {head.hex()} are neither pcap nor pcapng"
    )


def _iter_pcap(path: Path, head: bytes, big_endian: bool) -> Iterator[Packet]:
    endian = ">" if big_endian else "<"
    magic = struct.unpack(f"{endian}I", head)[0]
    if magic in (0xA1B23C4D, 0x4D3CB2A1):
        # nanosecond-resolution pcap
        nanosecond = True
    else:
        nanosecond = False

    with path.open("rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise CaptureError(f"Truncated pcap global header in {path}")
        # global header: magic, major, minor, thiszone, sigfigs, snaplen, network
        _, _, _, _, _, _, network = struct.unpack(f"{endian}IHHiiii", header)
        linktype = network & 0xFFFF  # low 16 bits are the link type

        rec_header = struct.Struct(f"{endian}IIII")
        while True:
            rec = fh.read(16)
            if not rec:
                break
            if len(rec) < 16:
                raise CaptureError(f"Truncated packet record header in {path}")
            ts_sec, ts_frac, incl_len, _orig_len = rec_header.unpack(rec)
            data = fh.read(incl_len)
            if len(data) < incl_len:
                raise CaptureError(f"Truncated packet data in {path}")
            if nanosecond:
                timestamp = ts_sec + ts_frac / 1_000_000_000
            else:
                timestamp = ts_sec + ts_frac / 1_000_000
            yield Packet(timestamp, data, linktype)


def _iter_pcapng(path: Path) -> Iterator[Packet]:
    """Parse a pcapng file, yielding packets with their per-interface linktype."""
    # pcapng block header: block type (4), block total length (4), then body,
    # then block total length (4) repeated. Endianness is determined by the
    # byte-order magic in the SHB.
    with path.open("rb") as fh:
        endian = _pcapng_endian(fh, path)
        fh.seek(0)

        interfaces: list[int] = []
        tsresol: list[int] = []  # per-interface timestamp resolution (ticks/sec)
        block_hdr = struct.Struct(f"{endian}II")

        while True:
            header = fh.read(8)
            if not header:
                break
            if len(header) < 8:
                raise CaptureError(f"Truncated pcapng block header in {path}")
            block_type, total_len = block_hdr.unpack(header)
            if total_len < 12 or total_len % 4 != 0:
                raise CaptureError(f"Invalid pcapng block length {total_len} in {path}")
            body = fh.read(total_len - 8)
            if len(body) < total_len - 8:
                raise CaptureError(f"Truncated pcapng block in {path}")
            # trailing total length is the last 4 bytes of body
            body = body[:-4]

            if block_type == 0x00000001:  # Interface Description Block
                linktype = struct.unpack(f"{endian}H", body[:2])[0]
                interfaces.append(linktype)
                tsresol.append(_parse_tsresol(body))
            elif block_type == 0x00000006:  # Enhanced Packet Block
                if len(interfaces) == 0:
                    raise CaptureError(
                        f"pcapng EPB encountered before any interface block in {path}"
                    )
                if len(body) < 20:
                    raise CaptureError(f"Short pcapng EPB in {path}")
                iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack(
                    f"{endian}IIIII", body[:20]
                )
                if iface_id >= len(interfaces):
                    raise CaptureError(
                        f"pcapng EPB references unknown interface {iface_id} in {path}"
                    )
                data = body[20 : 20 + cap_len]
                if len(data) < cap_len:
                    raise CaptureError(f"Truncated pcapng EPB data in {path}")
                ticks_per_sec = tsresol[iface_id]
                timestamp = ((ts_high << 32) | ts_low) / ticks_per_sec
                yield Packet(timestamp, data, interfaces[iface_id])
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(interfaces) == 0:
                    raise CaptureError(
                        f"pcapng SPB encountered before any interface block in {path}"
                    )
                if len(body) < 4:
                    raise CaptureError(f"Short pcapng SPB in {path}")
                orig_len = struct.unpack(f"{endian}I", body[:4])[0]
                data = body[4 : 4 + orig_len]
                # SPB has no timestamp; use 0.0
                yield Packet(0.0, data, interfaces[0])
            # Other block types (SHB, NRB, ISB, etc.) are skipped.


def _pcapng_endian(fh, path: Path) -> str:
    """Read the Section Header Block byte-order magic and return struct endian."""
    header = fh.read(12)
    if len(header) < 12:
        raise CaptureError(f"Truncated pcapng section header in {path}")
    block_type = struct.unpack("<I", header[:4])[0]
    if block_type != _PCAPNG_MAGIC:
        raise CaptureError(f"Missing pcapng section header in {path}")
    bom = header[8:12]
    if bom == b"\x1a\x2b\x3c\x4d":
        return "<"
    if bom == b"\x4d\x3c\x2b\x1a":
        return ">"
    raise CaptureError(f"Invalid pcapng byte-order magic in {path}")


def _parse_tsresol(body: bytes) -> int:
    """Parse the if_tsresol option; return ticks per second (default 1e6)."""
    # IDB body layout: linktype(2) reserved(2) snaplen(4) options...
    if len(body) < 8:
        return 1_000_000
    offset = 8
    while offset + 4 <= len(body):
        code, opt_len = struct.unpack("<HH", body[offset : offset + 4])
        if code == 0:  # opt_endofopt
            break
        opt_val = body[offset + 4 : offset + 4 + opt_len]
        if code == 9 and len(opt_val) >= 1:  # if_tsresol
            val = opt_val[0]
            if val & 0x80:  # negative power of two
                return 1 << (val & 0x7F)
            return 10 ** val
        offset += 4 + opt_len + ((4 - opt_len % 4) % 4)
    return 1_000_000