"""Stream packets from a pcap or pcapng file, yielding (timestamp, raw_bytes)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator, NamedTuple


class CaptureError(Exception):
    """Raised for missing, empty, or unrecognized capture files."""


# On-disk magic byte sequences. The pcap magic is deliberately asymmetric so a
# reader can tell the file's byte order from the first 4 bytes:
#   A1 B2 C3 D4  -> big-endian,    microsecond timestamps
#   D4 C3 B2 A1  -> little-endian, microsecond timestamps
#   A1 B2 3C 4D  -> big-endian,    nanosecond  timestamps
#   4D 3C B2 A1  -> little-endian, nanosecond  timestamps
_PCAP_MAGIC_BE_USEC = b"\xa1\xb2\xc3\xd4"
_PCAP_MAGIC_LE_USEC = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_BE_NSEC = b"\xa1\xb2\x3c\x4d"
_PCAP_MAGIC_LE_NSEC = b"\x4d\x3c\xb2\xa1"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"
_PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"

# Link types we care about (pcap/pcapng linktype registry).
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113


class Packet(NamedTuple):
    timestamp: float | None
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

    if head == _PCAP_MAGIC_BE_USEC:
        return _iter_pcap(path, endian=">", nanosecond=False)
    if head == _PCAP_MAGIC_LE_USEC:
        return _iter_pcap(path, endian="<", nanosecond=False)
    if head == _PCAP_MAGIC_BE_NSEC:
        return _iter_pcap(path, endian=">", nanosecond=True)
    if head == _PCAP_MAGIC_LE_NSEC:
        return _iter_pcap(path, endian="<", nanosecond=True)
    if head == _PCAPNG_MAGIC:
        return _iter_pcapng(path)

    raise CaptureError(
        f"Unrecognized capture format in {path}: "
        f"magic bytes {head.hex()} are neither pcap nor pcapng"
    )


def _iter_pcap(path: Path, endian: str, nanosecond: bool) -> Iterator[Packet]:
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

            if block_type == 0x0A0D0D0A:  # Section Header Block
                # A new SHB begins a new section: interface state is reset and
                # the section's byte order may differ from the previous one.
                # The header we just read was decoded with the *old* endian,
                # so re-derive endian from this SHB's byte-order magic before
                # reading the next block header.
                if len(body) < 4:
                    raise CaptureError(f"Short pcapng SHB in {path}")
                bom = body[0:4]
                if bom == _PCAPNG_BOM_LE:
                    endian = "<"
                elif bom == _PCAPNG_BOM_BE:
                    endian = ">"
                else:
                    raise CaptureError(f"Invalid pcapng SHB byte-order magic in {path}")
                interfaces = []
                tsresol = []
                block_hdr = struct.Struct(f"{endian}II")
                continue
            if block_type == 0x00000001:  # Interface Description Block
                linktype = struct.unpack(f"{endian}H", body[:2])[0]
                interfaces.append(linktype)
                tsresol.append(_parse_tsresol(body, endian))
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
                # SPB has no timestamp. Yield None so the aggregator can skip
                # it for first_seen / last_seen.
                yield Packet(None, data, interfaces[0])
            # Other block types (NRB, ISB, etc.) are skipped.

def _pcapng_endian(fh, path: Path) -> str:
    """Read the Section Header Block byte-order magic and return struct endian."""
    header = fh.read(12)
    if len(header) < 12:
        raise CaptureError(f"Truncated pcapng section header in {path}")
    if header[0:4] != _PCAPNG_MAGIC:
        raise CaptureError(f"Missing pcapng section header in {path}")
    bom = header[8:12]
    if bom == _PCAPNG_BOM_LE:
        return "<"
    if bom == _PCAPNG_BOM_BE:
        return ">"
    raise CaptureError(f"Invalid pcapng byte-order magic in {path}")


def _parse_tsresol(body: bytes, endian: str) -> int:
    """Parse the if_tsresol option; return ticks per second (default 1e6)."""
    # IDB body layout: linktype(2) reserved(2) snaplen(4) options...
    if len(body) < 8:
        return 1_000_000
    offset = 8
    option_struct = struct.Struct(f"{endian}HH")
    while offset + 4 <= len(body):
        code, opt_len = option_struct.unpack(body[offset : offset + 4])
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