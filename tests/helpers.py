"""Packet and capture builders used by tests. Pure functions, no fixtures."""

from __future__ import annotations

import struct


def _ipv4(src: bytes, dst: bytes, proto: int, payload: bytes = b"") -> bytes:
    total_len = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, proto, 0, src, dst,
    ) + payload


def _ipv6(src: bytes, dst: bytes, nxt: int, payload: bytes = b"") -> bytes:
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nxt, 64, src, dst) + payload


def _eth(ethertype: int, payload: bytes) -> bytes:
    return (
        b"\xaa\xbb\xcc\xdd\xee\xff"
        + b"\x11\x22\x33\x44\x55\x66"
        + struct.pack("!H", ethertype)
        + payload
    )


def _eth_vlan(vlan_id: int, ethertype: int, payload: bytes) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan_id & 0x0FFF)
    return (
        b"\xaa\xbb\xcc\xdd\xee\xff"
        + b"\x11\x22\x33\x44\x55\x66"
        + tag
        + struct.pack("!H", ethertype)
        + payload
    )


def _pcap(packets: list[tuple[int, int, bytes]], linktype: int = 1) -> bytes:
    # Little-endian pcap: magic written as bytes D4 C3 B2 A1; header and
    # records follow in little-endian to match.
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts_sec, ts_usec, data in packets:
        out += struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data))
        out += data
    return out


def _pcap_be(
    packets: list[tuple[int, int, bytes]],
    linktype: int = 1,
    nanosecond: bool = False,
) -> bytes:
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    out = struct.pack(">IHHIIII", magic, 2, 4, 0, 0, 65535, linktype)
    for ts_sec, ts_frac, data in packets:
        out += struct.pack(">IIII", ts_sec, ts_frac, len(data), len(data))
        out += data
    return out


def _pcapng(
    packets: list[tuple[int, int, bytes]],
    linktypes: list[int] | None = None,
) -> bytes:
    if linktypes is None:
        linktypes = [1]

    def block(block_type: int, body: bytes) -> bytes:
        pad = (4 - (len(body) % 4)) % 4
        body = body + b"\x00" * pad
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = block(0x0A0D0D0A, shb_body)

    for lt in linktypes:
        out += block(0x00000001, struct.pack("<HHI", lt, 0, 65535))

    for ts_sec, ts_usec, data in packets:
        ts = ts_sec * 1_000_000 + ts_usec
        epb = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data))
        epb += data
        out += block(0x00000006, epb)
    return out


def _pcapng_be(
    packets: list[tuple[int, int, bytes]],
    linktypes: list[int] | None = None,
) -> bytes:
    if linktypes is None:
        linktypes = [1]

    def block(block_type: int, body: bytes) -> bytes:
        pad = (4 - (len(body) % 4)) % 4
        body = body + b"\x00" * pad
        total = 12 + len(body)
        return struct.pack(">II", block_type, total) + body + struct.pack(">I", total)

    shb_body = struct.pack(">IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = block(0x0A0D0D0A, shb_body)

    for lt in linktypes:
        out += block(0x00000001, struct.pack(">HHI", lt, 0, 65535))

    for ts_sec, ts_usec, data in packets:
        ts = ts_sec * 1_000_000 + ts_usec
        epb = struct.pack(">IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data))
        epb += data
        out += block(0x00000006, epb)
    return out