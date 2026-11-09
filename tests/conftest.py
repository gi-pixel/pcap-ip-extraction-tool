"""Generate small pcap/pcapng fixtures in code — no real traffic committed."""

from __future__ import annotations

import struct

import pytest


def _ipv4(src: bytes, dst: bytes, proto: int, payload: bytes = b"") -> bytes:
    total_len = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, proto, 0, src, dst,
    ) + payload


def _ipv6(src: bytes, dst: bytes, nxt: int, payload: bytes = b"") -> bytes:
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nxt, 64, src, dst) + payload


def _eth(ethertype: int, payload: bytes) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack(
        "!H", ethertype
    ) + payload


def _eth_vlan(vlan_id: int, ethertype: int, payload: bytes) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan_id & 0x0FFF)
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + tag + struct.pack(
        "!H", ethertype
    ) + payload


def _pcap(packets: list[tuple[int, int, bytes]], linktype: int = 1) -> bytes:
    # Little-endian pcap: magic as bytes D4 C3 B2 A1, rest of header and
    # records written little-endian to match.
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts_sec, ts_usec, data in packets:
        out += struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data))
        out += data
    return out


def _pcapng(packets: list[tuple[int, int, bytes]], linktypes: list[int] | None = None) -> bytes:
    if linktypes is None:
        linktypes = [1]

    def block(block_type: int, body: bytes) -> bytes:
        pad = (4 - (len(body) % 4)) % 4
        body = body + b"\x00" * pad
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    # Section Header Block (little-endian): type, total_len, BOM, ver(2+2), sect_len(8)
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = block(0x0A0D0D0A, shb_body)

    for lt in linktypes:
        idb_body = struct.pack("<HHI", lt, 0, 65535)
        out += block(0x00000001, idb_body)

    for ts_sec, ts_usec, data in packets:
        ts = ts_sec * 1_000_000 + ts_usec
        epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data))
        epb_body += data
        out += block(0x00000006, epb_body)

    return out


@pytest.fixture
def fixtures_dir(tmp_path):
    return tmp_path


@pytest.fixture
def arp_packet() -> bytes:
    """Raw Ethernet frame carrying an ARP payload (non-IP)."""
    return _eth(0x0806, b"\x00" * 28)


@pytest.fixture
def sample_pcap(fixtures_dir):
    """A pcap with IPv4, IPv6, ARP, and a truncated packet."""
    ipv4 = _eth(
        0x0800,
        _ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 6, b"\x00" * 20),
    )
    ipv6 = _eth(
        0x86DD,
        _ipv6(
            bytes.fromhex("20010db8000000000000000000000001"),
            bytes.fromhex("20010db8000000000000000000000002"),
            17,
            b"\x00" * 8,
        ),
    )
    arp = _eth(0x0806, b"\x00" * 28)
    truncated = _eth(0x0800, b"\x45")  # too short to parse as IPv4

    path = fixtures_dir / "sample.pcap"
    path.write_bytes(
        _pcap(
            [
                (1_700_000_000, 0, ipv4),
                (1_700_000_001, 0, ipv6),
                (1_700_000_002, 0, arp),
                (1_700_000_003, 0, truncated),
            ]
        )
    )
    return path


@pytest.fixture
def sample_pcapng(fixtures_dir):
    ipv4 = _eth(
        0x0800,
        _ipv4(bytes([192, 168, 1, 1]), bytes([192, 168, 1, 2]), 17, b"\x00" * 8),
    )
    path = fixtures_dir / "sample.pcapng"
    path.write_bytes(_pcapng([(1_700_000_000, 0, ipv4)]))
    return path


@pytest.fixture
def vlan_pcap(fixtures_dir):
    ipv4 = _eth_vlan(
        100,
        0x0800,
        _ipv4(bytes([1, 1, 1, 1]), bytes([1, 1, 1, 2]), 6, b"\x00" * 20),
    )
    path = fixtures_dir / "vlan.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, ipv4)]))
    return path