"""Fixtures for pcapscope tests. Builders live in helpers.py."""

from __future__ import annotations

import pytest

from helpers import (
    _eth,
    _eth_vlan,
    _ipv4,
    _ipv6,
    _pcap,
    _pcap_be,
    _pcapng,
    _pcapng_be,
)


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


@pytest.fixture
def pcap_be_usec(fixtures_dir):
    ipv4 = _eth(0x0800, _ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 6, b"\x00" * 20))
    path = fixtures_dir / "be_usec.pcap"
    path.write_bytes(_pcap_be([(1_700_000_000, 500_000, ipv4)]))
    return path


@pytest.fixture
def pcap_be_nsec(fixtures_dir):
    ipv4 = _eth(0x0800, _ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 6, b"\x00" * 20))
    path = fixtures_dir / "be_nsec.pcap"
    path.write_bytes(_pcap_be([(1_700_000_000, 500_000_000, ipv4)], nanosecond=True))
    return path


@pytest.fixture
def pcapng_be(fixtures_dir):
    ipv4 = _eth(0x0800, _ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 6, b"\x00" * 20))
    path = fixtures_dir / "be.pcapng"
    path.write_bytes(_pcapng_be([(1_700_000_000, 0, ipv4)]))
    return path