"""Extract a PacketRecord from raw link-layer bytes."""

from __future__ import annotations

import dpkt

from .models import PacketRecord

# Protocol numbers from IP headers.
_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMP"}  # 58 = ICMPv6

ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88A8

# dpkt.DLT_* values we support.
_SUPPORTED_LINKTYPES = {
    0,    # NULL / loopback (BSD)
    1,    # Ethernet
    101,  # RAW IP
    108,  # LOOP (OpenBSD)
    113,  # Linux SLL
}


class MalformedPacket(Exception):
    """Raised when a packet's bytes cannot be parsed."""


def extract_record(
    timestamp: float, raw_bytes: bytes, linktype: int
) -> PacketRecord | None:
    """Parse one packet.

    Returns None for non-IP packets (ARP, etc.). Raises MalformedPacket for
    packets that are IP-shaped but cannot be parsed, so the caller can count
    them without crashing.
    """
    if linktype not in _SUPPORTED_LINKTYPES:
        raise MalformedPacket(f"Unsupported link type {linktype}")

    payload = _strip_link_layer(raw_bytes, linktype)
    if payload is None:
        return None

    version = payload[0] >> 4
    if version == 4:
        return _extract_ipv4(timestamp, payload)
    if version == 6:
        return _extract_ipv6(timestamp, payload)
    raise MalformedPacket(f"Unknown IP version nibble {version}")


def _strip_link_layer(raw: bytes, linktype: int) -> bytes | None:
    """Strip the link-layer header and return the IP payload (or None)."""
    if not raw:
        raise MalformedPacket("Empty packet")

    if linktype == 1:  # Ethernet
        return _strip_ethernet(raw)
    if linktype in (0, 108):  # NULL / LOOP
        if len(raw) < 4:
            raise MalformedPacket("Truncated loopback header")
        # 4-byte family field in host order; just trust the IP version nibble next.
        return raw[4:]
    if linktype == 101:  # RAW IP
        return raw
    if linktype == 113:  # Linux SLL (16-byte header)
        if len(raw) < 16:
            raise MalformedPacket("Truncated SLL header")
        proto = int.from_bytes(raw[14:16], "big")
        if proto not in (ETH_TYPE_IPV4, ETH_TYPE_IPV6):
            return None
        return raw[16:]
    raise MalformedPacket(f"Unsupported link type {linktype}")


def _strip_ethernet(raw: bytes) -> bytes | None:
    if len(raw) < 14:
        raise MalformedPacket("Truncated Ethernet header")
    ethertype = int.from_bytes(raw[12:14], "big")
    offset = 14
    # Handle 802.1Q / QinQ VLAN tags.
    while ethertype in (ETH_TYPE_VLAN, ETH_TYPE_QINQ):
        if len(raw) < offset + 4:
            raise MalformedPacket("Truncated VLAN tag")
        ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype == ETH_TYPE_IPV4 or ethertype == ETH_TYPE_IPV6:
        return raw[offset:]
    return None  # ARP, etc.


def _extract_ipv4(timestamp: float, payload: bytes) -> PacketRecord:
    try:
        ip = dpkt.ip.IP(payload)
        src = _ip_to_str(dpkt.ip.IP, ip.src)
        dst = _ip_to_str(dpkt.ip.IP, ip.dst)
    except Exception as exc:  # dpkt raises various errors on bad input
        raise MalformedPacket(f"Malformed IPv4 packet: {exc}") from exc

    if not isinstance(src, str) or not isinstance(dst, str):
        raise MalformedPacket("Could not decode IPv4 addresses")

    proto_num = ip.p
    protocol = _PROTO_NAMES.get(proto_num, "OTHER")
    length = len(payload)
    return PacketRecord(timestamp, src, dst, protocol, length)


def _extract_ipv6(timestamp: float, payload: bytes) -> PacketRecord:
    try:
        ip6 = dpkt.ip6.IP6(payload)
        src = str(dpkt.ip6.inet_ntop(dpkt.socket.AF_INET6, ip6.src))
        dst = str(dpkt.ip6.inet_ntop(dpkt.socket.AF_INET6, ip6.dst))
    except Exception as exc:
        raise MalformedPacket(f"Malformed IPv6 packet: {exc}") from exc

    proto_num = ip6.nxt
    protocol = _PROTO_NAMES.get(proto_num, "OTHER")
    length = len(payload)
    return PacketRecord(timestamp, src, dst, protocol, length)


def _ip_to_str(cls, addr_bytes: bytes) -> str:
    return str(dpkt.ip.inet_ntop(dpkt.socket.AF_INET, addr_bytes))