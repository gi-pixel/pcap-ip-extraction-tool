"""Extract a PacketRecord from raw link-layer bytes."""

from __future__ import annotations

import socket

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

class UnsupportedLinktype(Exception):
    """Raised when the capture's link type is not supported."""

    def __init__(self, linktype: int) -> None:
        self.linktype = linktype
        super().__init__(f"unsupported link type {linktype}")

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
        raise UnsupportedLinktype(linktype)

    payload = _strip_link_layer(raw_bytes, linktype)
    if payload is None:
        return None
    if not payload:
        raise MalformedPacket("Empty IP payload after link-layer strip")

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
    captured = len(payload)

    # Header-only checks first. These reject genuinely corrupt packets, not
    # snaplen-truncated ones.
    if captured < 20:
        raise MalformedPacket(
            f"IPv4 packet too short for header: {captured} bytes"
        )
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20:
        raise MalformedPacket(f"IPv4 IHL below minimum: {ihl} bytes")
    if ihl > captured:
        raise MalformedPacket(
            f"IPv4 header length {ihl} exceeds captured {captured} bytes"
        )

    try:
        ip = dpkt.ip.IP(payload)
    except Exception as exc:
        raise MalformedPacket(f"Malformed IPv4 packet: {exc}") from exc

    total_len = ip.len
    # Total length 0 is valid: TCP segmentation offload on the sending host
    # leaves the field at 0 and fills it in later (Wireshark warns on this).
    # In that case, fall back to the captured length.
    if total_len == 0:
        byte_count = captured
    elif total_len < ihl:
        raise MalformedPacket(
            f"IPv4 total length {total_len} below header length {ihl}"
        )
    else:
        # Snaplen truncation is normal; do not reject when captured < total_len.
        byte_count = total_len

    src = socket.inet_ntop(socket.AF_INET, ip.src)
    dst = socket.inet_ntop(socket.AF_INET, ip.dst)
    protocol = _PROTO_NAMES.get(ip.p, "OTHER")
    return PacketRecord(timestamp, src, dst, protocol, byte_count)


def _extract_ipv6(timestamp: float, payload: bytes) -> PacketRecord:
    captured = len(payload)
    if captured < 40:
        raise MalformedPacket(
            f"IPv6 packet too short for header: {captured} bytes"
        )

    try:
        ip6 = dpkt.ip6.IP6(payload)
    except Exception as exc:
        raise MalformedPacket(f"Malformed IPv6 packet: {exc}") from exc

    plen = ip6.plen
    # plen == 0 means either a zero-payload packet or a jumbogram whose real
    # length is in a Hop-by-Hop Jumbo Payload option. In both cases, use the
    # captured length. Snaplen truncation is not an error.
    byte_count = 40 + plen if plen > 0 else captured

    src = socket.inet_ntop(socket.AF_INET6, ip6.src)
    dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
    # ip6.p is the protocol after walking extension headers; ip6.nxt is only
    # the first next-header value.
    protocol = _PROTO_NAMES.get(ip6.p, "OTHER")
    return PacketRecord(timestamp, src, dst, protocol, byte_count)