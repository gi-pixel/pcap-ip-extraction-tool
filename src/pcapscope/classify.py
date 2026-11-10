"""Classify an IP address into a scope bucket."""

from __future__ import annotations

import ipaddress

# Explicit networks for the `private` bucket. Do not use `is_private` —
# Python's flags for IPv4-mapped IPv6, 192.0.0.0/24, and documentation ranges
# have drifted between releases. Explicit lists are stable.
_V4_PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_V6_PRIVATE = (ipaddress.ip_network("fc00::/7"),)
_V4_SHARED = ipaddress.ip_network("100.64.0.0/10")


def classify_ip(ip: str) -> str:
    """Return one of: public, private, shared, loopback, link_local,
    multicast, reserved."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "reserved"

    # IPv4-mapped IPv6 (e.g. ::ffff:8.8.8.8): classify the embedded IPv4 address.
    # The original string is preserved by the caller; only the classification
    # uses the unwrapped form.
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified or addr.is_reserved:
        return "reserved"
    if addr.version == 4 and addr in _V4_SHARED:
        return "shared"
    if addr.version == 4 and any(addr in n for n in _V4_PRIVATE):
        return "private"
    if addr.version == 6 and any(addr in n for n in _V6_PRIVATE):
        return "private"
    if addr.is_global:
        return "public"
    return "reserved"