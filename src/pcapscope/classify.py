"""Classify an IP address into a scope bucket."""

from __future__ import annotations

import ipaddress


def classify_ip(ip: str) -> str:
    """Return one of: public, private, loopback, link_local, multicast, reserved."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "reserved"

    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    # Reserved must win over private: Python's is_private also returns True for
    # 240.0.0.0/4 (Class E) and IPv6 documentation ranges like 2001:db8::/32.
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    if addr.version == 4 and addr in ipaddress.ip_network("240.0.0.0/4"):
        return "reserved"
    if addr.is_private:
        return "private"
    return "public"