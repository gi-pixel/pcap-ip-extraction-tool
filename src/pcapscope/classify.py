"""Classify an IP address into a scope bucket."""

from __future__ import annotations

import ipaddress

_SCOPES = ("public", "private", "loopback", "link_local", "multicast", "reserved")


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
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"