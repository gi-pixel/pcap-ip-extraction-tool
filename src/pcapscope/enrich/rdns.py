"""Online reverse-DNS enricher using the system resolver."""

from __future__ import annotations

import socket
from typing import Any


class ReverseDNSEnricher:
    name = "rdns"
    service = "system reverse DNS"
    requires_network = True

    def enrich(self, ip: str) -> dict[str, Any] | None:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, OSError):
            return None
        return {"rdns": name}