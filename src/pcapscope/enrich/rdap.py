"""Online RDAP (WHOIS replacement) enricher."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class RDAPEnricher:
    name = "rdap"
    service = "rdap.org"
    requires_network = True

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def enrich(self, ip: str) -> dict[str, Any] | None:
        url = f"https://rdap.org/ip/{ip}"
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        out: dict[str, Any] = {}
        if "name" in payload:
            out["network_name"] = payload["name"]
        if "country" in payload:
            out["country"] = payload["country"]
        for entity in payload.get("entities", []):
            if "vcardArray" in entity:
                vcard = entity["vcardArray"]
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if len(field) >= 4 and field[0] == "fn":
                            out["org"] = field[3]
                            break
        return out or None