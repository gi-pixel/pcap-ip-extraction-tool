"""ASN/org lookup via ipinfo.io (online)."""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

_DEFAULT_URL = "https://ipinfo.io/{ip}/json"
_ORG_ASN_RE = re.compile(r"^AS(\d+)\s+(.*)$")


class ASNOnlineEnricher:
    name = "asn-online"
    service = "ipinfo.io"
    requires_network = True

    def __init__(self, url_template: str = _DEFAULT_URL, timeout: float = 5.0) -> None:
        self._url_template = url_template
        self._timeout = timeout

    def enrich(self, ip: str) -> dict[str, Any] | None:
        url = self._url_template.format(ip=ip)
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        keys = ("org", "asn", "country", "city")
        trimmed: dict[str, Any] = {k: payload[k] for k in keys if k in payload}
        if "asn" not in trimmed and isinstance(trimmed.get("org"), str):
            m = _ORG_ASN_RE.match(trimmed["org"])
            if m:
                trimmed["asn"] = f"AS{m.group(1)}"
                trimmed["org"] = m.group(2)
        return trimmed or None