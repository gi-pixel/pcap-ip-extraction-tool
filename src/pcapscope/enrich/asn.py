"""Reference enricher: ASN lookup via a public HTTP API."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

_DEFAULT_URL = "https://ipinfo.io/{ip}/json"


class ASNEnricher:
    """Looks up ASN/org info for an IP.

    Network errors propagate; `run_enrichers` catches them and records
    {"error": ...} on the IPStats. This is the single error-handling site
    for all enrichers, so individual enrichers stay trivial.
    """

    name = "asn"

    def __init__(self, url_template: str = _DEFAULT_URL, timeout: float = 5.0) -> None:
        self._url_template = url_template
        self._timeout = timeout

    def enrich(self, ip: str) -> dict[str, Any] | None:
        url = self._url_template.format(ip=ip)
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        keys = ("org", "asn", "country", "city")
        trimmed = {k: payload[k] for k in keys if k in payload}
        return trimmed or None