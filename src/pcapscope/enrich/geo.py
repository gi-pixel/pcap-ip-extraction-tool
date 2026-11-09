"""Reference enricher: geographic location for an IP.

Same protocol as ASNEnricher — one `enrich(ip)` method, one `name` attribute.
Demonstrates that the Enricher protocol isn't shaped around a single
implementation: the fields differ, the source could differ, and nothing outside
`enrich/` needs to know.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

_DEFAULT_URL = "https://ipinfo.io/{ip}/json"


class GeoEnricher:
    """Looks up country/region/city/loc for an IP."""

    name = "geo"

    def __init__(self, url_template: str = _DEFAULT_URL, timeout: float = 5.0) -> None:
        self._url_template = url_template
        self._timeout = timeout

    def enrich(self, ip: str) -> dict[str, Any] | None:
        url = self._url_template.format(ip=ip)
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        keys = ("country", "region", "city", "loc")
        trimmed = {k: payload[k] for k in keys if k in payload}
        return trimmed or None