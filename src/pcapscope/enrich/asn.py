"""Reference enricher: ASN lookup via a public HTTP API.

Uses only the standard library (`urllib.request`) so `pcapscope` gains no new
runtime dependency. The endpoint is intentionally swappable: pass a different
`url_template` to the constructor.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

_DEFAULT_URL = "https://ipinfo.io/{ip}/json"


class ASNEnricher:
    """Looks up ASN/org info for an IP.

    Note: this makes network calls. It's only wired into the CLI when the user
    passes `--enrich asn`, so the default run is offline and deterministic.
    """

    name = "asn"

    def __init__(self, url_template: str = _DEFAULT_URL, timeout: float = 5.0) -> None:
        self._url_template = url_template
        self._timeout = timeout

    def enrich(self, ip: str) -> dict[str, Any] | None:
        url = self._url_template.format(ip=ip)
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            # Let run_enrichers decide how to surface it.
            raise

        # Trim to the fields a reviewer actually wants in a report.
        keys = ("org", "asn", "country", "city")
        trimmed = {k: payload[k] for k in keys if k in payload}
        return trimmed or None