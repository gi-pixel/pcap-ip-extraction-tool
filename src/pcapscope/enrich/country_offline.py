"""Offline country enricher backed by a local GeoLite2-Country database."""

from __future__ import annotations

from typing import Any

from ..datasets import mmdb_path
from ..models import IPStats


class CountryEnricher:
    name = "country"
    service = "GeoLite2-Country (offline)"
    requires_network = False

    def __init__(self, mmdb_file: str | None = None) -> None:
        self._path = mmdb_file
        self._reader: Any = None

    def prepare(self, stats: list[IPStats]) -> None:
        import geoip2.database  # type: ignore[import-not-found]
        path = self._path or mmdb_path("country")
        if path is None:
            raise RuntimeError(
                "GeoLite2-Country.mmdb not found. "
                "Run 'pcapscope update-data' with MAXMIND_LICENSE_KEY set, "
                "or pass --enrich-data /path/to/GeoLite2-Country.mmdb"
            )
        self._reader = geoip2.database.Reader(str(path))

    def enrich(self, ip: str) -> dict[str, Any] | None:
        try:
            resp = self._reader.country(ip)
        except Exception:
            return None
        if resp is None or resp.country is None or resp.country.iso_code is None:
            return None
        return {
            "country": resp.country.iso_code,
            "country_name": resp.country.name or "",
        }