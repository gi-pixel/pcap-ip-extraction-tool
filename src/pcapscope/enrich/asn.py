"""Offline ASN enricher backed by a local GeoLite2-ASN database."""

from __future__ import annotations

from typing import Any

from ..datasets import mmdb_path
from ..models import IPStats


class ASNEnricher:
    name = "asn"
    service = "GeoLite2-ASN (offline)"
    requires_network = False

    def __init__(self, mmdb_file: str | None = None) -> None:
        self._path = mmdb_file
        self._reader: Any = None

    def prepare(self, stats: list[IPStats]) -> None:
        import geoip2.database  # type: ignore[import-not-found]
        path = self._path or mmdb_path("ASN")
        if path is None or not path.is_file():
            raise RuntimeError(
                "GeoLite2-ASN.mmdb not found. Run 'pcapscope update-data' "
                "with MAXMIND_LICENSE_KEY set, or pass --enrich-data."
            )
        self._reader = geoip2.database.Reader(str(path))

    def enrich(self, ip: str) -> dict[str, Any] | None:
        try:
            resp = self._reader.asn(ip)
        except Exception:
            return None
        if resp is None or resp.autonomous_system_number is None:
            return None
        return {
            "asn": f"AS{resp.autonomous_system_number}",
            "org": resp.autonomous_system_organization or "",
        }