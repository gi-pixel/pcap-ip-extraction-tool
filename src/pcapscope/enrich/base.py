"""Enricher protocol, caching wrapper, and the run loop."""

from __future__ import annotations

import sys
import urllib.error
from typing import Any, Iterable, Protocol, runtime_checkable

from ..models import IPStats


@runtime_checkable
class Enricher(Protocol):
    """Structural interface for an enricher.

    Implementations provide:
      - `name` (str): key under IPStats.enriched
      - `service` (str): human-readable source, used in stderr notices
      - `requires_network` (bool): True for online enrichers
      - `enrich(ip) -> dict | None`: look up one IP
      - `prepare(stats)`: optional; called once before the enrich loop.
        Default no-op. Offline enrichers load their dataset here.
    """

    name: str
    service: str
    requires_network: bool

    def enrich(self, ip: str) -> dict[str, Any] | None: ...

    def prepare(self, stats: list[IPStats]) -> None:
        """Optional. Called once before the enrich loop."""
        return None


class CachingEnricher:
    def __init__(self, inner: Enricher) -> None:
        self._inner = inner
        self.name = inner.name
        self.service = getattr(inner, "service", inner.name)
        self.requires_network = getattr(inner, "requires_network", False)
        self._cache: dict[str, dict[str, Any] | None] = {}

    def prepare(self, stats: list[IPStats]) -> None:
        prep = getattr(self._inner, "prepare", None)
        if prep is not None:
            prep(stats)

    def enrich(self, ip: str) -> dict[str, Any] | None:
        if ip not in self._cache:
            self._cache[ip] = self._inner.enrich(ip)
        return self._cache[ip]


def _is_systemic(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        return code in (401, 403, 429) or 500 <= code < 600
    if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError)):
        return True
    return False

def run_enrichers(stats: Iterable[IPStats], enrichers: Iterable[Enricher]) -> None:
    enrichers = list(enrichers)
    if not enrichers:
        return

    stats = list(stats)
    total = len(stats)

    # Prepare phase. Offline prepare failures are fatal.
    for enricher in enrichers:
        prep = getattr(enricher, "prepare", None)
        if prep is None:
            continue
        try:
            prep(stats)
        except Exception as exc:
            if getattr(enricher, "requires_network", False):
                continue
            raise RuntimeError(f"{enricher.name}: prepare failed: {exc}") from exc

    for enricher in enrichers:
        service = getattr(enricher, "service", enricher.name)
        online = getattr(enricher, "requires_network", False)
        print(
            f"pcapscope: enriching {total} IPs via {service}"
            + (" (online)" if online else " (offline)"),
            file=sys.stderr,
        )

        done = 0
        aborted = False
        abort_reason = ""
        for stat in stats:
            if aborted:
                break
            try:
                result = enricher.enrich(stat.ip)
            except Exception as exc:
                if _is_systemic(exc) and online:
                    stat.enriched[enricher.name] = {"error": str(exc)}
                    aborted = True
                    abort_reason = str(exc)
                    break
                stat.enriched[enricher.name] = {"error": str(exc)}
                done += 1
                continue
            if result:
                stat.enriched[enricher.name] = result
            done += 1

        if aborted:
            print(
                f"pcapscope: enrichment stopped after {done} of {total} IPs "
                f"via {service}: {abort_reason}",
                file=sys.stderr,
            )
    """Run enrichers against stats.

    Error policy:
      - Offline enrichers (requires_network=False) that fail in prepare() or
        enrich() abort the run: their data was expected to be present.
      - Online enrichers (requires_network=True) that fail in enrich()
        record the error on that IP and continue. A network outage
        shouldn't discard the offline enrichers' output.
    """
    enrichers = list(enrichers)
    if not enrichers:
        return

    stats = list(stats)
    total = len(stats)

    # Prepare phase. Offline prepare failures are fatal.
    for enricher in enrichers:
        prep = getattr(enricher, "prepare", None)
        if prep is None:
            continue
        try:
            prep(stats)
        except Exception as exc:
            if getattr(enricher, "requires_network", False):
                continue
            raise RuntimeError(f"{enricher.name}: prepare failed: {exc}") from exc

    for enricher in enrichers:
        service = getattr(enricher, "service", enricher.name)
        online = getattr(enricher, "requires_network", False)
        print(
            f"pcapscope: enriching {total} IPs via {service}"
            + (" (online)" if online else " (offline)"),
            file=sys.stderr,
        )

        done = 0
        aborted = False
        abort_reason = ""
        for stat in stats:
            if aborted:
                break
            try:
                result = enricher.enrich(stat.ip)
            except Exception as exc:
                if _is_systemic(exc) and online:
                    stat.enriched[enricher.name] = {"error": str(exc)}
                    aborted = True
                    abort_reason = str(exc)
                    break
                stat.enriched[enricher.name] = {"error": str(exc)}
                done += 1
                continue
            if result:
                stat.enriched[enricher.name] = result
            done += 1

        if aborted:
            print(
                f"pcapscope: enrichment stopped after {done} of {total} IPs "
                f"via {service}: {abort_reason}",
                file=sys.stderr,
            )