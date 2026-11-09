"""Enricher protocol, caching wrapper, and the run loop.

An enricher takes an IP string and returns a dict of metadata (or None if it
has nothing to say). The pipeline calls each enricher once per unique IP, after
aggregation and before formatting.
"""

from __future__ import annotations

from typing import Any, Iterable, Protocol, runtime_checkable

from ..models import IPStats


@runtime_checkable
class Enricher(Protocol):
    """Structural interface for an enricher.

    Implementations only need a `name` attribute and an `enrich(ip)` method.
    """

    name: str

    def enrich(self, ip: str) -> dict[str, Any] | None: ...


class CachingEnricher:
    """Wrap an enricher so each IP is looked up at most once per run.

    The cache is per-instance, so a fresh CachingEnricher per CLI invocation
    means no cross-run leakage. Memory scales with unique IPs, matching the
    aggregator's discipline.
    """

    def __init__(self, inner: Enricher) -> None:
        self._inner = inner
        self.name = inner.name
        self._cache: dict[str, dict[str, Any] | None] = {}

    def enrich(self, ip: str) -> dict[str, Any] | None:
        if ip not in self._cache:
            self._cache[ip] = self._inner.enrich(ip)
        return self._cache[ip]


def run_enrichers(stats: Iterable[IPStats], enrichers: Iterable[Enricher]) -> None:
    """Mutate each IPStats in place, merging each enricher's output under its name.

    Enricher failures are non-fatal: an exception from one enricher is caught
    and recorded as {"error": "..."} so a network blip doesn't lose the rest
    of the report. The enricher's output for that IP is still a dict, so
    formatters see a uniform shape.
    """
    enrichers = list(enrichers)
    if not enrichers:
        return

    for stat in stats:
        for enricher in enrichers:
            try:
                result = enricher.enrich(stat.ip)
            except Exception as exc:  # network, JSON, rate limit — all non-fatal
                stat.enriched[enricher.name] = {"error": str(exc)}
                continue
            if result:
                stat.enriched[enricher.name] = result