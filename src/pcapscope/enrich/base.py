"""Enricher protocol, caching wrapper, and the run loop."""

from __future__ import annotations

import sys
import urllib.error
from typing import Any, Iterable, Protocol, runtime_checkable

from ..models import IPStats


@runtime_checkable
class Enricher(Protocol):
    name: str
    service: str

    def enrich(self, ip: str) -> dict[str, Any] | None: ...


class CachingEnricher:
    def __init__(self, inner: Enricher) -> None:
        self._inner = inner
        self.name = inner.name
        self.service = getattr(inner, "service", inner.name)
        self._cache: dict[str, dict[str, Any] | None] = {}

    def enrich(self, ip: str) -> dict[str, Any] | None:
        if ip not in self._cache:
            self._cache[ip] = self._inner.enrich(ip)
        return self._cache[ip]


def _is_systemic(exc: BaseException) -> bool:
    """True if the error should abort remaining lookups."""
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        return code in (401, 403, 429) or 500 <= code < 600
    if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError)):
        return True
    return False


def run_enrichers(stats: Iterable[IPStats], enrichers: Iterable[Enricher]) -> None:
    """Mutate each IPStats in place, merging each enricher's output under its name."""
    enrichers = list(enrichers)
    if not enrichers:
        return

    stats = list(stats)
    total = len(stats)
    for enricher in enrichers:
        service = getattr(enricher, "service", enricher.name)
        print(
            f"pcapscope: enriching {total} IPs via {service}",
            file=sys.stderr,
        )

    for enricher in enrichers:
        service = getattr(enricher, "service", enricher.name)
        done = 0
        aborted = False
        abort_reason = ""
        for stat in stats:
            if aborted:
                break
            try:
                result = enricher.enrich(stat.ip)
            except Exception as exc:
                if _is_systemic(exc):
                    stat.enriched[enricher.name] = {"error": str(exc)}
                    aborted = True
                    abort_reason = str(exc)
                    break
                # Per-IP error (e.g. 404): record on this IP, continue.
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