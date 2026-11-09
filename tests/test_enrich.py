from __future__ import annotations

import json

import pytest

from pcapscope import cli
from pcapscope.enrich import CachingEnricher, Enricher, run_enrichers
from pcapscope.models import IPStats


class FakeEnricher:
    name = "fake"

    def __init__(self, mapping: dict[str, dict | None]) -> None:
        self.mapping = mapping
        self.calls = 0

    def enrich(self, ip: str) -> dict | None:
        self.calls += 1
        return self.mapping.get(ip)


class BoomEnricher:
    name = "boom"

    def enrich(self, ip: str) -> dict | None:
        raise RuntimeError("network down")


def test_run_enrichers_merges_output():
    stats = [IPStats(ip="8.8.8.8"), IPStats(ip="10.0.0.1")]
    enricher = FakeEnricher({"8.8.8.8": {"org": "Google"}})
    run_enrichers(stats, [enricher])
    assert stats[0].enriched == {"fake": {"org": "Google"}}
    assert stats[1].enriched == {}


def test_caching_enricher_calls_once_per_ip():
    inner = FakeEnricher({"8.8.8.8": {"org": "Google"}})
    cached = CachingEnricher(inner)
    stats = [IPStats(ip="8.8.8.8"), IPStats(ip="8.8.8.8")]

    # Simulate calling enrich twice for the same IP via run_enrichers' loop
    for s in stats:
        cached.enrich(s.ip)

    assert inner.calls == 1


def test_enricher_failure_is_non_fatal():
    stats = [IPStats(ip="8.8.8.8")]
    run_enrichers(stats, [BoomEnricher()])
    assert stats[0].enriched["boom"]["error"] == "network down"


def test_cli_with_enrich_uses_json_field(sample_pcap, capsys, monkeypatch):
    def fake_build(name):
        if name == "asn":
            return [CachingEnricher(FakeEnricher({"8.8.8.8": {"org": "Google"}}))]
        return []

    monkeypatch.setattr(cli, "_build_enrichers", fake_build)
    rc = cli.main([str(sample_pcap), "--format", "json", "--enrich", "asn"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    by_ip = {ip["ip"]: ip for ip in parsed["ips"]}
    assert by_ip["8.8.8.8"]["enriched"]["fake"] == {"org": "Google"}


def test_cli_without_enrich_has_empty_enriched(sample_pcap, capsys):
    rc = cli.main([str(sample_pcap), "--format", "json"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    for ip in parsed["ips"]:
        assert ip["enriched"] == {}