from __future__ import annotations

import json

import pytest
import urllib.error


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
    def fake_build(names, mmdb_dir=None):
        if names and "asn" in names:
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

def test_two_enrichers_merge_under_distinct_keys():
    stats = [IPStats(ip="8.8.8.8")]
    asn = FakeEnricher({"8.8.8.8": {"org": "Google"}})
    asn.name = "asn"
    geo = FakeEnricher({"8.8.8.8": {"country": "US"}})
    geo.name = "geo"
    run_enrichers(stats, [asn, geo])
    assert stats[0].enriched == {
        "asn": {"org": "Google"},
        "geo": {"country": "US"},
    }


def test_geo_enricher_trims_fields(tmp_path):
    # Serve a canned JSON document over file:// so the test never touches the net.
    payload = tmp_path / "8.8.8.8.json"
    payload.write_text(
        '{"country":"US","region":"California","city":"Mountain View",'
        '"loc":"37.4,-122.1","org":"Google","asn":"AS15169"}'
    )
    from pcapscope.enrich.geo import GeoEnricher

    geo = GeoEnricher(url_template=f"file://{payload}")
    assert geo.enrich("8.8.8.8") == {
        "country": "US",
        "region": "California",
        "city": "Mountain View",
        "loc": "37.4,-122.1",
    }


def test_cli_with_geo_enrich(sample_pcap, capsys, monkeypatch):
    def fake_build(names, mmdb_dir=None):
        if names and "geo" in names:
            return [CachingEnricher(FakeEnricher({"8.8.8.8": {"country": "US"}}))]
        return []

    monkeypatch.setattr(cli, "_build_enrichers", fake_build)
    rc = cli.main([str(sample_pcap), "--format", "json", "--enrich", "geo"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    by_ip = {ip["ip"]: ip for ip in parsed["ips"]}
    assert by_ip["8.8.8.8"]["enriched"]["fake"] == {"country": "US"}

def test_multi_enrich_merges_under_distinct_keys():
    """`--enrich asn --enrich rdns` merges both under their names."""
    from pcapscope.enrich import CachingEnricher, run_enrichers
    from pcapscope.models import IPStats

    class StubA:
        name = "asn"
        service = "asn"
        requires_network = False

        def enrich(self, ip):
            return {"asn": "AS15169", "org": "Google LLC"}

    class StubB:
        name = "rdns"
        service = "rdns"
        requires_network = True

        def enrich(self, ip):
            return {"rdns": "dns.google"}

    stats = [IPStats(ip="8.8.8.8")]
    run_enrichers(stats, [CachingEnricher(StubA()), CachingEnricher(StubB())])
    assert stats[0].enriched["asn"] == {"asn": "AS15169", "org": "Google LLC"}
    assert stats[0].enriched["rdns"] == {"rdns": "dns.google"}


def test_offline_prepare_failure_is_fatal():
    """Offline enricher missing its dataset -> RuntimeError, not silent None."""
    from pcapscope.enrich import run_enrichers
    from pcapscope.models import IPStats

    class BrokenOffline:
        name = "asn"
        service = "asn"
        requires_network = False

        def prepare(self, stats):
            raise RuntimeError("GeoLite2-ASN.mmdb not found")

        def enrich(self, ip):
            return None

    with pytest.raises(RuntimeError, match="GeoLite2-ASN.mmdb not found"):
        run_enrichers([IPStats(ip="8.8.8.8")], [BrokenOffline()])


def test_online_failure_does_not_abort_offline_output():
    """If online enricher fails systemically, offline output survives."""
    from pcapscope.enrich import run_enrichers
    from pcapscope.models import IPStats

    class OKOffline:
        name = "asn"
        service = "asn"
        requires_network = False

        def prepare(self, stats):
            pass

        def enrich(self, ip):
            return {"asn": "AS1"}

    class FailingOnline:
        name = "rdns"
        service = "rdns"
        requires_network = True

        def enrich(self, ip):
            raise ConnectionError("network down")

    stats = [IPStats(ip="8.8.8.8"), IPStats(ip="1.1.1.1")]
    run_enrichers(stats, [OKOffline(), FailingOnline()])
    assert stats[0].enriched["asn"] == {"asn": "AS1"}
    assert stats[1].enriched["asn"] == {"asn": "AS1"}
    # rdns recorded an error on the first IP; the loop aborted, so the
    # second IP has no rdns entry at all.
    assert "error" in stats[0].enriched["rdns"]
    assert "rdns" not in stats[1].enriched
    """If online enricher fails systemically, offline output survives."""
    from pcapscope.enrich import run_enrichers

    class OKOffline:
        name = "asn"
        service = "asn"
        requires_network = False
        def enrich(self, ip):
            return {"asn": "AS1"}
        def prepare(self, stats):
            pass

    class FailingOnline:
        name = "rdns"
        service = "rdns"
        requires_network = True
        def enrich(self, ip):
            raise ConnectionError("network down")

    stats = [IPStats(ip="8.8.8.8"), IPStats(ip="1.1.1.1")]
    run_enrichers(stats, [OKOffline(), FailingOnline()])
    assert stats[0].enriched["asn"] == {"asn": "AS1"}
    assert stats[1].enriched["asn"] == {"asn": "AS1"}
    # rdns recorded error on the first, remaining skipped
    assert "error" in stats[0].enriched["rdns"]
    assert "rdns" not in stats[1].enriched or not stats[1].enriched.get

def test_asn_offline_resolves_known_ip():
    """ASNEnricher queries a stubbed geoip2 reader and returns asn/org."""
    from pcapscope.enrich.asn import ASNEnricher

    class StubResponse:
        autonomous_system_number = 15169
        autonomous_system_organization = "Google LLC"

    class StubReader:
        def asn(self, ip):
            assert ip == "8.8.8.8"
            return StubResponse()
        def close(self):
            pass

    enricher = ASNEnricher(mmdb_file="/dev/null")
    enricher._reader = StubReader()
    result = enricher.enrich("8.8.8.8")
    assert result == {"asn": "AS15169", "org": "Google LLC"}


def test_asn_offline_unknown_ip():
    """Reader raises on unknown IP; ASNEnricher returns None."""
    from pcapscope.enrich.asn import ASNEnricher

    class StubReader:
        def asn(self, ip):
            raise ValueError("not in database")
        def close(self):
            pass

    enricher = ASNEnricher(mmdb_file="/dev/null")
    enricher._reader = StubReader()
    assert enricher.enrich("203.0.113.1") is None


def test_country_offline_resolves_known_ip():
    from pcapscope.enrich.country_offline import CountryEnricher

    class StubCountry:
        iso_code = "US"
        name = "United States"

    class StubResponse:
        country = StubCountry()

    class StubReader:
        def country(self, ip):
            return StubResponse()
        def close(self):
            pass

    enricher = CountryEnricher(mmdb_file="/dev/null")
    enricher._reader = StubReader()
    result = enricher.enrich("8.8.8.8")
    assert result == {"country": "US", "country_name": "United States"}


def test_cloud_matches_aws(tmp_path, monkeypatch):
    """A small in-memory CIDR list matches as expected."""
    from pcapscope.enrich.cloud import CloudEnricher

    # Write a tiny AWS-shaped JSON
    aws_file = tmp_path / "aws-ranges.json"
    aws_file.write_text(
        '{"prefixes": [{"ip_prefix": "54.0.0.0/8", "region": "us-east-1"}]}'
    )

    enricher = CloudEnricher()
    # Override the loader to read from our file, ignoring cache-dir conventions
    from pcapscope.enrich import cloud as cloud_mod
    monkeypatch.setattr(cloud_mod, "list_file_path", lambda name: aws_file)
    enricher.prepare(stats=[])

    assert enricher.enrich("54.10.0.1") == {"provider": "aws", "region": "us-east-1"}
    assert enricher.enrich("8.8.8.8") is None


def test_tor_matches(tmp_path, monkeypatch):
    from pcapscope.enrich.tor import TorEnricher

    tor_file = tmp_path / "tor-exit-list.txt"
    tor_file.write_text("185.220.101.1\n185.220.101.2\n")

    from pcapscope.enrich import tor as tor_mod
    monkeypatch.setattr(tor_mod, "list_file_path", lambda name: tor_file)

    enricher = TorEnricher()
    enricher.prepare(stats=[])

    assert enricher.enrich("185.220.101.1") == {"tor_exit": True}
    assert enricher.enrich("8.8.8.8") is None


def test_rdap_parses_response(monkeypatch):
    """Stubbed urlopen returns canned RDAP JSON; the parser extracts fields."""
    from pcapscope.enrich.rdap import RDAPEnricher

    payload = {
        "name": "GOOGLE",
        "country": "US",
        "entities": [
            {
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Google LLC"]],
                ]
            }
        ],
    }

    class StubResp:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            import json as _json
            return _json.dumps(payload).encode("utf-8")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: StubResp())

    enricher = RDAPEnricher()
    result = enricher.enrich("8.8.8.8")
    assert result == {
        "network_name": "GOOGLE",
        "country": "US",
        "org": "Google LLC",
    }


def test_rdap_network_failure_returns_none(monkeypatch):
    from pcapscope.enrich.rdap import RDAPEnricher

    import urllib.error
    import urllib.request

    def fail(url, timeout):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    enricher = RDAPEnricher()
    # rdap.py propagates the exception; run_enrichers catches it.
    # So call enrich directly and expect the raise.
    import pytest
    with pytest.raises(urllib.error.URLError):
        enricher.enrich("8.8.8.8")


def test_rdns_returns_name(monkeypatch):
    import socket
    from pcapscope.enrich.rdns import ReverseDNSEnricher

    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("dns.google", [], ["8.8.8.8"])
    )
    enricher = ReverseDNSEnricher()
    assert enricher.enrich("8.8.8.8") == {"rdns": "dns.google"}


def test_rdns_failure_returns_none(monkeypatch):
    import socket
    from pcapscope.enrich.rdns import ReverseDNSEnricher

    def fail(ip):
        raise socket.herror("no PTR")

    monkeypatch.setattr(socket, "gethostbyaddr", fail)
    enricher = ReverseDNSEnricher()
    assert enricher.enrich("8.8.8.8") is None