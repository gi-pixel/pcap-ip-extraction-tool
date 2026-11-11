from __future__ import annotations

import json

from pcapscope.cli import main


def test_cli_table(sample_pcap, capsys):
    rc = main([str(sample_pcap)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "total packets:" in out


def test_cli_json(sample_pcap, capsys):
    rc = main([str(sample_pcap), "--format", "json"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert "ips" in parsed and "summary" in parsed


def test_cli_public_only(sample_pcap, capsys):
    rc = main([str(sample_pcap), "--format", "json", "--public-only"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert all(ip["scope"] == "public" for ip in parsed["ips"])


def test_cli_sort_and_top(sample_pcap, capsys):
    rc = main([str(sample_pcap), "--format", "json", "--sort", "bytes", "--top", "1"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert len(parsed["ips"]) == 1


def test_cli_missing_file(tmp_path, capsys):
    rc = main([str(tmp_path / "nope.pcap")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "error" in err
    assert "Traceback" not in err


def test_cli_output_file(sample_pcap, tmp_path, capsys):
    out = tmp_path / "out.txt"
    rc = main([str(sample_pcap), "--output", str(out)])
    assert rc == 0
    assert "8.8.8.8" in out.read_text()

def test_cli_unsupported_linktype_exits_once(fixtures_dir, capsys):
    import struct
    # Minimal pcap with linktype 276, one packet.
    data = b"\x00" * 50
    pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 276)
    pcap += struct.pack("<IIII", 1_700_000_000, 0, len(data), len(data)) + data
    path = fixtures_dir / "sll2.pcap"
    path.write_bytes(pcap)

    from pcapscope.cli import main
    rc = main([str(path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "unsupported link type 276" in err
    assert "Linux cooked v2" in err
    assert "skipped (malformed)" not in capsys.readouterr().out

def test_cli_top_rejects_zero_and_negative(sample_pcap, capsys):
    from pcapscope.cli import main
    import pytest
    with pytest.raises(SystemExit):
        main([str(sample_pcap), "--top", "0"])
    with pytest.raises(SystemExit):
        main([str(sample_pcap), "--top", "-3"])

def test_enrich_flag_is_repeatable():
    from pcapscope.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["x", "--enrich", "asn", "--enrich", "rdns"])
    assert args.enrich == ["asn", "rdns"]


def test_enrich_unknown_name_errors(sample_pcap, capsys):
    from pcapscope.cli import main
    rc = main([str(sample_pcap), "--enrich", "bogus"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Unknown enricher" in err or "bogus" in err


def test_update_data_runs_offline(monkeypatch, capsys):
    """update-data with download functions stubbed returns 0."""
    from pcapscope import cli

    calls = {"lists": [], "geolite2": []}

    def fake_download_lists(*names):
        calls["lists"].append(names)
        return len(names)

    def fake_download_geolite2(which, key):
        calls["geolite2"].append((which, key))
        return True

    monkeypatch.setattr(cli, "download_lists", fake_download_lists)
    monkeypatch.setattr(cli, "download_geolite2", fake_download_geolite2)

    rc = cli.main(["update-data", "--maxmind-key", "fake-key"])
    assert rc == 0
    assert len(calls["lists"]) == 1
    assert len(calls["geolite2"]) == 2


def test_offline_enricher_missing_data_exits(sample_pcap, capsys, monkeypatch):
    """If ASNEnricher.prepare raises RuntimeError, CLI exits 1 with a clear message."""
    from pcapscope import cli

    class FailingASN:
        name = "asn"
        service = "GeoLite2-ASN"
        requires_network = False
        def prepare(self, stats):
            raise RuntimeError(
                "GeoLite2-ASN.mmdb not found. "
                "Run 'pcapscope update-data' with MAXMIND_LICENSE_KEY set."
            )
        def enrich(self, ip):
            return None

    from pcapscope.enrich import CachingEnricher
    monkeypatch.setattr(
        cli, "_build_enrichers",
        lambda names, mmdb_dir=None: [CachingEnricher(FailingASN())] if names else [],
    )

    rc = cli.main([str(sample_pcap), "--enrich", "asn"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "GeoLite2-ASN.mmdb not found" in err