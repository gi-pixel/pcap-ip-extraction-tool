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