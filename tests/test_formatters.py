from __future__ import annotations

import json

from pcapscope.formatters import format_csv, format_json, format_table
from pcapscope.models import IPStats, ParseSummary


def _sample():
    stats = [
        IPStats(
            ip="8.8.8.8",
            packets_sent=2,
            packets_received=1,
            bytes_sent=200,
            bytes_received=100,
            first_seen=1_700_000_000.0,
            last_seen=1_700_000_010.0,
            scope="public",
        )
    ]
    summary = ParseSummary(total_packets=5, ip_packets=3, skipped_non_ip=1, skipped_malformed=1)
    return stats, summary


def test_table_contains_summary():
    stats, summary = _sample()
    out = format_table(stats, summary)
    assert "8.8.8.8" in out
    assert "public" in out
    assert "total packets:" in out
    assert "skipped (malformed)" in out


def test_json_parses_and_has_summary():
    stats, summary = _sample()
    parsed = json.loads(format_json(stats, summary))
    assert parsed["ips"][0]["ip"] == "8.8.8.8"
    assert parsed["summary"]["total_packets"] == 5


def test_csv_has_header_and_rows():
    stats, summary = _sample()
    out = format_csv(stats, summary)
    assert out.startswith("ip,scope,")
    assert "8.8.8.8" in out