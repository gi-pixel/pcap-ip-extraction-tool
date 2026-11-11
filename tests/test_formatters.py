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

def test_json_keys_include_ports_fields():
    stats, summary = _sample()
    parsed = json.loads(format_json(stats, summary))
    ip = parsed["ips"][0]
    # Original keys still present
    for key in ("ip", "scope", "packets_sent", "packets_received",
                "bytes_sent", "bytes_received", "total_packets",
                "total_bytes", "first_seen", "last_seen", "enriched"):
        assert key in ip, f"missing {key}"
    # New batch-1 keys
    for key in ("protocols", "ports", "top_ports", "ports_overflow"):
        assert key in ip, f"missing new key {key}"


def test_table_with_ports_has_new_columns():
    stats, summary = _sample()
    # _sample has no ports; use a stats object with some.
    stats[0].protocols = {"TCP": 3, "UDP": 1}
    stats[0].ports = {("tcp", 443): [2, 1], ("udp", 53): [0, 1]}
    out = format_table(stats, summary, show_ports=True)
    assert "protocols" in out
    assert "top ports" in out
    assert "TCP:3" in out
    assert "tcp/443" in out


def test_table_without_ports_is_unchanged():
    stats, summary = _sample()
    baseline = format_table(stats, summary)
    # Calling with show_ports=False explicitly must give the same output
    assert format_table(stats, summary, show_ports=False) == baseline
    # And without show_ports at all
    assert format_table(stats, summary) == baseline


def test_top_ports_ordering_is_deterministic():
    stats, summary = _sample()
    stats[0].ports = {
        ("tcp", 443): [10, 5],   # total 15
        ("tcp", 80): [5, 5],     # total 10
        ("udp", 53): [5, 5],     # total 10; udp before tcp at equal total
        ("tcp", 8080): [3, 2],   # total 5
    }
    out1 = format_table(stats, summary, show_ports=True)
    out2 = format_table(stats, summary, show_ports=True)
    assert out1 == out2
    # The sort is total desc, then proto, then port. So among the 10-total
    # entries, ('tcp', 80) should come before ('udp', 53)? No — sort key is
    # (-total, proto, port), so 'tcp' < 'udp' means tcp/80 before udp/53.
    parsed = json.loads(format_json(stats, summary))
    tops = parsed["ips"][0]["top_ports"]
    assert tops[0]["port"] == 443
    assert (tops[1]["proto"], tops[1]["port"]) == ("tcp", 80)
    assert (tops[2]["proto"], tops[2]["port"]) == ("udp", 53)
    assert tops[3]["port"] == 8080

def test_summary_has_public_ips_named_line():
    stats, summary = _sample()
    summary.public_ips_total = 10
    summary.public_ips_named = 7
    out = format_table(stats, summary)
    assert "public IPs named:" in out
    assert "7 of 10" in out


def test_json_summary_has_named_counters():
    stats, summary = _sample()
    summary.public_ips_total = 10
    summary.public_ips_named = 7
    parsed = json.loads(format_json(stats, summary))
    assert parsed["summary"]["public_ips_named"] == 7
    assert parsed["summary"]["public_ips_total"] == 10