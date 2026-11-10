"""Render aggregation results and summary in table, JSON, or CSV form."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from .models import IPStats, ParseSummary


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "n/a"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_table(stats: list[IPStats], summary: ParseSummary) -> str:
    headers = ["IP", "scope", "sent", "received", "bytes", "first seen", "last seen"]
    rows = [
        [
            s.ip,
            s.scope,
            str(s.packets_sent),
            str(s.packets_received),
            str(s.total_bytes),
            _fmt_ts(s.first_seen),
            _fmt_ts(s.last_seen),
        ]
        for s in stats
    ]

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render_row(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    lines = [render_row(headers), render_row(["-" * w for w in widths])]
    lines.extend(render_row(row) for row in rows)
    lines.append("")
    lines.extend(_summary_lines(summary))
    return "\n".join(lines)


def _summary_lines(summary: ParseSummary) -> list[str]:
    return [
        f"total packets:      {summary.total_packets}",
        f"ip packets:         {summary.ip_packets}",
        f"skipped (non-ip):   {summary.skipped_non_ip}",
        f"skipped (malformed):{summary.skipped_malformed}",
    ]


def format_json(stats: list[IPStats], summary: ParseSummary) -> str:
    payload = {
        "ips": [
            {
                "ip": s.ip,
                "scope": s.scope,
                "packets_sent": s.packets_sent,
                "packets_received": s.packets_received,
                "bytes_sent": s.bytes_sent,
                "bytes_received": s.bytes_received,
                "total_packets": s.total_packets,
                "total_bytes": s.total_bytes,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
                "first_seen_iso": _fmt_ts(s.first_seen),
                "last_seen_iso": _fmt_ts(s.last_seen),
                "enriched": s.enriched,
            }
            for s in stats
        ],
        "summary": {
            "total_packets": summary.total_packets,
            "ip_packets": summary.ip_packets,
            "skipped_non_ip": summary.skipped_non_ip,
            "skipped_malformed": summary.skipped_malformed,
        },
    }
    return json.dumps(payload, indent=2)


def format_csv(stats: list[IPStats], summary: ParseSummary) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["ip", "scope", "packets_sent", "packets_received", "bytes",
         "first_seen", "last_seen"]
    )
    for s in stats:
        writer.writerow(
            [
                s.ip,
                s.scope,
                s.packets_sent,
                s.packets_received,
                s.total_bytes,
                _fmt_ts(s.first_seen),
                _fmt_ts(s.last_seen),
            ]
        )
    writer.writerow([])
    for line in _summary_lines(summary):
        writer.writerow([line])
    return buf.getvalue()