"""Render aggregation results and summary in table, JSON, or CSV form."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from .models import IPStats, ParseSummary


_TOP_PORTS_JSON = 10
_TOP_PORTS_TABLE = 3

def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "n/a"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_table(
    stats: list[IPStats], summary: ParseSummary, show_ports: bool = False
) -> str:
    headers = ["IP", "scope", "sent", "received", "ip bytes"]
    if show_ports:
        headers.extend(["protocols", "top ports"])
    headers.extend(["first seen", "last seen"])
    rows = []
    for s in stats:
        row = [
            s.ip,
            s.scope,
            str(s.packets_sent),
            str(s.packets_received),
            str(s.total_bytes),
        ]
        if show_ports:
            row.extend([_fmt_protocols(s.protocols), _fmt_top_ports(s.ports)])
        row.extend([_fmt_ts(s.first_seen), _fmt_ts(s.last_seen)])
        rows.append(row)

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
        f"total packets:       {summary.total_packets}",
        f"ip packets:          {summary.ip_packets}",
        f"skipped (non-ip):    {summary.skipped_non_ip}",
        f"skipped (malformed): {summary.skipped_malformed}",
        f"public IPs named:    {summary.public_ips_named} of {summary.public_ips_total}",
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
                "enriched": s.enriched,
                "protocols": s.protocols,
                "ports": {f"{proto}/{port}": [tx, rx] for (proto, port), (tx, rx) in s.ports.items()},
                "top_ports": _top_ports_json(s.ports),
                "ports_overflow": s.ports_overflow,
            }
            for s in stats
        ],
        "summary": {
            "total_packets": summary.total_packets,
            "ip_packets": summary.ip_packets,
            "skipped_non_ip": summary.skipped_non_ip,
            "skipped_malformed": summary.skipped_malformed,
            "public_ips_named": summary.public_ips_named,
            "public_ips_total": summary.public_ips_total,
        },
    }
    return json.dumps(payload, indent=2)


def format_csv(
    stats: list[IPStats], summary: ParseSummary, show_ports: bool = False
) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    header = ["ip", "scope", "packets_sent", "packets_received", "ip_bytes"]
    if show_ports:
        header.extend(["protocols", "top_ports"])
    header.extend(["first_seen", "last_seen"])
    writer.writerow(header)
    for s in stats:
        row = [
            s.ip,
            s.scope,
            s.packets_sent,
            s.packets_received,
            s.total_bytes,
        ]
        if show_ports:
            row.extend([_fmt_protocols(s.protocols), _fmt_top_ports(s.ports)])
        row.extend([_fmt_ts(s.first_seen), _fmt_ts(s.last_seen)])
        writer.writerow(row)
    writer.writerow([])
    for line in _summary_lines(summary):
        writer.writerow([line])
    return buf.getvalue()

def _top_ports_json(ports: dict[tuple[str, int], list[int]]) -> list[dict]:
    """Up to 10 top ports, sorted by total desc, then proto, then port."""
    items = [
        (proto, port, tx, rx)
        for (proto, port), (tx, rx) in ports.items()
    ]
    items.sort(key=lambda x: (-(x[2] + x[3]), x[0], x[1]))
    return [
        {"proto": proto, "port": port, "tx": tx, "rx": rx, "total": tx + rx}
        for proto, port, tx, rx in items[:_TOP_PORTS_JSON]
    ]


def _fmt_protocols(protocols: dict[str, int]) -> str:
    """e.g. 'TCP:812 UDP:3' sorted by count desc, then name."""
    items = sorted(protocols.items(), key=lambda kv: (-kv[1], kv[0]))
    return " ".join(f"{name}:{count}" for name, count in items) or "-"


def _fmt_top_ports(ports: dict[tuple[str, int], list[int]]) -> str:
    """e.g. 'tcp/443 udp/53' — top 3 by total desc, then proto, then port."""
    items = [
        (proto, port, tx + rx)
        for (proto, port), (tx, rx) in ports.items()
    ]
    items.sort(key=lambda x: (-x[2], x[0], x[1]))
    return " ".join(f"{proto}/{port}" for proto, port, _ in items[:_TOP_PORTS_TABLE]) or "-"