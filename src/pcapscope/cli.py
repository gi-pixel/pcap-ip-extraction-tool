"""Command-line entry point: pcapscope <file>."""

from __future__ import annotations

import argparse
import sys

from .aggregate import Aggregator
from .enrich import ASNEnricher, CachingEnricher, Enricher, GeoEnricher, run_enrichers
from .extract import MalformedPacket, extract_record
from .formatters import format_csv, format_json, format_table
from .models import IPStats, ParseSummary
from .reader import CaptureError, open_capture


def _build_enrichers(name: str | None) -> list[Enricher]:
    if name is None:
        return []
    if name == "asn":
        return [CachingEnricher(ASNEnricher())]
    if name == "geo":
        return [CachingEnricher(GeoEnricher())]
    raise ValueError(f"Unknown enricher: {name}")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcapscope",
        description="Stream a pcap/pcapng file and report unique IP addresses with stats.",
    )
    parser.add_argument("file", help="Path to a .pcap or .pcapng file")
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--public-only",
        action="store_true",
        help="Only show public IP addresses",
    )
    parser.add_argument(
        "--top",
        type=int,
        metavar="N",
        default=None,
        help="Show only the top N IPs (by total packets unless --sort says otherwise)",
    )
    parser.add_argument(
        "--sort",
        choices=("packets", "bytes", "first_seen"),
        default="packets",
        help="Sort order (default: packets)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write output to FILE instead of stdout",
    )
    parser.add_argument(
        "--enrich",
        choices=("asn", "geo"),
        default=None,
        help="Enrich results with external metadata (currently: asn, geo)",
    )
    return parser


def _sort_key(stat: IPStats, sort: str):
    if sort == "packets":
        return stat.total_packets
    if sort == "bytes":
        return stat.total_bytes
    return stat.first_seen


def run(args: argparse.Namespace) -> int:
    summary = ParseSummary()
    aggregator = Aggregator()

    try:
        for packet in open_capture(args.file):
            summary.total_packets += 1
            try:
                record = extract_record(packet.timestamp, packet.raw_bytes, packet.linktype)
            except MalformedPacket:
                summary.skipped_malformed += 1
                continue
            if record is None:
                summary.skipped_non_ip += 1
                continue
            summary.ip_packets += 1
            aggregator.add(record)
    except CaptureError as exc:
        print(f"pcapscope: error: {exc}", file=sys.stderr)
        return 1

    stats = aggregator.results()

    if args.public_only:
        stats = [s for s in stats if s.scope == "public"]

    stats.sort(key=lambda s: _sort_key(s, args.sort), reverse=(args.sort != "first_seen"))

    if args.top is not None:
        stats = stats[: args.top]

    # Enrichment runs after filtering and truncation — so we never make a
    # network call for an IP the user asked us not to show.
    try:
        enrichers = _build_enrichers(args.enrich)
    except ValueError as exc:
        print(f"pcapscope: error: {exc}", file=sys.stderr)
        return 1
    run_enrichers(stats, enrichers)

    if args.format == "json":
        output = format_json(stats, summary)
    elif args.format == "csv":
        output = format_csv(stats, summary)
    else:
        output = format_table(stats, summary)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
                if not output.endswith("\n"):
                    fh.write("\n")
        except OSError as exc:
            print(f"pcapscope: error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        print(output)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())