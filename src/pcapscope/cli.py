"""Command-line entry point: pcapscope <file>."""

from __future__ import annotations

import argparse
import sys
import os

from .datasets import download_geolite2, download_lists
from .enrich import (
    ASNEnricher, ASNOnlineEnricher, CachingEnricher,
    CloudEnricher, CountryEnricher, Enricher, GeoEnricher,
    RDAPEnricher, ReverseDNSEnricher, TorEnricher, run_enrichers,
)
from .aggregate import Aggregator
from .enrich import ASNEnricher, CachingEnricher, Enricher, GeoEnricher, run_enrichers
from .extract import MalformedPacket, extract_record, UnsupportedLinktype
from .formatters import format_csv, format_json, format_table
from .models import IPStats, ParseSummary
from .reader import CaptureError, open_capture


def _build_enrichers(names: list[str] | None, mmdb_dir: str | None = None) -> list[Enricher]:
    if not names:
        return []
    out: list[Enricher] = []
    for name in names:
        if name == "asn":
            out.append(CachingEnricher(ASNEnricher(mmdb_dir)))
        elif name == "asn-online":
            out.append(CachingEnricher(ASNOnlineEnricher()))
        elif name == "country":
            out.append(CachingEnricher(CountryEnricher(mmdb_dir)))
        elif name == "cloud":
            out.append(CachingEnricher(CloudEnricher()))
        elif name == "tor":
            out.append(CachingEnricher(TorEnricher()))
        elif name == "rdap":
            out.append(CachingEnricher(RDAPEnricher()))
        elif name == "rdns":
            out.append(CachingEnricher(ReverseDNSEnricher()))
        elif name == "geo":
            out.append(CachingEnricher(GeoEnricher()))
        else:
            raise ValueError(f"Unknown enricher: {name}")
    return out

def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int: {value!r}") from exc
    if n <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer, got {n}")
    return n

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
        type=_positive_int,
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
        action="append",
        metavar="NAME",
        help=(
            "Enable an enricher (repeatable). Choices: "
            "asn, asn-online, country, cloud, tor, rdap, rdns, geo"
        ),
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Add protocol and port breakdown columns",
    )
        parser.add_argument(
        "--enrich-data",
        metavar="DIR_OR_FILE",
        default=None,
        help="Path to a GeoLite2 .mmdb file (overrides the ASN/Country default)",
    )
    parser.add_argument("file", nargs="?", help="Path to a .pcap or .pcapng file")
    return parser


def _sort_key(stat: IPStats, sort: str):
    if sort == "packets":
        return stat.total_packets
    if sort == "bytes":
        return stat.total_bytes
    return stat.first_seen if stat.first_seen is not None else float("-inf")


def run(args: argparse.Namespace) -> int:
    summary = ParseSummary()
    aggregator = Aggregator()

    try:
        for packet in open_capture(args.file):
            summary.total_packets += 1
            try:
                record = extract_record(packet.timestamp, packet.raw_bytes, packet.linktype)
            except UnsupportedLinktype as exc:
                _LINKTYPE_NAMES = {276: "Linux cooked v2"}
                hint = _LINKTYPE_NAMES.get(exc.linktype)
                hint_str = f" ({hint})" if hint else ""
                print(
                    f"pcapscope: error: unsupported link type "
                    f"{exc.linktype}{hint_str}",
                    file=sys.stderr,
                )
                return 1
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

    if args.sort == "first_seen":
        stats.sort(key=lambda s: (s.first_seen, s.ip))
    else:
        stats.sort(key=lambda s: (_sort_key(s, args.sort), s.ip), reverse=True)

    if args.top is not None:
        stats = stats[: args.top]

    # Enrichment runs after filtering and truncation — so we never make a
    # network call for an IP the user asked us not to show.
    try:
        enrichers = _build_enrichers(args.enrich, args.enrich_data)
    except ValueError as exc:
        print(f"pcapscope: error: {exc}", file=sys.stderr)
        return 1
    try:
        run_enrichers(stats, enrichers)
    except RuntimeError as exc:
        print(f"pcapscope: error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        output = format_json(stats, summary)
    elif args.format == "csv":
        output = format_csv(stats, summary, show_ports=args.ports)
    else:
        output = format_table(stats, summary, show_ports=args.ports)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="") as fh:
                fh.write(output)
                if not output.endswith("\n"):
                    fh.write("\n")
        except OSError as exc:
            print(f"pcapscope: error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        try:
            print(output)
        except BrokenPipeError:
            try:
                sys.stdout.close()
            except Exception:
                pass
            return 0

    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "update-data":
        return _update_data(argv[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.file:
        parser.error("the following arguments are required: file")
    return run(args)


def _update_data(argv: list[str]) -> int:
    import argparse as _argparse
    parser = _argparse.ArgumentParser(prog="pcapscope update-data")
    parser.add_argument("--maxmind-key", default=None)
    args = parser.parse_args(argv)

    print("Downloading public data...", file=sys.stderr)
    download_lists("aws", "gcp", "cloudflare_v4", "cloudflare_v6", "tor")

    key = args.maxmind_key or os.environ.get("MAXMIND_LICENSE_KEY")
    if not key:
        print(
            "GeoLite2 skipped; set MAXMIND_LICENSE_KEY or pass --maxmind-key",
            file=sys.stderr,
        )
        return 0
    print("Downloading GeoLite2-ASN...", file=sys.stderr)
    ok_asn = download_geolite2("asn", key)
    print("Downloading GeoLite2-Country...", file=sys.stderr)
    ok_country = download_geolite2("country", key)
    return 0 if ok_asn and ok_country else 1

if __name__ == "__main__":
    sys.exit(main())