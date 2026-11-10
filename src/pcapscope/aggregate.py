"""Aggregate PacketRecords into per-IP statistics."""

from __future__ import annotations

from .classify import classify_ip
from .models import IPStats, PacketRecord


class Aggregator:
    """Accumulate per-IP counters. Memory scales with unique IPs only."""

    def __init__(self) -> None:
        self._stats: dict[str, IPStats] = {}

    def add(self, record: PacketRecord) -> None:
        src = self._get_or_create(record.src_ip)
        dst = self._get_or_create(record.dst_ip)

        src.packets_sent += 1
        src.bytes_sent += record.length
        _touch(src, record.timestamp)

        dst.packets_received += 1
        dst.bytes_received += record.length
        _touch(dst, record.timestamp)

    def results(self) -> list[IPStats]:
        return list(self._stats.values())

    def _get_or_create(self, ip: str) -> IPStats:
        stats = self._stats.get(ip)
        if stats is None:
            # Classification computed once per unique IP.
            stats = IPStats(
                ip=ip,
                first_seen=None,
                last_seen=None,
                scope=classify_ip(ip),
            )
            self._stats[ip] = stats
        return stats


def _touch(stats: IPStats, ts: float | None) -> None:
    if ts is None:
        return
    if stats.first_seen is None or ts < stats.first_seen:
        stats.first_seen = ts
    if stats.last_seen is None or ts > stats.last_seen:
        stats.last_seen = ts