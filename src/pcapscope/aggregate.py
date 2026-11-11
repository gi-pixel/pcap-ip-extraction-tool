"""Aggregate PacketRecords into per-IP statistics."""

from __future__ import annotations

from .classify import classify_ip
from .models import IPStats, PacketRecord

MAX_TRACKED_PORTS_PER_IP = 256

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

        _count_protocol(src, record.protocol)
        _count_protocol(dst, record.protocol)

        if record.src_port is not None and record.dst_port is not None:
            proto = record.protocol.lower()
            _count_port(src, proto, record.src_port, is_tx=True)
            _count_port(dst, proto, record.dst_port, is_tx=False)

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

def _count_protocol(stats: IPStats, protocol: str) -> None:
    stats.protocols[protocol] = stats.protocols.get(protocol, 0) + 1


def _count_port(stats: IPStats, proto: str, port: int, *, is_tx: bool) -> None:
    key = (proto, port)
    if key in stats.ports:
        stats.ports[key][0 if is_tx else 1] += 1
        return
    if len(stats.ports) >= MAX_TRACKED_PORTS_PER_IP:
        stats.ports_overflow += 1
        return
    stats.ports[key] = [1, 0] if is_tx else [0, 1]