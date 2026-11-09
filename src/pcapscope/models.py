"""Data models shared across the pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PacketRecord:
    """A single parsed IP packet, reduced to the fields the pipeline needs."""

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str  # TCP, UDP, ICMP, OTHER
    length: int


@dataclass
class IPStats:
    """Aggregated statistics for a single IP address."""

    ip: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    scope: str = ""

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass
class ParseSummary:
    """Counters describing what the parse stage did."""

    total_packets: int = 0
    ip_packets: int = 0
    skipped_non_ip: int = 0
    skipped_malformed: int = 0