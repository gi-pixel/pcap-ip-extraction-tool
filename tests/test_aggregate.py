from __future__ import annotations

from pcapscope.aggregate import Aggregator
from pcapscope.models import PacketRecord


def test_aggregator_counts_both_directions():
    agg = Aggregator()
    agg.add(PacketRecord(1.0, "8.8.8.8", "10.0.0.1", "TCP", 100))
    agg.add(PacketRecord(2.0, "10.0.0.1", "8.8.8.8", "TCP", 50))

    by_ip = {s.ip: s for s in agg.results()}
    public = by_ip["8.8.8.8"]
    private = by_ip["10.0.0.1"]

    assert public.packets_sent == 1
    assert public.packets_received == 1
    assert public.bytes_sent == 100
    assert public.bytes_received == 50
    assert public.scope == "public"

    assert private.packets_sent == 1
    assert private.packets_received == 1
    assert private.scope == "private"


def test_first_last_seen():
    agg = Aggregator()
    agg.add(PacketRecord(5.0, "8.8.8.8", "1.1.1.1", "UDP", 10))
    agg.add(PacketRecord(1.0, "1.1.1.1", "8.8.8.8", "UDP", 10))
    agg.add(PacketRecord(9.0, "8.8.8.8", "1.1.1.1", "UDP", 10))

    stats = {s.ip: s for s in agg.results()}["8.8.8.8"]
    assert stats.first_seen == 1.0
    assert stats.last_seen == 9.0