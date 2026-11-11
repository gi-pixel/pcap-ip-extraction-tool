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

def test_spb_timestamp_does_not_affect_first_last_seen():
    from pcapscope.aggregate import Aggregator
    from pcapscope.models import PacketRecord
    # Simulate what the CLI does with an SPB-derived Packet (timestamp=None).
    agg = Aggregator()
    agg.add(PacketRecord(100.0, "8.8.8.8", "1.1.1.1", "TCP", 10))
    agg.add(PacketRecord(None, "8.8.8.8", "1.1.1.1", "TCP", 10))  # type: ignore[arg-type]
    stats = {s.ip: s for s in agg.results()}["8.8.8.8"]
    assert stats.first_seen == 100.0
    assert stats.last_seen == 100.0

def test_tx_rx_land_on_correct_sides():
    from pcapscope.aggregate import Aggregator
    from pcapscope.models import PacketRecord

    agg = Aggregator()
    # A:1000 -> B:80
    agg.add(PacketRecord(1.0, "10.0.0.1", "10.0.0.2", "TCP", 100, 1000, 80))
    # B:80 -> A:1000
    agg.add(PacketRecord(2.0, "10.0.0.2", "10.0.0.1", "TCP", 100, 80, 1000))

    by_ip = {s.ip: s for s in agg.results()}
    a = by_ip["10.0.0.1"]
    b = by_ip["10.0.0.2"]

    # A is the sender in packet 1: tx on port 1000.
    # A is the receiver in packet 2: rx on port 1000.
    assert a.ports[("tcp", 1000)] == [1, 1]
    # B is the receiver in packet 1: rx on port 80.
    # B is the sender in packet 2: tx on port 80.
    assert b.ports[("tcp", 80)] == [1, 1]


def test_protocols_sum_to_total(sample_pcap, sample_pcapng, vlan_pcap):
    """For every IP in every fixture, sum(protocols) == total_packets."""
    from pcapscope.aggregate import Aggregator
    from pcapscope.extract import extract_record, MalformedPacket, UnsupportedLinktype
    from pcapscope.reader import open_capture

    for capture in (sample_pcap, sample_pcapng, vlan_pcap):
        agg = Aggregator()
        for pkt in open_capture(capture):
            try:
                rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
            except (MalformedPacket, UnsupportedLinktype):
                continue
            if rec is not None:
                agg.add(rec)
        for stat in agg.results():
            assert sum(stat.protocols.values()) == stat.total_packets, (
                f"{capture.name}: {stat.ip} protocols={stat.protocols} "
                f"total={stat.total_packets}"
            )


def test_ports_overflow_at_256():
    from pcapscope.aggregate import Aggregator, MAX_TRACKED_PORTS_PER_IP
    from pcapscope.models import PacketRecord

    agg = Aggregator()
    # 300 distinct dst ports from a single source IP -> single destination IP
    for i in range(300):
        agg.add(PacketRecord(1.0, "10.0.0.1", "10.0.0.2", "TCP", 100, 1000 + i, 50000 + i))

    by_ip = {s.ip: s for s in agg.results()}

    # Source: 300 distinct source ports
    src = by_ip["10.0.0.1"]
    assert len(src.ports) == MAX_TRACKED_PORTS_PER_IP
    assert src.ports_overflow == 300 - MAX_TRACKED_PORTS_PER_IP

    # Destination: 300 distinct destination ports
    dst = by_ip["10.0.0.2"]
    assert len(dst.ports) == MAX_TRACKED_PORTS_PER_IP
    assert dst.ports_overflow == 300 - MAX_TRACKED_PORTS_PER_IP