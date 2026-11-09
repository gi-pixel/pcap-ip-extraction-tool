from __future__ import annotations

import pytest

from pcapscope.extract import MalformedPacket, extract_record


def test_ipv4_and_ipv6(sample_pcap):
    from pcapscope.reader import open_capture

    records = []
    for pkt in open_capture(sample_pcap):
        try:
            r = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
        except MalformedPacket:
            continue
        if r is not None:
            records.append(r)
    addrs = {r.src_ip for r in records} | {r.dst_ip for r in records}
    assert "10.0.0.1" in addrs
    assert "8.8.8.8" in addrs
    assert "2001:db8::1" in addrs
    assert "2001:db8::2" in addrs


def test_arp_returns_none(fixtures_dir):
    from tests.conftest import _eth, _pcap

    arp = _eth(0x0806, b"\x00" * 28)
    assert extract_record(0.0, arp, 1) is None


def test_truncated_raises(sample_pcap):
    from pcapscope.reader import open_capture

    pkts = list(open_capture(sample_pcap))
    truncated = pkts[-1].raw_bytes
    with pytest.raises(MalformedPacket):
        extract_record(0.0, truncated, 1)


def test_vlan_tagged(vlan_pcap):
    from pcapscope.reader import open_capture

    pkt = next(iter(open_capture(vlan_pcap)))
    rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
    assert rec is not None
    assert rec.src_ip == "1.1.1.1"
    assert rec.protocol == "TCP"