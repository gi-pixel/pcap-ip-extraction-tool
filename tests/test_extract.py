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


def test_arp_returns_none(arp_packet):
    assert extract_record(0.0, arp_packet, 1) is None


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

def test_snaplen_truncated_ipv4_is_counted(fixtures_dir):
    # A full 100-byte IP packet, but the capture only kept the first 34 bytes.
        from helpers import _eth, _ipv4, _pcap  # see note below on imports

    full = _eth(0x0800, _ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 6, b"\x00" * 80))
    truncated = full[:34]  # 14-byte Ethernet header + 20-byte IPv4 header, no payload
    path = fixtures_dir / "snap.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, truncated)]))

    from pcapscope.reader import open_capture
    from pcapscope.extract import extract_record
    pkt = next(iter(open_capture(path)))
    rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
    assert rec is not None
    assert rec.src_ip == "10.0.0.1"
    # Captured < total_len: snaplen truncation, not an error.
    assert rec.length == 100


def test_ipv4_length_zero_uses_captured(fixtures_dir):
    # TSO case: total-length field is 0 on the wire.
    from helpers import _eth, _pcap
    import struct

    payload = b"\x00" * 80
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 0,  # version/IHL, DSCP, total_len=0
        0, 0, 64, 6, 0,
        bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]),
    ) + payload
    frame = _eth(0x0800, ip_hdr)
    path = fixtures_dir / "tso.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, frame)]))

    from pcapscope.reader import open_capture
    from pcapscope.extract import extract_record
    pkt = next(iter(open_capture(path)))
    rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
    assert rec is not None
    assert rec.length == len(ip_hdr)  # captured, not 0


def test_ethernet_padding_uses_ip_length(fixtures_dir):
    # 20-byte IP header, no payload; Ethernet pads the frame to 60 bytes.
    from helpers import _eth, _ipv4, _pcap
    payload = _ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 6, b"")
    frame = _eth(0x0800, payload)
    assert len(frame) < 60  # confirms padding is needed
    padded = frame + b"\x00" * (60 - len(frame))
    path = fixtures_dir / "padded.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, padded)]))

    from pcapscope.reader import open_capture
    from pcapscope.extract import extract_record
    pkt = next(iter(open_capture(path)))
    rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
    assert rec is not None
    assert rec.length == 20  # ip.len, not the 60-byte frame


def test_ipv4_length_below_header_is_malformed(fixtures_dir):
    from helpers import _eth, _pcap
    import struct

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 12,  # total_len=12, below the 20-byte header
        0, 0, 64, 6, 0,
        bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]),
    )
    frame = _eth(0x0800, ip_hdr)
    path = fixtures_dir / "badlen.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, frame)]))

    from pcapscope.reader import open_capture
    import pytest
    from pcapscope.extract import MalformedPacket, extract_record
    pkt = next(iter(open_capture(path)))
    with pytest.raises(MalformedPacket):
        extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)


def test_ipv6_plen_zero_with_extra_bytes_uses_captured(fixtures_dir):
    # plen=0 but extra bytes present: use captured length, not 40.
    from helpers import _eth, _pcap
    import struct

    extra = b"\x00" * 30
    ip6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000, 0, 59, 64,  # plen=0, next-header=No Next Header
        bytes.fromhex("20010db8000000000000000000000001"),
        bytes.fromhex("20010db8000000000000000000000002"),
    ) + extra
    frame = _eth(0x86DD, ip6_hdr)
    path = fixtures_dir / "v6jumbo.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, frame)]))

    from pcapscope.reader import open_capture
    from pcapscope.extract import extract_record
    pkt = next(iter(open_capture(path)))
    rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
    assert rec is not None
    assert rec.length == len(ip6_hdr)  # captured, not 40


def test_ipv6_plen_zero_exactly_40_bytes(fixtures_dir):
    from helpers import _eth, _pcap
    import struct

    ip6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000, 0, 59, 64,
        bytes.fromhex("20010db8000000000000000000000001"),
        bytes.fromhex("20010db8000000000000000000000002"),
    )
    frame = _eth(0x86DD, ip6_hdr)
    path = fixtures_dir / "v6empty.pcap"
    path.write_bytes(_pcap([(1_700_000_000, 0, frame)]))

    from pcapscope.reader import open_capture
    from pcapscope.extract import extract_record
    pkt = next(iter(open_capture(path)))
    rec = extract_record(pkt.timestamp, pkt.raw_bytes, pkt.linktype)
    assert rec is not None
    assert rec.length == 40