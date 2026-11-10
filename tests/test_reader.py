from __future__ import annotations

import pytest

from pcapscope.reader import CaptureError, open_capture


def test_pcap_streams_packets(sample_pcap):
    packets = list(open_capture(sample_pcap))
    assert len(packets) == 4
    assert all(p.linktype == 1 for p in packets)


def test_pcapng_streams_packets(sample_pcapng):
    packets = list(open_capture(sample_pcapng))
    assert len(packets) == 1
    assert packets[0].linktype == 1


def test_missing_file(tmp_path):
    with pytest.raises(CaptureError, match="not found"):
        list(open_capture(tmp_path / "nope.pcap"))


def test_empty_file(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(CaptureError, match="empty"):
        list(open_capture(p))


def test_unrecognized_format(tmp_path):
    p = tmp_path / "junk.pcap"
    p.write_bytes(b"NOTAPCAP")
    with pytest.raises(CaptureError, match="Unrecognized"):
        list(open_capture(p))

def test_pcap_big_endian_usec(pcap_be_usec):
    from pcapscope.reader import open_capture
    pkts = list(open_capture(pcap_be_usec))
    assert len(pkts) == 1
    assert pkts[0].timestamp == pytest.approx(1_700_000_000.5)
    assert pkts[0].linktype == 1


def test_pcap_big_endian_nsec(pcap_be_nsec):
    from pcapscope.reader import open_capture
    pkts = list(open_capture(pcap_be_nsec))
    assert len(pkts) == 1
    assert pkts[0].timestamp == pytest.approx(1_700_000_000.5)


def test_pcapng_big_endian(pcapng_be):
    from pcapscope.reader import open_capture
    pkts = list(open_capture(pcapng_be))
    assert len(pkts) == 1
    assert pkts[0].linktype == 1

def test_pcapng_multi_section_resets_interfaces(pcapng_multi_section):
    """A new SHB must reset interface state; section 2's linktype differs from
    section 1's, so a failure to reset would parse section 2's packet wrongly."""
    from pcapscope.reader import open_capture
    from pcapscope.extract import extract_record

    packets = list(open_capture(pcapng_multi_section))
    assert len(packets) == 2
    assert packets[0].linktype == 1
    assert packets[1].linktype == 101

    rec0 = extract_record(packets[0].timestamp, packets[0].raw_bytes, packets[0].linktype)
    rec1 = extract_record(packets[1].timestamp, packets[1].raw_bytes, packets[1].linktype)
    assert rec0 is not None and rec0.src_ip == "10.0.0.1"
    assert rec1 is not None and rec1.src_ip == "10.0.0.2"
    assert packets[0].timestamp == pytest.approx(1_700_000_000.0)
    assert packets[1].timestamp == pytest.approx(1_700_000_001.0)