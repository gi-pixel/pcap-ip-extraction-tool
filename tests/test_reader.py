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