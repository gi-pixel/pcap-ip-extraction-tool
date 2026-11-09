from __future__ import annotations

import pytest

from pcapscope.classify import classify_ip


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", "public"),
        ("10.0.0.1", "private"),
        ("192.168.1.1", "private"),
        ("172.16.0.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("2001:4860:4860::8888", "public"),
        ("fe80::1", "link_local"),
        ("::1", "loopback"),
        ("ff02::1", "multicast"),
    ],
)
def test_classify(ip, expected):
    assert classify_ip(ip) == expected