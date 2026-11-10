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
        ("100.64.0.1", "shared"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("192.0.0.1", "reserved"),
        ("198.18.0.1", "reserved"),
        ("192.0.2.1", "reserved"),
        ("0.0.0.0", "reserved"),
        ("2001:4860:4860::8888", "public"),
        ("fc00::1", "private"),
        ("2001:db8::1", "reserved"),
        ("fe80::1", "link_local"),
        ("::1", "loopback"),
        ("ff02::1", "multicast"),
        ("::ffff:10.0.0.1", "private"),
        ("::ffff:8.8.8.8", "public"),
        ("::ffff:127.0.0.1", "loopback"),
    ],
)
def test_classify(ip, expected):
    assert classify_ip(ip) == expected

def test_public_only_and_enrich_use_only_public():
    # Contract check: only the "public" scope is eligible for --public-only
    # and enrichment. This test documents the invariant; the filters
    # themselves are asserted in test_cli.py.
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("100.64.0.1") != "public"
    assert classify_ip("10.0.0.1") != "public"