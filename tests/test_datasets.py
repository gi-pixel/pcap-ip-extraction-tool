"""Tests for pcapscope.datasets — cache path resolution and downloads."""

from __future__ import annotations

import pytest


def test_list_file_path_returns_cache_path(monkeypatch, tmp_path):
    from pcapscope import datasets
    monkeypatch.setattr(datasets, "CACHE_DIR", tmp_path)
    path = datasets.list_file_path("aws")
    assert path.parent == tmp_path
    assert path.name == "aws-ranges.json"


def test_download_lists_writes_file(monkeypatch, tmp_path):
    from pcapscope import datasets
    monkeypatch.setattr(datasets, "CACHE_DIR", tmp_path)

    class StubResp:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            return b"1.2.3.4\n5.6.7.8\n"

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: StubResp())

    written = datasets.download_lists("tor")
    assert written == 1
    out = tmp_path / "tor-exit-list.txt"
    assert out.is_file()
    assert out.read_text() == "1.2.3.4\n5.6.7.8\n"


def test_mmdb_path_returns_none_when_missing(monkeypatch, tmp_path):
    from pcapscope import datasets
    monkeypatch.setattr(datasets, "CACHE_DIR", tmp_path)
    # System paths are checked too; patch them to nonexistent.
    # The function's candidates list includes cache_dir and /usr/share/...
    # On WSL with GeoLite2 not installed, the system paths won't exist.
    assert datasets.mmdb_path("asn") is None