"""Locating and downloading external data files used by enrichers."""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

CACHE_DIR = Path(os.environ.get("PCAPSCOPE_CACHE", "~/.cache/pcapscope")).expanduser()

# All downloadable URLs and the local filename they're cached under.
_LIST_SOURCES = {
    "aws": (
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "aws-ranges.json",
    ),
    "gcp": (
        "https://www.gstatic.com/ipranges/cloud.json",
        "gcp-ranges.json",
    ),
    "cloudflare_v4": (
        "https://www.cloudflare.com/ips-v4",
        "cloudflare-v4.txt",
    ),
    "cloudflare_v6": (
        "https://www.cloudflare.com/ips-v6",
        "cloudflare-v6.txt",
    ),
    "tor": (
        "https://check.torproject.org/torbulkexitlist",
        "tor-exit-list.txt",
    ),
}

_GEOLITE2_ASN_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-ASN&license_key={key}&suffix=tar.gz"
)
_GEOLITE2_COUNTRY_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-Country&license_key={key}&suffix=tar.gz"
)


def cache_dir() -> Path:
    """Return the cache directory, creating it if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def list_file_path(name: str) -> Path:
    """Local path for a named list source (aws, gcp, cloudflare_v4, …)."""
    if name not in _LIST_SOURCES:
        raise KeyError(f"unknown list source: {name}")
    _, filename = _LIST_SOURCES[name]
    return cache_dir() / filename


def mmdb_path(name: str) -> Path | None:
    """Path to a GeoLite2 .mmdb file, or None if not present.

    `name` is 'asn' or 'country'.
    """
    candidates = [
        cache_dir() / f"GeoLite2-{name.capitalize()}.mmdb",
        cache_dir() / f"GeoLite2-{name.upper()}.mmdb",
        Path(f"/usr/share/GeoLite2/GeoLite2-{name.capitalize()}.mmdb"),
        Path(f"/var/lib/GeoLite2/GeoLite2-{name.capitalize()}.mmdb"),
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def download_lists(*names: str) -> int:
    """Download the named list sources into the cache dir. Returns count of files written."""
    written = 0
    for name in names:
        url, filename = _LIST_SOURCES[name]
        dest = cache_dir() / filename
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                dest.write_bytes(resp.read())
            print(f"wrote {dest}", file=sys.stderr)
            written += 1
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"failed to fetch {url}: {exc}", file=sys.stderr)
    return written


def download_geolite2(which: str, license_key: str) -> bool:
    """Download a GeoLite2 .mmdb (which = 'asn' or 'country') into the cache dir.

    Returns True on success. MaxMind ships a tar.gz containing the .mmdb; this
    extracts the .mmdb and discards the rest.
    """
    import tarfile
    import tempfile

    if which == "asn":
        url = _GEOLITE2_ASN_URL.format(key=license_key)
        inner_name = "GeoLite2-ASN.mmdb"
    elif which == "country":
        url = _GEOLITE2_COUNTRY_URL.format(key=license_key)
        inner_name = "GeoLite2-Country.mmdb"
    else:
        raise ValueError(f"unknown GeoLite2 dataset: {which}")

    dest = cache_dir() / inner_name
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
                tmp.write(resp.read())
                tmp_path = Path(tmp.name)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"failed to fetch GeoLite2-{which}: {exc}", file=sys.stderr)
        return False

    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(inner_name):
                    with tar.extractfile(member) as src:
                        if src is not None:
                            dest.write_bytes(src.read())
                    print(f"wrote {dest}", file=sys.stderr)
                    return True
        print(f"GeoLite2-{which}: {inner_name} not found in archive", file=sys.stderr)
        return False
    finally:
        tmp_path.unlink(missing_ok=True)