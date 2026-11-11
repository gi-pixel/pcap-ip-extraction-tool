"""Offline cloud-provider matcher using published CIDR lists."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from ..datasets import list_file_path
from ..models import IPStats


def _load_aws(path) -> list[tuple[ipaddress._BaseNetwork, str]]:
    data = json.loads(path.read_text())
    out = []
    for entry in data.get("prefixes", []):
        cidr = entry.get("ip_prefix") or entry.get("ipv6_prefix")
        region = entry.get("region", "")
        if cidr:
            out.append((ipaddress.ip_network(cidr), f"aws:{region}"))
    return out


def _load_gcp(path) -> list[tuple[ipaddress._BaseNetwork, str]]:
    data = json.loads(path.read_text())
    out = []
    for entry in data.get("prefixes", []):
        cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        scope = entry.get("scope", "")
        if cidr:
            out.append((ipaddress.ip_network(cidr), f"gcp:{scope}"))
    return out


def _load_cloudflare(path) -> list[tuple[ipaddress._BaseNetwork, str]]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append((ipaddress.ip_network(line), "cloudflare"))
    return out


class CloudEnricher:
    name = "cloud"
    service = "cloud provider ranges (offline)"
    requires_network = False

    def __init__(self) -> None:
        self._ranges: list[tuple[ipaddress._BaseNetwork, str]] = []

    def prepare(self, stats: list[IPStats]) -> None:
        loaders = [
            ("aws", _load_aws),
            ("gcp", _load_gcp),
            ("cloudflare_v4", _load_cloudflare),
            ("cloudflare_v6", _load_cloudflare),
        ]
        for name, loader in loaders:
            path = list_file_path(name)
            if path.is_file():
                try:
                    self._ranges.extend(loader(path))
                except (ValueError, json.JSONDecodeError):
                    continue
        if not self._ranges:
            raise RuntimeError(
                "No cloud provider range lists found. "
                "Run 'pcapscope update-data' to download them."
            )

    def enrich(self, ip: str) -> dict[str, Any] | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, label in self._ranges:
            if addr in net:
                provider, _, region = label.partition(":")
                result = {"provider": provider}
                if region:
                    result["region"] = region
                return result
        return None