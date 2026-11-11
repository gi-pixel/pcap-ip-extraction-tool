"""Offline Tor exit-node matcher."""

from __future__ import annotations

from typing import Any

from ..datasets import list_file_path
from ..models import IPStats


class TorEnricher:
    name = "tor"
    service = "Tor exit list (offline)"
    requires_network = False

    def __init__(self) -> None:
        self._nodes: set[str] = set()

    def prepare(self, stats: list[IPStats]) -> None:
        path = list_file_path("tor")
        if not path.is_file():
            raise RuntimeError(
                "Tor exit list not found. Run 'pcapscope update-data' to download it."
            )
        self._nodes = {line.strip() for line in path.read_text().splitlines() if line.strip()}

    def enrich(self, ip: str) -> dict[str, Any] | None:
        return {"tor_exit": True} if ip in self._nodes else None