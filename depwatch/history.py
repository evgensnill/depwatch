"""Tracks and persists scan history for depwatch."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class ScanRecord:
    """A single historical scan record."""

    timestamp: str
    total_packages: int
    outdated_count: int
    vulnerable_count: int
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "total_packages": self.total_packages,
            "outdated_count": self.outdated_count,
            "vulnerable_count": self.vulnerable_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanRecord":
        return cls(
            timestamp=data["timestamp"],
            total_packages=data["total_packages"],
            outdated_count=data["outdated_count"],
            vulnerable_count=data["vulnerable_count"],
            notes=data.get("notes", ""),
        )


@dataclass
class ScanHistory:
    """Collection of scan records."""

    records: List[ScanRecord] = field(default_factory=list)

    def add(self, record: ScanRecord) -> None:
        self.records.append(record)

    def latest(self) -> Optional[ScanRecord]:
        return self.records[-1] if self.records else None

    def to_dict(self) -> dict:
        return {"records": [r.to_dict() for r in self.records]}

    @classmethod
    def from_dict(cls, data: dict) -> "ScanHistory":
        return cls(records=[ScanRecord.from_dict(r) for r in data.get("records", [])])


def make_scan_record(
    total_packages: int,
    outdated_count: int,
    vulnerable_count: int,
    notes: str = "",
) -> ScanRecord:
    """Create a ScanRecord stamped with the current UTC time."""
    ts = datetime.now(timezone.utc).isoformat()
    return ScanRecord(
        timestamp=ts,
        total_packages=total_packages,
        outdated_count=outdated_count,
        vulnerable_count=vulnerable_count,
        notes=notes,
    )


def load_history(path: str) -> ScanHistory:
    """Load scan history from a JSON file, returning empty history if absent."""
    if not os.path.exists(path):
        return ScanHistory()
    with open(path, "r", encoding="utf-8") as fh:
        return ScanHistory.from_dict(json.load(fh))


def save_history(history: ScanHistory, path: str) -> None:
    """Persist scan history to a JSON file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(history.to_dict(), fh, indent=2)
