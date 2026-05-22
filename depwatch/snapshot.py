"""Snapshot module for saving and comparing dependency states over time."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class SnapshotEntry:
    name: str
    installed_version: str
    latest_version: Optional[str]
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class Snapshot:
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    packages: Dict[str, SnapshotEntry] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "created_at": self.created_at,
            "packages": {k: asdict(v) for k, v in self.packages.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        packages = {
            k: SnapshotEntry(**v) for k, v in data.get("packages", {}).items()
        }
        return cls(created_at=data.get("created_at", ""), packages=packages)


def save_snapshot(snapshot: Snapshot, path: str) -> None:
    """Persist a snapshot to a JSON file."""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot.to_dict(), fh, indent=2)


def load_snapshot(path: str) -> Optional[Snapshot]:
    """Load a snapshot from a JSON file. Returns None if file does not exist."""
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return Snapshot.from_dict(data)


def diff_snapshots(old: Snapshot, new: Snapshot) -> Dict[str, dict]:
    """Return a dict of packages that changed between two snapshots.

    Each value contains 'old' and 'new' SnapshotEntry dicts (or None).
    """
    changed: Dict[str, dict] = {}
    all_keys = set(old.packages) | set(new.packages)
    for key in all_keys:
        o = old.packages.get(key)
        n = new.packages.get(key)
        if o != n:
            changed[key] = {
                "old": asdict(o) if o else None,
                "new": asdict(n) if n else None,
            }
    return changed
