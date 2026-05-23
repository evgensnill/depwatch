"""Baseline management: pin current state as an approved baseline."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

from depwatch.snapshot import Snapshot, SnapshotEntry


@dataclass
class Baseline:
    """A pinned snapshot used as the approved reference state."""

    entries: Dict[str, SnapshotEntry] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "notes": self.notes,
            "entries": {name: e.to_dict() for name, e in self.entries.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        entries = {
            name: SnapshotEntry.from_dict(v)
            for name, v in data.get("entries", {}).items()
        }
        return cls(entries=entries, notes=data.get("notes", ""))

    @classmethod
    def from_snapshot(cls, snapshot: Snapshot, notes: str = "") -> "Baseline":
        return cls(entries=dict(snapshot.entries), notes=notes)


def save_baseline(baseline: Baseline, path: str) -> None:
    """Persist a baseline to *path* as JSON."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline.to_dict(), fh, indent=2)


def load_baseline(path: str) -> Baseline:
    """Load a baseline from *path*; raises FileNotFoundError if absent."""
    with open(path, "r", encoding="utf-8") as fh:
        return Baseline.from_dict(json.load(fh))


def deviations_from_baseline(
    baseline: Baseline, snapshot: Snapshot
) -> List[str]:
    """Return human-readable strings describing packages that deviate from the baseline."""
    messages: List[str] = []
    for name, entry in snapshot.entries.items():
        if name not in baseline.entries:
            messages.append(f"{name}: new package not in baseline (installed {entry.installed_version})")
            continue
        base_entry = baseline.entries[name]
        if entry.installed_version != base_entry.installed_version:
            messages.append(
                f"{name}: version changed {base_entry.installed_version} -> {entry.installed_version}"
            )
        new_vulns = {v.vuln_id for v in entry.vulnerabilities} - {
            v.vuln_id for v in base_entry.vulnerabilities
        }
        if new_vulns:
            messages.append(f"{name}: new vulnerabilities since baseline: {', '.join(sorted(new_vulns))}")
    for name in baseline.entries:
        if name not in snapshot.entries:
            messages.append(f"{name}: removed since baseline")
    return messages
