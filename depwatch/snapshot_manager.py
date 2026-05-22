"""High-level manager that ties the checker and snapshot modules together."""

from __future__ import annotations

from typing import Dict, List, Optional

from depwatch.checker import PackageStatus
from depwatch.snapshot import (
    Snapshot,
    SnapshotEntry,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)


DEFAULT_SNAPSHOT_PATH = ".depwatch_snapshot.json"


def build_snapshot(statuses: List[PackageStatus]) -> Snapshot:
    """Convert a list of PackageStatus objects into a Snapshot."""
    packages: Dict[str, SnapshotEntry] = {}
    for status in statuses:
        vuln_ids = [v.vuln_id for v in status.vulnerabilities]
        packages[status.name] = SnapshotEntry(
            name=status.name,
            installed_version=status.installed_version,
            latest_version=status.latest_version,
            vulnerabilities=vuln_ids,
        )
    return Snapshot(packages=packages)


def update_snapshot(
    statuses: List[PackageStatus],
    path: str = DEFAULT_SNAPSHOT_PATH,
) -> Dict[str, dict]:
    """Build a new snapshot, diff it against the previous one, persist it.

    Returns a dict of changed packages (empty dict if first run or no changes).
    """
    new_snapshot = build_snapshot(statuses)
    old_snapshot = load_snapshot(path)

    changes: Dict[str, dict] = {}
    if old_snapshot is not None:
        changes = diff_snapshots(old_snapshot, new_snapshot)

    save_snapshot(new_snapshot, path)
    return changes


def summarise_changes(changes: Dict[str, dict]) -> str:
    """Return a human-readable summary of snapshot changes."""
    if not changes:
        return "No changes detected since last snapshot."

    lines = [f"{len(changes)} package(s) changed since last snapshot:"]
    for pkg, diff in changes.items():
        old_ver = (diff["old"] or {}).get("installed_version", "N/A")
        new_ver = (diff["new"] or {}).get("installed_version", "N/A")
        if diff["old"] is None:
            lines.append(f"  + {pkg} added at {new_ver}")
        elif diff["new"] is None:
            lines.append(f"  - {pkg} removed (was {old_ver})")
        else:
            lines.append(f"  ~ {pkg}: {old_ver} -> {new_ver}")
    return "\n".join(lines)
