"""Diff utilities for comparing dependency snapshots over time."""

from dataclasses import dataclass, field
from typing import List, Optional

from depwatch.snapshot import Snapshot, SnapshotEntry


@dataclass
class PackageDiff:
    """Represents a change in a single package between two snapshots."""

    name: str
    change_type: str  # 'added', 'removed', 'upgraded', 'downgraded', 'unchanged'
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    new_vulns: List[str] = field(default_factory=list)
    resolved_vulns: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        if self.change_type == "added":
            return f"[+] {self.name} {self.new_version} (added)"
        if self.change_type == "removed":
            return f"[-] {self.name} {self.old_version} (removed)"
        direction = "upgraded" if self.change_type == "upgraded" else "downgraded"
        return f"[~] {self.name} {self.old_version} -> {self.new_version} ({direction})"


def diff_snapshots(old: Snapshot, new: Snapshot) -> List[PackageDiff]:
    """Compare two snapshots and return a list of PackageDiff entries."""
    diffs: List[PackageDiff] = []

    old_pkgs = {e.name: e for e in old.entries}
    new_pkgs = {e.name: e for e in new.entries}

    all_names = set(old_pkgs) | set(new_pkgs)

    for name in sorted(all_names):
        old_entry: Optional[SnapshotEntry] = old_pkgs.get(name)
        new_entry: Optional[SnapshotEntry] = new_pkgs.get(name)

        if old_entry is None and new_entry is not None:
            diffs.append(
                PackageDiff(
                    name=name,
                    change_type="added",
                    new_version=new_entry.version,
                    new_vulns=list(new_entry.vuln_ids),
                )
            )
        elif new_entry is None and old_entry is not None:
            diffs.append(
                PackageDiff(
                    name=name,
                    change_type="removed",
                    old_version=old_entry.version,
                )
            )
        else:
            assert old_entry is not None and new_entry is not None
            old_vulns = set(old_entry.vuln_ids)
            new_vulns_set = set(new_entry.vuln_ids)

            if old_entry.version == new_entry.version and old_vulns == new_vulns_set:
                continue

            from packaging.version import Version, InvalidVersion

            try:
                change_type = (
                    "upgraded"
                    if Version(new_entry.version) > Version(old_entry.version)
                    else "downgraded"
                    if Version(new_entry.version) < Version(old_entry.version)
                    else "unchanged"
                )
            except InvalidVersion:
                change_type = "unchanged"

            diffs.append(
                PackageDiff(
                    name=name,
                    change_type=change_type,
                    old_version=old_entry.version,
                    new_version=new_entry.version,
                    new_vulns=sorted(new_vulns_set - old_vulns),
                    resolved_vulns=sorted(old_vulns - new_vulns_set),
                )
            )

    return diffs
