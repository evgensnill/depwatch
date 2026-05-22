"""Generate human-readable diff reports between two dependency snapshots."""

from typing import List

from depwatch.diff import PackageDiff, diff_snapshots
from depwatch.snapshot import Snapshot


def _section(title: str, items: List[str]) -> str:
    """Format a titled section of lines."""
    if not items:
        return ""
    lines = [f"  {item}" for item in items]
    return f"{title}:\n" + "\n".join(lines)


def format_diff_report(diffs: List[PackageDiff]) -> str:
    """Render a list of PackageDiff objects as a plain-text report."""
    if not diffs:
        return "No changes detected between snapshots."

    added = [str(d) for d in diffs if d.change_type == "added"]
    removed = [str(d) for d in diffs if d.change_type == "removed"]
    upgraded = [str(d) for d in diffs if d.change_type == "upgraded"]
    downgraded = [str(d) for d in diffs if d.change_type == "downgraded"]

    new_vulns = [
        f"{d.name}: {', '.join(d.new_vulns)}"
        for d in diffs
        if d.new_vulns
    ]
    resolved_vulns = [
        f"{d.name}: {', '.join(d.resolved_vulns)}"
        for d in diffs
        if d.resolved_vulns
    ]

    sections = filter(
        None,
        [
            _section("Added", added),
            _section("Removed", removed),
            _section("Upgraded", upgraded),
            _section("Downgraded", downgraded),
            _section("New vulnerabilities", new_vulns),
            _section("Resolved vulnerabilities", resolved_vulns),
        ],
    )

    header = f"Snapshot diff ({len(diffs)} change(s))"
    separator = "-" * len(header)
    return "\n\n".join([f"{header}\n{separator}", *sections])


def report_snapshot_diff(old: Snapshot, new: Snapshot) -> str:
    """Convenience wrapper: diff two snapshots and return a formatted report."""
    diffs = diff_snapshots(old, new)
    return format_diff_report(diffs)
