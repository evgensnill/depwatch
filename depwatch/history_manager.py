"""High-level helpers that integrate scan results with ScanHistory."""

from __future__ import annotations

from typing import List

from depwatch.history import (
    ScanHistory,
    ScanRecord,
    make_scan_record,
    load_history,
    save_history,
)
from depwatch.reporter import PackageReport


DEFAULT_HISTORY_PATH = ".depwatch_history.json"


def record_from_reports(reports: List[PackageReport], notes: str = "") -> ScanRecord:
    """Build a ScanRecord from a list of PackageReport objects."""
    total = len(reports)
    outdated = sum(1 for r in reports if r.needs_attention() and not r.is_vulnerable())
    vulnerable = sum(1 for r in reports if r.is_vulnerable())
    return make_scan_record(
        total_packages=total,
        outdated_count=outdated,
        vulnerable_count=vulnerable,
        notes=notes,
    )


def append_scan(
    reports: List[PackageReport],
    path: str = DEFAULT_HISTORY_PATH,
    notes: str = "",
) -> ScanRecord:
    """Load history, append a new record derived from *reports*, and save.

    Returns the newly created ScanRecord.
    """
    history = load_history(path)
    record = record_from_reports(reports, notes=notes)
    history.add(record)
    save_history(history, path)
    return record


def summarise_history(history: ScanHistory) -> str:
    """Return a human-readable summary of the scan history."""
    if not history.records:
        return "No scan history available."

    lines = [f"Scan history ({len(history.records)} record(s)):\n"]
    for rec in history.records:
        status = []
        if rec.outdated_count:
            status.append(f"{rec.outdated_count} outdated")
        if rec.vulnerable_count:
            status.append(f"{rec.vulnerable_count} vulnerable")
        status_str = ", ".join(status) if status else "all up-to-date"
        note = f" [{rec.notes}]" if rec.notes else ""
        lines.append(
            f"  {rec.timestamp}  packages={rec.total_packages}  {status_str}{note}"
        )
    return "\n".join(lines)
