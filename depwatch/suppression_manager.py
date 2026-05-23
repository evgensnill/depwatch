"""High-level helpers for managing the suppression list."""
from __future__ import annotations

from pathlib import Path
from typing import List

from depwatch.suppression import (
    SuppressionEntry,
    SuppressionList,
    load_suppression_list,
    save_suppression_list,
)

DEFAULT_PATH = Path(".depwatch_suppressions.json")


def add_suppression(
    vuln_id: str,
    package: str,
    reason: str = "",
    expires: str | None = None,
    path: Path = DEFAULT_PATH,
) -> SuppressionList:
    """Add a new suppression entry and persist the list."""
    sl = load_suppression_list(path)
    # Avoid duplicates
    if not sl.is_suppressed(vuln_id, package):
        sl.entries.append(
            SuppressionEntry(vuln_id=vuln_id, package=package, reason=reason, expires=expires)
        )
        save_suppression_list(sl, path)
    return sl


def remove_suppression(
    vuln_id: str,
    package: str,
    path: Path = DEFAULT_PATH,
) -> SuppressionList:
    """Remove a suppression entry and persist the updated list."""
    sl = load_suppression_list(path)
    sl.entries = [
        e for e in sl.entries
        if not (e.vuln_id == vuln_id and e.package == package)
    ]
    save_suppression_list(sl, path)
    return sl


def list_suppressions(path: Path = DEFAULT_PATH) -> List[SuppressionEntry]:
    """Return all current suppression entries."""
    return load_suppression_list(path).entries


def suppression_summary(path: Path = DEFAULT_PATH) -> str:
    """Return a human-readable summary of active suppressions."""
    entries = list_suppressions(path)
    if not entries:
        return "No active suppressions."
    lines = [f"Active suppressions ({len(entries)}):\n"]
    for e in entries:
        expiry = f"  expires: {e.expires}" if e.expires else ""
        lines.append(f"  [{e.vuln_id}] {e.package} — {e.reason or 'no reason given'}{expiry}")
    return "\n".join(lines)
