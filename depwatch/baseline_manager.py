"""High-level helpers that tie baseline operations to the rest of depwatch."""
from __future__ import annotations

from typing import List

from depwatch.baseline import (
    Baseline,
    deviations_from_baseline,
    load_baseline,
    save_baseline,
)
from depwatch.snapshot import Snapshot
from depwatch.snapshot_manager import build_snapshot

_DEFAULT_PATH = ".depwatch/baseline.json"


def pin_current_state(path: str = _DEFAULT_PATH, notes: str = "") -> Baseline:
    """Build a fresh snapshot from installed packages and save it as the baseline."""
    snapshot = build_snapshot()
    baseline = Baseline.from_snapshot(snapshot, notes=notes)
    save_baseline(baseline, path)
    return baseline


def check_against_baseline(
    path: str = _DEFAULT_PATH,
) -> List[str]:
    """Load the saved baseline and compare it with the current environment.

    Returns a (possibly empty) list of deviation strings.
    Raises FileNotFoundError if no baseline has been pinned yet.
    """
    baseline = load_baseline(path)
    snapshot = build_snapshot()
    return deviations_from_baseline(baseline, snapshot)


def baseline_summary(path: str = _DEFAULT_PATH) -> str:
    """Return a short human-readable summary of the saved baseline."""
    baseline = load_baseline(path)
    total = len(baseline.entries)
    vulnerable = sum(
        1 for e in baseline.entries.values() if e.vulnerabilities
    )
    lines = [
        f"Baseline packages : {total}",
        f"Vulnerable at pin : {vulnerable}",
    ]
    if baseline.notes:
        lines.append(f"Notes             : {baseline.notes}")
    return "\n".join(lines)
