"""Tests for depwatch.baseline_manager."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from depwatch.baseline import Baseline
from depwatch.baseline_manager import (
    baseline_summary,
    check_against_baseline,
    pin_current_state,
)
from depwatch.snapshot import Snapshot, SnapshotEntry
from depwatch.vulnerability import Vulnerability


def _make_entry(version="1.0.0", vulns=None):
    return SnapshotEntry(
        installed_version=version,
        latest_version=version,
        vulnerabilities=vulns or [],
    )


def _make_snapshot(packages: dict) -> Snapshot:
    return Snapshot(entries=packages)


class TestPinCurrentState:
    def test_saves_and_returns_baseline(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        snap = _make_snapshot({"requests": _make_entry("2.28.0")})
        with patch("depwatch.baseline_manager.build_snapshot", return_value=snap):
            bl = pin_current_state(path=path, notes="pinned")
        assert isinstance(bl, Baseline)
        assert "requests" in bl.entries
        assert bl.notes == "pinned"

    def test_file_is_created(self, tmp_path):
        import os
        path = str(tmp_path / "sub" / "baseline.json")
        snap = _make_snapshot({"flask": _make_entry("2.0.0")})
        with patch("depwatch.baseline_manager.build_snapshot", return_value=snap):
            pin_current_state(path=path)
        assert os.path.exists(path)


class TestCheckAgainstBaseline:
    def test_no_deviations_when_unchanged(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        snap = _make_snapshot({"pkg": _make_entry("1.0.0")})
        with patch("depwatch.baseline_manager.build_snapshot", return_value=snap):
            pin_current_state(path=path)
            result = check_against_baseline(path=path)
        assert result == []

    def test_returns_deviations_on_change(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        old_snap = _make_snapshot({"pkg": _make_entry("1.0.0")})
        new_snap = _make_snapshot({"pkg": _make_entry("2.0.0")})
        with patch("depwatch.baseline_manager.build_snapshot", return_value=old_snap):
            pin_current_state(path=path)
        with patch("depwatch.baseline_manager.build_snapshot", return_value=new_snap):
            result = check_against_baseline(path=path)
        assert any("pkg" in d for d in result)

    def test_raises_when_no_baseline(self, tmp_path):
        path = str(tmp_path / "missing.json")
        snap = _make_snapshot({})
        with patch("depwatch.baseline_manager.build_snapshot", return_value=snap):
            with pytest.raises(FileNotFoundError):
                check_against_baseline(path=path)


class TestBaselineSummary:
    def test_summary_contains_counts(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        vuln = Vulnerability(vuln_id="CVE-1", summary="x", severity=None)
        snap = _make_snapshot({
            "safe": _make_entry("1.0.0"),
            "risky": _make_entry("0.9.0", vulns=[vuln]),
        })
        with patch("depwatch.baseline_manager.build_snapshot", return_value=snap):
            pin_current_state(path=path, notes="ci run")
        summary = baseline_summary(path=path)
        assert "2" in summary
        assert "1" in summary
        assert "ci run" in summary
