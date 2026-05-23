"""Tests for depwatch.baseline."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from depwatch.baseline import (
    Baseline,
    deviations_from_baseline,
    load_baseline,
    save_baseline,
)
from depwatch.snapshot import Snapshot, SnapshotEntry
from depwatch.vulnerability import Vulnerability


def _make_entry(version: str = "1.0.0", vulns=None) -> SnapshotEntry:
    return SnapshotEntry(
        installed_version=version,
        latest_version=version,
        vulnerabilities=vulns or [],
    )


def _make_snapshot(packages: dict) -> Snapshot:
    return Snapshot(entries=packages)


class TestBaseline:
    def test_from_snapshot_copies_entries(self):
        snap = _make_snapshot({"requests": _make_entry("2.28.0")})
        bl = Baseline.from_snapshot(snap, notes="initial")
        assert "requests" in bl.entries
        assert bl.notes == "initial"

    def test_to_dict_roundtrip(self):
        snap = _make_snapshot({"flask": _make_entry("2.3.0")})
        bl = Baseline.from_snapshot(snap)
        restored = Baseline.from_dict(bl.to_dict())
        assert "flask" in restored.entries
        assert restored.entries["flask"].installed_version == "2.3.0"

    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "baseline.json")
        snap = _make_snapshot({"numpy": _make_entry("1.24.0")})
        bl = Baseline.from_snapshot(snap, notes="test")
        save_baseline(bl, path)
        assert os.path.exists(path)
        loaded = load_baseline(path)
        assert "numpy" in loaded.entries
        assert loaded.notes == "test"

    def test_load_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_baseline(str(tmp_path / "nonexistent.json"))


class TestDeviationsFromBaseline:
    def test_no_deviations_when_identical(self):
        entry = _make_entry("1.0.0")
        snap = _make_snapshot({"pkg": entry})
        bl = Baseline.from_snapshot(snap)
        assert deviations_from_baseline(bl, snap) == []

    def test_detects_version_change(self):
        bl_snap = _make_snapshot({"pkg": _make_entry("1.0.0")})
        new_snap = _make_snapshot({"pkg": _make_entry("2.0.0")})
        bl = Baseline.from_snapshot(bl_snap)
        devs = deviations_from_baseline(bl, new_snap)
        assert any("1.0.0" in d and "2.0.0" in d for d in devs)

    def test_detects_new_package(self):
        bl_snap = _make_snapshot({})
        new_snap = _make_snapshot({"newpkg": _make_entry("0.1.0")})
        bl = Baseline.from_snapshot(bl_snap)
        devs = deviations_from_baseline(bl, new_snap)
        assert any("newpkg" in d for d in devs)

    def test_detects_removed_package(self):
        bl_snap = _make_snapshot({"oldpkg": _make_entry("1.0.0")})
        new_snap = _make_snapshot({})
        bl = Baseline.from_snapshot(bl_snap)
        devs = deviations_from_baseline(bl, new_snap)
        assert any("oldpkg" in d and "removed" in d for d in devs)

    def test_detects_new_vulnerability(self):
        vuln = Vulnerability(vuln_id="CVE-2024-0001", summary="bad", severity="HIGH")
        bl_snap = _make_snapshot({"pkg": _make_entry("1.0.0", vulns=[])})
        new_snap = _make_snapshot({"pkg": _make_entry("1.0.0", vulns=[vuln])})
        bl = Baseline.from_snapshot(bl_snap)
        devs = deviations_from_baseline(bl, new_snap)
        assert any("CVE-2024-0001" in d for d in devs)
