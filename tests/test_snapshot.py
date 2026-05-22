"""Tests for depwatch.snapshot module."""

import json
import os
import tempfile

import pytest

from depwatch.snapshot import (
    Snapshot,
    SnapshotEntry,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)


def _make_entry(name="requests", installed="2.28.0", latest="2.31.0", vulns=None):
    return SnapshotEntry(
        name=name,
        installed_version=installed,
        latest_version=latest,
        vulnerabilities=vulns or [],
    )


class TestSnapshotEntry:
    def test_defaults_empty_vulns(self):
        entry = SnapshotEntry(name="flask", installed_version="2.0.0", latest_version=None)
        assert entry.vulnerabilities == []


class TestSnapshot:
    def test_to_dict_roundtrip(self):
        entry = _make_entry()
        snap = Snapshot(packages={"requests": entry})
        d = snap.to_dict()
        restored = Snapshot.from_dict(d)
        assert restored.packages["requests"].installed_version == "2.28.0"
        assert restored.created_at == snap.created_at

    def test_from_dict_empty_packages(self):
        snap = Snapshot.from_dict({"created_at": "2024-01-01T00:00:00+00:00"})
        assert snap.packages == {}


class TestSaveLoadSnapshot:
    def test_save_creates_file(self, tmp_path):
        path = str(tmp_path / "snap.json")
        snap = Snapshot(packages={"pip": _make_entry(name="pip")})
        save_snapshot(snap, path)
        assert os.path.exists(path)

    def test_load_returns_none_when_missing(self, tmp_path):
        result = load_snapshot(str(tmp_path / "nonexistent.json"))
        assert result is None

    def test_save_and_load_roundtrip(self, tmp_path):
        path = str(tmp_path / "snap.json")
        entry = _make_entry(vulns=["CVE-2023-1234"])
        snap = Snapshot(packages={"requests": entry})
        save_snapshot(snap, path)
        loaded = load_snapshot(path)
        assert loaded is not None
        assert loaded.packages["requests"].vulnerabilities == ["CVE-2023-1234"]

    def test_saved_file_is_valid_json(self, tmp_path):
        path = str(tmp_path / "snap.json")
        save_snapshot(Snapshot(), path)
        with open(path) as fh:
            data = json.load(fh)
        assert "created_at" in data
        assert "packages" in data


class TestDiffSnapshots:
    def test_no_changes(self):
        entry = _make_entry()
        snap = Snapshot(packages={"requests": entry})
        assert diff_snapshots(snap, snap) == {}

    def test_detects_version_change(self):
        old_snap = Snapshot(packages={"requests": _make_entry(installed="2.28.0")})
        new_snap = Snapshot(packages={"requests": _make_entry(installed="2.31.0")})
        diff = diff_snapshots(old_snap, new_snap)
        assert "requests" in diff
        assert diff["requests"]["old"]["installed_version"] == "2.28.0"
        assert diff["requests"]["new"]["installed_version"] == "2.31.0"

    def test_detects_new_package(self):
        old_snap = Snapshot(packages={})
        new_snap = Snapshot(packages={"flask": _make_entry(name="flask")})
        diff = diff_snapshots(old_snap, new_snap)
        assert "flask" in diff
        assert diff["flask"]["old"] is None

    def test_detects_removed_package(self):
        old_snap = Snapshot(packages={"flask": _make_entry(name="flask")})
        new_snap = Snapshot(packages={})
        diff = diff_snapshots(old_snap, new_snap)
        assert "flask" in diff
        assert diff["flask"]["new"] is None
