"""Tests for depwatch.diff module."""

import pytest

from depwatch.diff import PackageDiff, diff_snapshots
from depwatch.snapshot import Snapshot, SnapshotEntry


def _make_snapshot(entries):
    """Helper: build a Snapshot from a list of (name, version, vuln_ids) tuples."""
    return Snapshot(
        entries=[
            SnapshotEntry(name=n, version=v, vuln_ids=list(ids))
            for n, v, ids in entries
        ]
    )


class TestPackageDiff:
    def test_str_added(self):
        d = PackageDiff(name="requests", change_type="added", new_version="2.28.0")
        assert "[+]" in str(d)
        assert "requests" in str(d)
        assert "added" in str(d)

    def test_str_removed(self):
        d = PackageDiff(name="flask", change_type="removed", old_version="1.0.0")
        assert "[-]" in str(d)
        assert "removed" in str(d)

    def test_str_upgraded(self):
        d = PackageDiff(
            name="numpy",
            change_type="upgraded",
            old_version="1.23.0",
            new_version="1.24.0",
        )
        result = str(d)
        assert "[~]" in result
        assert "->" in result
        assert "upgraded" in result


class TestDiffSnapshots:
    def test_added_package(self):
        old = _make_snapshot([])
        new = _make_snapshot([("requests", "2.28.0", [])])
        diffs = diff_snapshots(old, new)
        assert len(diffs) == 1
        assert diffs[0].change_type == "added"
        assert diffs[0].name == "requests"

    def test_removed_package(self):
        old = _make_snapshot([("flask", "2.0.0", [])])
        new = _make_snapshot([])
        diffs = diff_snapshots(old, new)
        assert len(diffs) == 1
        assert diffs[0].change_type == "removed"
        assert diffs[0].old_version == "2.0.0"

    def test_upgraded_package(self):
        old = _make_snapshot([("numpy", "1.23.0", [])])
        new = _make_snapshot([("numpy", "1.24.0", [])])
        diffs = diff_snapshots(old, new)
        assert len(diffs) == 1
        assert diffs[0].change_type == "upgraded"

    def test_downgraded_package(self):
        old = _make_snapshot([("numpy", "1.24.0", [])])
        new = _make_snapshot([("numpy", "1.23.0", [])])
        diffs = diff_snapshots(old, new)
        assert len(diffs) == 1
        assert diffs[0].change_type == "downgraded"

    def test_unchanged_package_excluded(self):
        old = _make_snapshot([("pip", "23.0", [])])
        new = _make_snapshot([("pip", "23.0", [])])
        diffs = diff_snapshots(old, new)
        assert diffs == []

    def test_new_vulnerability_detected(self):
        old = _make_snapshot([("django", "3.2.0", [])])
        new = _make_snapshot([("django", "3.2.0", ["GHSA-1234"])])
        diffs = diff_snapshots(old, new)
        assert len(diffs) == 1
        assert "GHSA-1234" in diffs[0].new_vulns

    def test_resolved_vulnerability_detected(self):
        old = _make_snapshot([("django", "3.2.0", ["GHSA-1234"])])
        new = _make_snapshot([("django", "3.2.1", [])])
        diffs = diff_snapshots(old, new)
        assert len(diffs) == 1
        assert "GHSA-1234" in diffs[0].resolved_vulns

    def test_multiple_packages(self):
        old = _make_snapshot([("a", "1.0", []), ("b", "2.0", [])])
        new = _make_snapshot([("a", "1.1", []), ("c", "3.0", [])])
        diffs = diff_snapshots(old, new)
        names = {d.name for d in diffs}
        assert names == {"a", "b", "c"}
