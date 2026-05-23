"""Tests for depwatch.suppression."""
import json
import pytest
from pathlib import Path

from depwatch.suppression import (
    SuppressionEntry,
    SuppressionList,
    save_suppression_list,
    load_suppression_list,
    filter_suppressed,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry(vuln_id="GHSA-0001", package="requests", reason="accepted", expires=None):
    return SuppressionEntry(vuln_id=vuln_id, package=package, reason=reason, expires=expires)


def _make_pkg_report(name, installed="1.0.0", latest="1.0.0", vulns=None):
    from depwatch.reporter import PackageReport
    from depwatch.vulnerability import Vulnerability
    vuln_objs = [
        Vulnerability(vuln_id=v, title="", severity=None, fixed_versions=[])
        for v in (vulns or [])
    ]
    return PackageReport(
        name=name,
        installed_version=installed,
        latest_version=latest,
        vulnerabilities=vuln_objs,
    )


# ---------------------------------------------------------------------------
# SuppressionEntry
# ---------------------------------------------------------------------------

class TestSuppressionEntry:
    def test_to_dict_roundtrip(self):
        entry = _make_entry(expires="2025-12-31")
        restored = SuppressionEntry.from_dict(entry.to_dict())
        assert restored.vuln_id == entry.vuln_id
        assert restored.package == entry.package
        assert restored.reason == entry.reason
        assert restored.expires == entry.expires

    def test_from_dict_missing_optional_fields(self):
        data = {"vuln_id": "CVE-2024-001", "package": "flask"}
        entry = SuppressionEntry.from_dict(data)
        assert entry.reason == ""
        assert entry.expires is None


# ---------------------------------------------------------------------------
# SuppressionList
# ---------------------------------------------------------------------------

class TestSuppressionList:
    def test_is_suppressed_true(self):
        sl = SuppressionList(entries=[_make_entry()])
        assert sl.is_suppressed("GHSA-0001", "requests") is True

    def test_is_suppressed_false_wrong_package(self):
        sl = SuppressionList(entries=[_make_entry()])
        assert sl.is_suppressed("GHSA-0001", "flask") is False

    def test_is_suppressed_false_wrong_vuln(self):
        sl = SuppressionList(entries=[_make_entry()])
        assert sl.is_suppressed("GHSA-9999", "requests") is False

    def test_empty_list_never_suppressed(self):
        sl = SuppressionList()
        assert sl.is_suppressed("GHSA-0001", "requests") is False

    def test_to_dict_roundtrip(self):
        sl = SuppressionList(entries=[_make_entry(), _make_entry(vuln_id="CVE-2024-001", package="flask")])
        restored = SuppressionList.from_dict(sl.to_dict())
        assert len(restored.entries) == 2
        assert restored.entries[0].vuln_id == "GHSA-0001"


# ---------------------------------------------------------------------------
# save / load
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_save_and_load(self, tmp_path):
        path = tmp_path / "suppressions.json"
        sl = SuppressionList(entries=[_make_entry()])
        save_suppression_list(sl, path)
        loaded = load_suppression_list(path)
        assert len(loaded.entries) == 1
        assert loaded.entries[0].vuln_id == "GHSA-0001"

    def test_load_missing_file_returns_empty(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        sl = load_suppression_list(path)
        assert sl.entries == []


# ---------------------------------------------------------------------------
# filter_suppressed
# ---------------------------------------------------------------------------

class TestFilterSuppressed:
    def test_removes_suppressed_vuln(self):
        sl = SuppressionList(entries=[_make_entry(vuln_id="GHSA-0001", package="requests")])
        reports = [_make_pkg_report("requests", vulns=["GHSA-0001", "GHSA-0002"])]
        result = filter_suppressed(reports, sl)
        assert len(result[0].vulnerabilities) == 1
        assert result[0].vulnerabilities[0].vuln_id == "GHSA-0002"

    def test_keeps_all_when_no_suppressions(self):
        sl = SuppressionList()
        reports = [_make_pkg_report("requests", vulns=["GHSA-0001"])]
        result = filter_suppressed(reports, sl)
        assert len(result[0].vulnerabilities) == 1

    def test_empty_reports_returns_empty(self):
        sl = SuppressionList(entries=[_make_entry()])
        result = filter_suppressed([], sl)
        assert result == []
