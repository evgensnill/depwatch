"""Tests for depwatch.history_manager."""

import pytest

from depwatch.history import ScanHistory, ScanRecord
from depwatch.history_manager import (
    record_from_reports,
    append_scan,
    summarise_history,
)
from depwatch.reporter import PackageReport
from depwatch.checker import PackageStatus
from depwatch.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(name="pkg", installed="1.0", latest="1.0", vulns=None):
    status = PackageStatus(name=name, installed_version=installed, latest_version=latest)
    return PackageReport(status=status, vulnerabilities=vulns or [])


def _vuln():
    return Vulnerability(vuln_id="GHSA-0000", summary="test", severity="HIGH", aliases=[])


# ---------------------------------------------------------------------------
# record_from_reports
# ---------------------------------------------------------------------------

class TestRecordFromReports:
    def test_empty_list(self):
        rec = record_from_reports([])
        assert rec.total_packages == 0
        assert rec.outdated_count == 0
        assert rec.vulnerable_count == 0

    def test_counts_outdated(self):
        reports = [
            _pkg(installed="1.0", latest="2.0"),
            _pkg(installed="1.0", latest="1.0"),
        ]
        rec = record_from_reports(reports)
        assert rec.total_packages == 2
        assert rec.outdated_count == 1
        assert rec.vulnerable_count == 0

    def test_counts_vulnerable(self):
        reports = [_pkg(vulns=[_vuln()])]
        rec = record_from_reports(reports)
        assert rec.vulnerable_count == 1
        assert rec.outdated_count == 0

    def test_notes_stored(self):
        rec = record_from_reports([], notes="ci run")
        assert rec.notes == "ci run"


# ---------------------------------------------------------------------------
# append_scan
# ---------------------------------------------------------------------------

def test_append_scan_creates_file_and_returns_record(tmp_path):
    path = str(tmp_path / "hist.json")
    reports = [_pkg(installed="1.0", latest="2.0")]
    rec = append_scan(reports, path=path)
    assert isinstance(rec, ScanRecord)
    assert rec.outdated_count == 1


def test_append_scan_accumulates_records(tmp_path):
    path = str(tmp_path / "hist.json")
    append_scan([_pkg()], path=path)
    append_scan([_pkg(), _pkg()], path=path)
    from depwatch.history import load_history
    h = load_history(path)
    assert len(h.records) == 2


# ---------------------------------------------------------------------------
# summarise_history
# ---------------------------------------------------------------------------

class TestSummariseHistory:
    def test_empty_history(self):
        msg = summarise_history(ScanHistory())
        assert "No scan history" in msg

    def test_shows_record_count(self):
        h = ScanHistory(records=[
            ScanRecord(
                timestamp="2024-01-01T00:00:00+00:00",
                total_packages=5,
                outdated_count=1,
                vulnerable_count=0,
            )
        ])
        msg = summarise_history(h)
        assert "1 record" in msg
        assert "1 outdated" in msg

    def test_all_up_to_date_label(self):
        h = ScanHistory(records=[
            ScanRecord(
                timestamp="2024-01-01T00:00:00+00:00",
                total_packages=3,
                outdated_count=0,
                vulnerable_count=0,
            )
        ])
        msg = summarise_history(h)
        assert "all up-to-date" in msg

    def test_notes_shown(self):
        h = ScanHistory(records=[
            ScanRecord(
                timestamp="2024-01-01T00:00:00+00:00",
                total_packages=1,
                outdated_count=0,
                vulnerable_count=0,
                notes="nightly",
            )
        ])
        msg = summarise_history(h)
        assert "nightly" in msg
