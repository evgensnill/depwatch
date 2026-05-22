"""Tests for depwatch.reporter module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from depwatch.checker import PackageStatus
from depwatch.reporter import PackageReport, Report, build_report
from depwatch.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pkg_report(
    name: str = "pkg",
    installed: str = "1.0.0",
    latest: str = "1.0.0",
    outdated: bool = False,
    vulns=None,
) -> PackageReport:
    return PackageReport(
        name=name,
        installed_version=installed,
        latest_version=latest,
        is_outdated=outdated,
        vulnerabilities=vulns or [],
    )


# ---------------------------------------------------------------------------
# PackageReport
# ---------------------------------------------------------------------------

class TestPackageReport:
    def test_is_vulnerable_false_when_no_vulns(self):
        pr = _make_pkg_report()
        assert pr.is_vulnerable is False

    def test_is_vulnerable_true_when_vulns_present(self):
        v = Vulnerability(vuln_id="CVE-1", summary="issue")
        pr = _make_pkg_report(vulns=[v])
        assert pr.is_vulnerable is True

    def test_needs_attention_when_outdated(self):
        pr = _make_pkg_report(outdated=True)
        assert pr.needs_attention is True

    def test_needs_attention_false_when_all_good(self):
        pr = _make_pkg_report()
        assert pr.needs_attention is False


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class TestReport:
    def test_outdated_filters_correctly(self):
        r = Report(packages=[
            _make_pkg_report(name="a", outdated=True),
            _make_pkg_report(name="b", outdated=False),
        ])
        assert len(r.outdated) == 1
        assert r.outdated[0].name == "a"

    def test_vulnerable_filters_correctly(self):
        v = Vulnerability(vuln_id="CVE-2", summary="x")
        r = Report(packages=[
            _make_pkg_report(name="c", vulns=[v]),
            _make_pkg_report(name="d"),
        ])
        assert len(r.vulnerable) == 1
        assert r.vulnerable[0].name == "c"

    def test_has_issues_false_when_clean(self):
        r = Report(packages=[_make_pkg_report()])
        assert r.has_issues is False

    def test_summary_contains_counts(self):
        r = Report(packages=[
            _make_pkg_report(name="e", outdated=True),
            _make_pkg_report(name="f"),
        ])
        s = r.summary()
        assert "2" in s
        assert "1" in s


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------

class TestBuildReport:
    @patch("depwatch.reporter.scan_packages", return_value={})
    @patch("depwatch.reporter.check_packages")
    def test_uses_provided_packages(self, mock_check, mock_scan):
        mock_check.return_value = [
            PackageStatus(name="mylib", installed_version="1.0", latest_version="1.0", is_outdated=False, is_vulnerable=False)
        ]
        report = build_report({"mylib": "1.0"})
        assert len(report.packages) == 1
        assert report.packages[0].name == "mylib"

    @patch("depwatch.reporter.scan_packages", return_value={})
    @patch("depwatch.reporter.check_packages", return_value=[])
    @patch("depwatch.reporter.get_installed_packages", return_value={"auto-pkg": "2.0"})
    def test_falls_back_to_installed_packages(self, mock_installed, mock_check, mock_scan):
        report = build_report()
        mock_installed.assert_called_once()
        assert len(report.packages) == 1
