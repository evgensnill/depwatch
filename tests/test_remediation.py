"""Tests for depwatch.remediation."""

import pytest

from depwatch.checker import PackageStatus
from depwatch.reporter import PackageReport
from depwatch.vulnerability import Vulnerability
from depwatch.remediation import (
    RemediationSuggestion,
    build_suggestion,
    generate_remediations,
)


def _make_status(name="requests", installed="2.0.0", latest="2.28.0"):
    return PackageStatus(name=name, installed_version=installed, latest_version=latest)


def _make_vuln(vuln_id="GHSA-1234", severity="HIGH"):
    return Vulnerability(vuln_id=vuln_id, summary="A vuln", severity=severity)


def _make_report(name="requests", installed="2.0.0", latest="2.28.0", vulns=None):
    status = _make_status(name=name, installed=installed, latest=latest)
    return PackageReport(status=status, vulnerabilities=vulns or [])


class TestBuildSuggestion:
    def test_returns_none_when_no_attention_needed(self):
        report = _make_report(installed="2.28.0", latest="2.28.0", vulns=[])
        assert build_suggestion(report) is None

    def test_returns_suggestion_for_outdated_package(self):
        report = _make_report(installed="2.0.0", latest="2.28.0")
        suggestion = build_suggestion(report)
        assert suggestion is not None
        assert suggestion.package == "requests"
        assert suggestion.current_version == "2.0.0"
        assert suggestion.suggested_version == "2.28.0"

    def test_outdated_reason_included(self):
        report = _make_report(installed="2.0.0", latest="2.28.0")
        suggestion = build_suggestion(report)
        assert any("outdated" in r for r in suggestion.reasons)

    def test_returns_suggestion_for_vulnerable_package(self):
        vuln = _make_vuln()
        report = _make_report(installed="2.0.0", latest="2.0.0", vulns=[vuln])
        suggestion = build_suggestion(report)
        assert suggestion is not None
        assert any("vulnerabilities" in r for r in suggestion.reasons)

    def test_vuln_ids_included_in_reasons(self):
        vuln = _make_vuln(vuln_id="GHSA-ABCD")
        report = _make_report(installed="1.0.0", latest="1.0.0", vulns=[vuln])
        suggestion = build_suggestion(report)
        assert any("GHSA-ABCD" in r for r in suggestion.reasons)

    def test_command_uses_latest_version(self):
        report = _make_report(installed="2.0.0", latest="2.28.0")
        suggestion = build_suggestion(report)
        assert any("2.28.0" in cmd for cmd in suggestion.commands)

    def test_command_uses_pip_install(self):
        report = _make_report(installed="2.0.0", latest="2.28.0")
        suggestion = build_suggestion(report)
        assert any(cmd.startswith("pip install") for cmd in suggestion.commands)


class TestGenerateRemediations:
    def test_empty_list_returns_empty(self):
        assert generate_remediations([]) == []

    def test_filters_out_ok_packages(self):
        ok = _make_report(installed="2.28.0", latest="2.28.0", vulns=[])
        result = generate_remediations([ok])
        assert result == []

    def test_includes_outdated_packages(self):
        outdated = _make_report(installed="1.0.0", latest="2.0.0")
        result = generate_remediations([outdated])
        assert len(result) == 1
        assert result[0].package == "requests"

    def test_multiple_packages_mixed(self):
        ok = _make_report(name="flask", installed="2.0.0", latest="2.0.0", vulns=[])
        bad = _make_report(name="django", installed="3.0.0", latest="4.0.0")
        result = generate_remediations([ok, bad])
        assert len(result) == 1
        assert result[0].package == "django"


class TestRemediationSuggestionStr:
    def test_str_includes_package_name(self):
        s = RemediationSuggestion(
            package="requests",
            current_version="2.0.0",
            suggested_version="2.28.0",
            reasons=["outdated"],
            commands=["pip install requests==2.28.0"],
        )
        text = str(s)
        assert "requests" in text
        assert "2.0.0" in text
        assert "2.28.0" in text
        assert "pip install" in text
