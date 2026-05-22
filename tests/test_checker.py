"""Tests for depwatch.checker module."""

from unittest.mock import MagicMock, patch

import pytest

from depwatch.checker import (
    PackageStatus,
    check_packages,
    fetch_latest_version,
    get_installed_packages,
)


class TestGetInstalledPackages:
    def test_returns_dict(self):
        result = get_installed_packages()
        assert isinstance(result, dict)

    def test_values_are_strings(self):
        result = get_installed_packages()
        for name, version in result.items():
            assert isinstance(name, str)
            assert isinstance(version, str)


class TestFetchLatestVersion:
    def test_returns_version_string_on_success(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"info": {"version": "2.0.0"}}
        mock_response.raise_for_status.return_value = None

        with patch("depwatch.checker.requests.get", return_value=mock_response):
            result = fetch_latest_version("requests")

        assert result == "2.0.0"

    def test_returns_none_on_http_error(self):
        import requests as req

        with patch(
            "depwatch.checker.requests.get",
            side_effect=req.RequestException("network error"),
        ):
            result = fetch_latest_version("nonexistent-pkg")

        assert result is None


class TestCheckPackages:
    def test_outdated_package_flagged(self):
        packages = {"requests": "2.0.0"}

        with patch("depwatch.checker.fetch_latest_version", return_value="2.28.0"):
            results = check_packages(packages)

        assert len(results) == 1
        status = results[0]
        assert status.name == "requests"
        assert status.installed_version == "2.0.0"
        assert status.latest_version == "2.28.0"
        assert status.is_outdated is True
        assert status.error is None

    def test_up_to_date_package_not_flagged(self):
        packages = {"requests": "2.28.0"}

        with patch("depwatch.checker.fetch_latest_version", return_value="2.28.0"):
            results = check_packages(packages)

        assert results[0].is_outdated is False

    def test_pypi_error_sets_error_field(self):
        packages = {"ghost-pkg": "1.0.0"}

        with patch("depwatch.checker.fetch_latest_version", return_value=None):
            results = check_packages(packages)

        status = results[0]
        assert status.latest_version is None
        assert status.error is not None
        assert "ghost-pkg" in status.error

    def test_empty_input_returns_empty_list(self):
        assert check_packages({}) == []
