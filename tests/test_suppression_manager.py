"""Tests for depwatch.suppression_manager."""
import pytest
from pathlib import Path

from depwatch.suppression_manager import (
    add_suppression,
    remove_suppression,
    list_suppressions,
    suppression_summary,
)
from depwatch.suppression import load_suppression_list


class TestAddSuppression:
    def test_creates_file_and_entry(self, tmp_path):
        path = tmp_path / "s.json"
        sl = add_suppression("GHSA-0001", "requests", reason="low risk", path=path)
        assert len(sl.entries) == 1
        assert path.exists()

    def test_does_not_duplicate_existing_entry(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        sl = add_suppression("GHSA-0001", "requests", path=path)
        assert len(sl.entries) == 1

    def test_adds_multiple_distinct_entries(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        sl = add_suppression("GHSA-0002", "flask", path=path)
        assert len(sl.entries) == 2

    def test_persists_to_disk(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        reloaded = load_suppression_list(path)
        assert reloaded.entries[0].vuln_id == "GHSA-0001"


class TestRemoveSuppression:
    def test_removes_existing_entry(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        sl = remove_suppression("GHSA-0001", "requests", path=path)
        assert len(sl.entries) == 0

    def test_noop_when_entry_not_present(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        sl = remove_suppression("GHSA-9999", "requests", path=path)
        assert len(sl.entries) == 1

    def test_only_removes_matching_entry(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        add_suppression("GHSA-0002", "flask", path=path)
        sl = remove_suppression("GHSA-0001", "requests", path=path)
        assert len(sl.entries) == 1
        assert sl.entries[0].vuln_id == "GHSA-0002"


class TestListSuppressions:
    def test_returns_empty_for_missing_file(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        assert list_suppressions(path) == []

    def test_returns_all_entries(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        add_suppression("GHSA-0002", "flask", path=path)
        entries = list_suppressions(path)
        assert len(entries) == 2


class TestSuppressionSummary:
    def test_empty_message_when_none(self, tmp_path):
        path = tmp_path / "s.json"
        summary = suppression_summary(path)
        assert "No active suppressions" in summary

    def test_summary_contains_vuln_id(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", reason="accepted risk", path=path)
        summary = suppression_summary(path)
        assert "GHSA-0001" in summary
        assert "requests" in summary
        assert "accepted risk" in summary

    def test_summary_shows_count(self, tmp_path):
        path = tmp_path / "s.json"
        add_suppression("GHSA-0001", "requests", path=path)
        add_suppression("GHSA-0002", "flask", path=path)
        summary = suppression_summary(path)
        assert "2" in summary
