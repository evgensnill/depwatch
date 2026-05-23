"""Tests for depwatch.history."""

import json
import os
import pytest

from depwatch.history import (
    ScanRecord,
    ScanHistory,
    make_scan_record,
    load_history,
    save_history,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(**kwargs) -> ScanRecord:
    defaults = dict(
        timestamp="2024-01-01T00:00:00+00:00",
        total_packages=10,
        outdated_count=2,
        vulnerable_count=1,
        notes="",
    )
    defaults.update(kwargs)
    return ScanRecord(**defaults)


# ---------------------------------------------------------------------------
# ScanRecord
# ---------------------------------------------------------------------------

class TestScanRecord:
    def test_to_dict_roundtrip(self):
        rec = _make_record(notes="initial")
        assert ScanRecord.from_dict(rec.to_dict()) == rec

    def test_from_dict_missing_notes_defaults_empty(self):
        data = {
            "timestamp": "2024-01-01T00:00:00+00:00",
            "total_packages": 5,
            "outdated_count": 0,
            "vulnerable_count": 0,
        }
        rec = ScanRecord.from_dict(data)
        assert rec.notes == ""


# ---------------------------------------------------------------------------
# ScanHistory
# ---------------------------------------------------------------------------

class TestScanHistory:
    def test_latest_returns_none_when_empty(self):
        assert ScanHistory().latest() is None

    def test_latest_returns_last_added(self):
        h = ScanHistory()
        r1 = _make_record(timestamp="2024-01-01T00:00:00+00:00")
        r2 = _make_record(timestamp="2024-06-01T00:00:00+00:00")
        h.add(r1)
        h.add(r2)
        assert h.latest() == r2

    def test_to_dict_roundtrip(self):
        h = ScanHistory(records=[_make_record(), _make_record(outdated_count=0)])
        restored = ScanHistory.from_dict(h.to_dict())
        assert restored.records == h.records

    def test_from_dict_empty_records(self):
        h = ScanHistory.from_dict({})
        assert h.records == []


# ---------------------------------------------------------------------------
# make_scan_record
# ---------------------------------------------------------------------------

def test_make_scan_record_has_timestamp():
    rec = make_scan_record(total_packages=3, outdated_count=1, vulnerable_count=0)
    assert rec.timestamp  # non-empty string
    assert rec.total_packages == 3


# ---------------------------------------------------------------------------
# load_history / save_history
# ---------------------------------------------------------------------------

def test_load_history_returns_empty_when_file_missing(tmp_path):
    h = load_history(str(tmp_path / "nonexistent.json"))
    assert h.records == []


def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "history.json")
    h = ScanHistory(records=[_make_record(), _make_record(vulnerable_count=3)])
    save_history(h, path)
    loaded = load_history(path)
    assert loaded.records == h.records


def test_save_creates_parent_dirs(tmp_path):
    path = str(tmp_path / "sub" / "dir" / "history.json")
    save_history(ScanHistory(), path)
    assert os.path.exists(path)
