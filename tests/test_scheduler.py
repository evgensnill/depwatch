"""Tests for depwatch.scheduler."""

import threading
import time
import pytest

from depwatch.scheduler import DependencyScheduler, SchedulerConfig


def _make_counter_callback():
    calls = []

    def callback():
        calls.append(1)

    return callback, calls


class TestSchedulerConfig:
    def test_defaults(self):
        cfg = SchedulerConfig()
        assert cfg.interval_seconds == 3600
        assert cfg.run_on_start is True
        assert cfg.max_runs is None

    def test_custom_values(self):
        cfg = SchedulerConfig(interval_seconds=60, run_on_start=False, max_runs=5)
        assert cfg.interval_seconds == 60
        assert cfg.run_on_start is False
        assert cfg.max_runs == 5


class TestDependencyScheduler:
    def test_is_not_running_before_start(self):
        cb, _ = _make_counter_callback()
        scheduler = DependencyScheduler(cb)
        assert not scheduler.is_running

    def test_run_count_zero_initially(self):
        cb, _ = _make_counter_callback()
        scheduler = DependencyScheduler(cb)
        assert scheduler.run_count == 0

    def test_run_on_start_executes_callback(self):
        cb, calls = _make_counter_callback()
        cfg = SchedulerConfig(interval_seconds=60, run_on_start=True, max_runs=1)
        scheduler = DependencyScheduler(cb, config=cfg)
        scheduler.start()
        time.sleep(0.1)
        scheduler.stop()
        assert len(calls) >= 1

    def test_run_on_start_false_skips_immediate_call(self):
        cb, calls = _make_counter_callback()
        cfg = SchedulerConfig(interval_seconds=60, run_on_start=False)
        scheduler = DependencyScheduler(cb, config=cfg)
        scheduler.start()
        time.sleep(0.05)
        scheduler.stop()
        assert len(calls) == 0

    def test_is_running_after_start(self):
        cb, _ = _make_counter_callback()
        cfg = SchedulerConfig(interval_seconds=60, run_on_start=False)
        scheduler = DependencyScheduler(cb, config=cfg)
        scheduler.start()
        assert scheduler.is_running
        scheduler.stop()

    def test_is_not_running_after_stop(self):
        cb, _ = _make_counter_callback()
        cfg = SchedulerConfig(interval_seconds=60, run_on_start=False)
        scheduler = DependencyScheduler(cb, config=cfg)
        scheduler.start()
        scheduler.stop()
        assert not scheduler.is_running

    def test_raises_if_started_twice(self):
        cb, _ = _make_counter_callback()
        cfg = SchedulerConfig(interval_seconds=60, run_on_start=False)
        scheduler = DependencyScheduler(cb, config=cfg)
        scheduler.start()
        try:
            with pytest.raises(RuntimeError, match="already running"):
                scheduler.start()
        finally:
            scheduler.stop()

    def test_callback_exception_does_not_crash_scheduler(self):
        def bad_callback():
            raise ValueError("boom")

        cfg = SchedulerConfig(interval_seconds=60, run_on_start=True)
        scheduler = DependencyScheduler(bad_callback, config=cfg)
        scheduler.start()
        time.sleep(0.1)
        scheduler.stop()
        # Scheduler thread should have exited cleanly
        assert not scheduler.is_running
