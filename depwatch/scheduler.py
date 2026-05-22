"""Scheduler for periodic dependency checks."""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class SchedulerConfig:
    """Configuration for the dependency check scheduler."""

    interval_seconds: int = 3600  # default: 1 hour
    run_on_start: bool = True
    max_runs: Optional[int] = None  # None means run indefinitely


class DependencyScheduler:
    """Runs a dependency check callback on a fixed interval."""

    def __init__(self, callback: Callable[[], None], config: Optional[SchedulerConfig] = None):
        self._callback = callback
        self._config = config or SchedulerConfig()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._run_count: int = 0

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def run_count(self) -> int:
        return self._run_count

    def _loop(self) -> None:
        if self._config.run_on_start:
            self._execute()

        while not self._stop_event.is_set():
            if self._config.max_runs is not None and self._run_count >= self._config.max_runs:
                logger.info("Scheduler reached max_runs=%d, stopping.", self._config.max_runs)
                break

            interrupted = self._stop_event.wait(timeout=self._config.interval_seconds)
            if interrupted:
                break

            if self._config.max_runs is None or self._run_count < self._config.max_runs:
                self._execute()

    def _execute(self) -> None:
        try:
            logger.debug("Running scheduled dependency check (run #%d).", self._run_count + 1)
            self._callback()
            self._run_count += 1
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Scheduled check failed: %s", exc)

    def start(self) -> None:
        if self.is_running:
            raise RuntimeError("Scheduler is already running.")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="depwatch-scheduler")
        self._thread.start()
        logger.info("Scheduler started with interval=%ds.", self._config.interval_seconds)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("Scheduler stopped after %d run(s).", self._run_count)
