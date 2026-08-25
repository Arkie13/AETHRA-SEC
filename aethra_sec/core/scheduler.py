"""A small periodic job runner used for background maintenance.

Jobs are health probes, aggregate flushes, retention pruning and session
purging - none of them touch Tk. Each job runs on the scheduler thread inside a
try/except so one failing job can never stop the others (§57, §58).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("core.scheduler")


@dataclass
class ScheduledJob:
    """One periodic job and its real execution counters."""

    name: str
    interval_seconds: float
    callback: Callable[[], None]
    next_run: float
    run_count: int = 0
    error_count: int = 0
    last_run: datetime | None = None
    last_error: str = ""
    last_duration: float = 0.0
    enabled: bool = True
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class PeriodicScheduler:
    """Runs registered callables at fixed intervals on a single daemon thread."""

    def __init__(self, tick_seconds: float = 0.5) -> None:
        """Create a stopped scheduler.

        Args:
            tick_seconds: granularity of the internal loop.
        """
        self._jobs: dict[str, ScheduledJob] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._tick = max(0.05, tick_seconds)

    def add_job(
        self,
        name: str,
        interval_seconds: float,
        callback: Callable[[], None],
        *,
        run_immediately: bool = False,
    ) -> None:
        """Register or replace a periodic job."""
        import time

        with self._lock:
            self._jobs[name] = ScheduledJob(
                name=name,
                interval_seconds=max(0.1, float(interval_seconds)),
                callback=callback,
                next_run=time.monotonic() + (0 if run_immediately else interval_seconds),
            )

    def remove_job(self, name: str) -> None:
        """Unregister a job; unknown names are ignored."""
        with self._lock:
            self._jobs.pop(name, None)

    def set_interval(self, name: str, interval_seconds: float) -> None:
        """Change a job's interval (used when an administrator edits settings)."""
        with self._lock:
            job = self._jobs.get(name)
            if job:
                job.interval_seconds = max(0.1, float(interval_seconds))

    def start(self) -> None:
        """Start the scheduler thread if it is not already running."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="aethra-scheduler", daemon=True
        )
        self._thread.start()
        LOGGER.info("Background scheduler started.")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the scheduler to stop and wait briefly for the thread."""
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None
        LOGGER.info("Background scheduler stopped.")

    @property
    def is_running(self) -> bool:
        """True while the scheduler thread is alive."""
        return bool(self._thread and self._thread.is_alive())

    def run_now(self, name: str) -> bool:
        """Run one job immediately on the calling thread.

        Returns:
            True when the job exists and completed without raising.
        """
        with self._lock:
            job = self._jobs.get(name)
        if job is None:
            return False
        return self._execute(job)

    def _run(self) -> None:
        """Scheduler loop."""
        import time

        while not self._stop.is_set():
            now = time.monotonic()
            with self._lock:
                due = [j for j in self._jobs.values() if j.enabled and j.next_run <= now]
            for job in due:
                job.next_run = time.monotonic() + job.interval_seconds
                self._execute(job)
            self._stop.wait(self._tick)

    def _execute(self, job: ScheduledJob) -> bool:
        """Execute a job, recording duration and any failure."""
        import time

        if not job._lock.acquire(blocking=False):
            # Previous invocation still running; skip this tick rather than
            # letting slow jobs pile up.
            return False
        started = time.monotonic()
        try:
            job.callback()
            job.run_count += 1
            job.last_run = utcnow()
            job.last_error = ""
            return True
        except Exception as exc:  # noqa: BLE001 - isolate failing jobs
            job.error_count += 1
            job.last_run = utcnow()
            job.last_error = str(exc)
            LOGGER.exception("Scheduled job '%s' failed", job.name)
            return False
        finally:
            job.last_duration = time.monotonic() - started
            job._lock.release()

    def job_status(self) -> list[dict[str, object]]:
        """Real execution statistics for the System Health screen."""
        with self._lock:
            jobs = list(self._jobs.values())
        return [
            {
                "name": job.name,
                "interval_seconds": job.interval_seconds,
                "runs": job.run_count,
                "errors": job.error_count,
                "last_run": job.last_run,
                "last_error": job.last_error,
                "last_duration_seconds": round(job.last_duration, 4),
            }
            for job in sorted(jobs, key=lambda j: j.name)
        ]
