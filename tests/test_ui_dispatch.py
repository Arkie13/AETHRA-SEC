"""Worker threads must never touch Tk (§75).

Tkinter is single-threaded. Calling ``widget.after()`` from a worker was always
unsafe and **Python 3.14 raises** ``RuntimeError: main thread is not in main
loop``, which froze the sign-in window on exactly that line. Every worker now
hands its result to :mod:`aethra_sec.ui.dispatch` instead.

These tests use a stub root, so they check the dispatcher's logic and the rule
itself without needing a display.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest

from aethra_sec.ui import dispatch
from aethra_sec.ui.dispatch import TkDispatcher

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UI_ROOT = PROJECT_ROOT / "aethra_sec" / "ui"


class StubRoot:
    """A stand-in for a Tk root that records scheduled callbacks."""

    def __init__(self) -> None:
        """Start with nothing scheduled."""
        self.scheduled: list = []
        self.cancelled: list[str] = []

    def after(self, _ms: int, callback) -> str:
        """Record a scheduled callback instead of running it."""
        self.scheduled.append(callback)
        return f"job{len(self.scheduled)}"

    def after_cancel(self, job: str) -> None:
        """Record a cancellation."""
        self.cancelled.append(job)


@pytest.fixture
def stub() -> StubRoot:
    """A fresh stub root."""
    return StubRoot()


@pytest.fixture(autouse=True)
def _clean_global_dispatcher():
    """Never leave a dispatcher installed for the next test."""
    yield
    dispatch.shutdown()


class TestDispatcherDelivery:
    """Callables posted from anywhere run on the draining thread."""

    def test_posted_callable_runs_on_drain(self, stub: StubRoot) -> None:
        """Nothing runs until the owner drains."""
        dispatcher = TkDispatcher(stub)
        dispatcher.start()
        ran: list[str] = []
        dispatcher.post(lambda: ran.append("a"))

        assert ran == [], "a posted callable must not run on the posting thread"
        assert dispatcher.drain() == 1
        assert ran == ["a"]

    def test_order_is_preserved(self, stub: StubRoot) -> None:
        """Results arrive in the order they were produced."""
        dispatcher = TkDispatcher(stub)
        dispatcher.start()
        ran: list[int] = []
        for index in range(5):
            dispatcher.post(lambda i=index: ran.append(i))
        dispatcher.drain()
        assert ran == [0, 1, 2, 3, 4]

    def test_delivery_from_a_worker_thread(self, stub: StubRoot) -> None:
        """A worker can post without touching Tk at all."""
        dispatcher = TkDispatcher(stub)
        dispatcher.start()
        ran: list[str] = []

        def worker() -> None:
            dispatcher.post(lambda: ran.append(threading.current_thread().name))

        thread = threading.Thread(target=worker, name="worker")
        thread.start()
        thread.join()

        assert ran == []
        dispatcher.drain()
        assert ran == [threading.current_thread().name], (
            "the callable must run on the draining thread, not the worker"
        )

    def test_a_failing_callable_does_not_stop_the_rest(self, stub: StubRoot) -> None:
        """One bad result must not strand every later one."""
        dispatcher = TkDispatcher(stub)
        dispatcher.start()
        ran: list[str] = []

        def boom() -> None:
            raise ValueError("deliberate")

        dispatcher.post(boom)
        dispatcher.post(lambda: ran.append("after the failure"))
        dispatcher.drain()
        assert ran == ["after the failure"]

    def test_stop_discards_pending_work(self, stub: StubRoot) -> None:
        """Nothing is delivered into a window that is closing."""
        dispatcher = TkDispatcher(stub)
        dispatcher.start()
        ran: list[str] = []
        dispatcher.post(lambda: ran.append("late"))
        dispatcher.stop()

        assert dispatcher.pending == 0
        assert dispatcher.drain() == 0
        assert ran == []

    def test_posting_to_a_stopped_dispatcher_is_dropped(self, stub: StubRoot) -> None:
        """A result produced after shutdown is dropped, not raised."""
        dispatcher = TkDispatcher(stub)
        dispatcher.start()
        dispatcher.stop()
        dispatcher.post(lambda: None)
        assert dispatcher.pending == 0


class TestModuleLevelPost:
    """``dispatch.post`` is what the screens actually call."""

    def test_uses_the_installed_dispatcher(self, stub: StubRoot) -> None:
        """With a dispatcher installed, the callable is queued."""
        dispatcher = dispatch.install(stub)
        ran: list[str] = []
        assert dispatch.post(lambda: ran.append("queued")) is True
        assert ran == []
        dispatcher.drain()
        assert ran == ["queued"]

    def test_runs_inline_on_the_main_thread_without_a_dispatcher(self) -> None:
        """A unit test with no window still gets its callback."""
        dispatch.shutdown()
        ran: list[str] = []
        assert dispatch.post(lambda: ran.append("inline")) is True
        assert ran == ["inline"]

    def test_worker_result_is_dropped_without_a_dispatcher(self) -> None:
        """Better to drop a result than to touch Tk from a worker."""
        dispatch.shutdown()
        outcome: list[bool] = []
        ran: list[str] = []

        def worker() -> None:
            outcome.append(dispatch.post(lambda: ran.append("never")))

        thread = threading.Thread(target=worker, name="worker")
        thread.start()
        thread.join()

        assert outcome == [False]
        assert ran == []

    def test_ensure_reuses_a_running_dispatcher(self, stub: StubRoot) -> None:
        """Windows call ensure(); it must not replace a live dispatcher."""
        first = dispatch.ensure(stub)
        second = dispatch.ensure(stub)
        assert first is second
        assert first.is_running

    def test_ensure_replaces_a_stopped_dispatcher(self, stub: StubRoot) -> None:
        """After shutdown, ensure() brings the bridge back."""
        first = dispatch.ensure(stub)
        first.stop()
        second = dispatch.ensure(stub)
        assert second is not first
        assert second.is_running


class TestNoWorkerTouchesTk:
    """The rule, enforced against the source."""

    #: Methods that run on a worker thread and must not schedule Tk work.
    WORKER_DELIVERY_FILES = (
        UI_ROOT / "base.py",
        UI_ROOT / "login.py",
        UI_ROOT / "screens" / "reports.py",
    )

    @pytest.mark.parametrize(
        "path", WORKER_DELIVERY_FILES, ids=lambda p: p.name
    )
    def test_no_immediate_after_calls(self, path: Path) -> None:
        """``after(0, ...)`` is the signature of the bug that was fixed.

        Timers scheduled from the Tk thread are fine; an immediate ``after(0)``
        means "run this as soon as possible", which is what worker code used to
        do and what Python 3.14 refuses.
        """
        text = path.read_text(encoding="utf-8")
        offenders = re.findall(r"\.after\(\s*0\s*,", text)
        assert not offenders, (
            f"{path.name} schedules immediate Tk work; post it through "
            "aethra_sec.ui.dispatch instead"
        )

    def test_windows_guarantee_the_bridge(self) -> None:
        """Both windows install the dispatcher themselves."""
        for name in ("app.py", "login.py"):
            text = (UI_ROOT / name).read_text(encoding="utf-8")
            assert "dispatch.ensure(" in text, f"{name} does not ensure a dispatcher"

    def test_console_stops_the_bridge_on_close(self) -> None:
        """Shutdown stops delivery before the widgets go away."""
        text = (UI_ROOT / "app.py").read_text(encoding="utf-8")
        assert "dispatch.shutdown()" in text
