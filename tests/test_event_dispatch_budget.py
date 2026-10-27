"""An event flood must not hold the Tk thread.

``MainWindow._tick`` drains the event bus on the Tk thread. Bounding that by a
count alone could not bound the time it takes, and under real load it did not:
measured during a full-port Nmap scan of one host, with the capture pipeline
raising ``capture.packet_batch`` at roughly 230 events a second,

    EventBus.dispatch_all   n 31   mean 777.11 ms   worst 2007.1 ms
    MainWindow._tick        n 31   mean 809.46 ms   worst 2181.6 ms

so dispatch was 96% of the tick (24.09 s of 25.09 s) and the interface stalled
69 times in 220 seconds, worst 2,896 ms. The per-event cost was not the
problem - it averaged 0.063 ms - but individual events reached 215 ms, so no
fixed count is safe.

After giving the drain a wall-clock budget, the same scan measured 15 stalls
and a worst lag of 643 ms, with ``dispatch_all`` at 80 ms mean / 235 ms worst.

The second fix held here is that the unread-notification count is a database
query, and it was being run on the Tk thread for every stored notification.
"""

from __future__ import annotations

import inspect
import time

import pytest

from aethra_sec.core.event_bus import EventBus


def _bus() -> EventBus:
    return EventBus()


class TestTheDrainRespectsAWallClockBudget:
    def test_a_slow_subscriber_cannot_overrun_the_budget_indefinitely(self) -> None:
        bus = _bus()
        handled: list[int] = []

        def slow(event) -> None:  # noqa: ANN001
            time.sleep(0.005)
            handled.append(1)

        sid = bus.subscribe(
            ("test.event",), slow, queued=True, max_size=4000, name="slow"
        )
        for index in range(400):
            bus.publish("test.event", {"n": index})
        assert bus.pending(sid) == 400

        start = time.monotonic()
        dispatched = bus.dispatch_all(limit_per_subscription=400, time_budget_ms=60.0)
        elapsed = (time.monotonic() - start) * 1000.0

        assert dispatched < 400, "the whole flood was drained in one tick"
        # 400 x 5 ms is two seconds; the budget must stop it far short of that.
        assert elapsed < 600, f"the drain took {elapsed:.0f} ms against a 60 ms budget"
        assert handled, "nothing was delivered at all"

    def test_nothing_is_lost_when_the_budget_expires(self) -> None:
        """Deferred is not dropped: the rest must still be in the queue."""
        bus = _bus()
        seen: list[int] = []

        def slow(event) -> None:  # noqa: ANN001
            time.sleep(0.004)
            seen.append(int(event.payload["n"]))

        sid = bus.subscribe(
            ("test.event",), slow, queued=True, max_size=4000, name="slow"
        )
        for index in range(100):
            bus.publish("test.event", {"n": index})

        total = 0
        rounds = 0
        while bus.pending(sid) and rounds < 200:
            total += bus.dispatch_all(limit_per_subscription=100, time_budget_ms=20.0)
            rounds += 1
        assert total == 100, f"{100 - total} event(s) vanished"
        assert bus.pending(sid) == 0
        assert seen == list(range(100)), "events were delivered out of order"

    def test_one_noisy_subscription_does_not_starve_another(self) -> None:
        """Round-robin, so a flood on one topic still lets the others through."""
        bus = _bus()
        noisy: list[int] = []
        quiet: list[int] = []

        def on_noisy(event) -> None:  # noqa: ANN001
            time.sleep(0.002)
            noisy.append(1)

        bus.subscribe(("noisy.event",), on_noisy, queued=True, max_size=4000,
                      name="noisy")
        bus.subscribe(("quiet.event",), lambda e: quiet.append(1), queued=True,
                      max_size=100, name="quiet")
        for index in range(300):
            bus.publish("noisy.event", {"n": index})
        bus.publish("quiet.event", {"n": 1})

        bus.dispatch_all(limit_per_subscription=300, time_budget_ms=30.0)
        assert quiet, (
            "the quiet subscription was never reached; a flood on one topic "
            "must not hide a status change on another"
        )

    def test_no_budget_still_drains_everything(self) -> None:
        """The default must stay exhaustive - callers rely on it."""
        bus = _bus()
        seen: list[int] = []
        sid = bus.subscribe(("test.event",), lambda e: seen.append(1),
                            queued=True, max_size=4000, name="fast")
        for index in range(250):
            bus.publish("test.event", {"n": index})
        assert bus.dispatch_all(limit_per_subscription=500) == 250
        assert bus.pending(sid) == 0

    def test_the_count_limit_is_still_honoured_under_a_budget(self) -> None:
        bus = _bus()
        sid = bus.subscribe(("test.event",), lambda e: None, queued=True,
                            max_size=4000, name="fast")
        for index in range(300):
            bus.publish("test.event", {"n": index})
        dispatched = bus.dispatch_all(limit_per_subscription=50, time_budget_ms=5000.0)
        assert dispatched == 50
        assert bus.pending(sid) == 250

    def test_an_empty_bus_is_free(self) -> None:
        bus = _bus()
        assert bus.dispatch_all(limit_per_subscription=400, time_budget_ms=60.0) == 0

    def test_the_chunk_is_small_enough_to_check_the_clock_often(self) -> None:
        assert 0 < EventBus.DISPATCH_CHUNK <= 64, (
            "a chunk runs to completion, so a large one is how far past the "
            "deadline a drain can go"
        )


class TestTheUiTickPassesABudget:
    def test_the_tick_bounds_its_dispatch(self) -> None:
        from aethra_sec.ui.app import MainWindow

        body = inspect.getsource(MainWindow._tick)
        assert "time_budget_ms" in body, (
            "an unbounded drain on the Tk thread is what stalled the window "
            "for two seconds during a scan"
        )

    def test_the_budget_leaves_room_in_the_tick(self) -> None:
        from aethra_sec.ui.app import MainWindow

        # The tick interval is clamped to at least 250 ms, and the rest of the
        # tick measured under 20 ms, so the budget must sit well inside that.
        assert 0 < MainWindow.EVENT_BUDGET_MS <= 150


class TestTheNotificationCountIsNotOnTheTkThread:
    def test_the_count_runs_on_a_worker(self) -> None:
        from aethra_sec.ui.app import MainWindow

        body = inspect.getsource(MainWindow.refresh_notifications)
        assert "threading.Thread" in body and "dispatch.post" in body, (
            "unread_count is a database query and this is called for every "
            "stored notification"
        )
        count_at = body.index("unread_count")
        thread_at = body.index("def runner")
        assert thread_at < count_at, (
            "the query must sit inside the worker, not before it"
        )

    def test_it_is_single_flight(self) -> None:
        from aethra_sec.ui.app import MainWindow

        body = inspect.getsource(MainWindow.refresh_notifications)
        assert "_notification_count_running" in body, (
            "a burst of notifications would otherwise start a thread each to "
            "ask the same question"
        )

    def test_a_coalesced_refresh_still_asks_again(self) -> None:
        from aethra_sec.ui.app import MainWindow

        body = inspect.getsource(MainWindow.refresh_notifications)
        assert "_notification_count_again" in body, (
            "a refresh dropped while one was in flight would leave the badge "
            "showing a stale count"
        )
