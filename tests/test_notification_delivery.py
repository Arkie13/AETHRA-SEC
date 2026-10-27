"""A stored notification must reach the interface, even during a flood.

The popup "did not appear reliably". It was not the popup: the main window
took every UI event through one queued subscription, and the bus discards the
oldest event when a buffer fills. During a flood the capture pipeline filled
it with packet batches and NOTIFICATION_STORED was evicted on exactly the
same terms as a counter update.

The production log showed it: notifications 2009, 2011 and 2024 were stored
with no matching line from the interface, while the ones that did arrive came
3s, then 7s, then 9s late - a buffer filling up.

Notifications now wait in a buffer of their own, and a discarded event is
logged instead of being counted in silence.

The events below are test fixtures. They are not observations of any network.
"""

from __future__ import annotations

import inspect
import logging

import pytest

from aethra_sec.core.event_bus import DROP_LOG_INTERVAL_SECONDS, EventBus
from aethra_sec.core.events import EventType


# ---------------------------------------------------------------------------
# The confirmed root cause, reproduced and fixed
# ---------------------------------------------------------------------------
class TestAFloodCannotEvictANotification:
    @staticmethod
    def _flood(bus: EventBus, count: int = 200) -> None:
        for index in range(count):
            bus.publish(EventType.PACKET_BATCH_PROCESSED, {"n": index})

    def test_a_shared_buffer_loses_the_notification(self) -> None:
        """The defect, reproduced. This is what the old wiring did.

        Kept as a test so the reason for the separate subscription stays
        legible: put them back together and the notification disappears.
        """
        bus = EventBus()
        seen: list[str] = []
        bus.subscribe(
            (EventType.PACKET_BATCH_PROCESSED, EventType.NOTIFICATION_STORED),
            lambda event: seen.append(event.type),
            queued=True, max_size=50, name="shared",
        )
        bus.publish(EventType.NOTIFICATION_STORED, {"id": 1})
        self._flood(bus)
        bus.dispatch_all()
        assert EventType.NOTIFICATION_STORED not in seen, (
            "the shared buffer no longer reproduces the reported loss; this "
            "test is the record of why notifications were separated"
        )

    def test_a_separate_buffer_keeps_it(self) -> None:
        """The fix, against the same flood."""
        bus = EventBus()
        traffic: list = []
        notes: list = []
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), traffic.append,
                      queued=True, max_size=50, name="main-window")
        bus.subscribe((EventType.NOTIFICATION_STORED,), notes.append,
                      queued=True, max_size=512,
                      name="main-window-notifications")
        bus.publish(EventType.NOTIFICATION_STORED, {"id": 1})
        self._flood(bus)
        bus.dispatch_all()
        assert len(notes) == 1, "the notification was lost despite its own buffer"

    def test_the_traffic_buffer_still_bounds_itself(self) -> None:
        """Separating them must not make the UI queue unbounded."""
        bus = EventBus()
        traffic: list = []
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), traffic.append,
                      queued=True, max_size=50, name="main-window")
        self._flood(bus, 500)
        bus.dispatch_all()
        assert len(traffic) == 50

    def test_many_notifications_still_fit(self) -> None:
        """A burst of real notifications is not itself a flood."""
        bus = EventBus()
        notes: list = []
        bus.subscribe((EventType.NOTIFICATION_STORED,), notes.append,
                      queued=True, max_size=512,
                      name="main-window-notifications")
        for index in range(300):
            bus.publish(EventType.NOTIFICATION_STORED, {"id": index})
        bus.dispatch_all()
        assert len(notes) == 300


# ---------------------------------------------------------------------------
# A discarded event says so
# ---------------------------------------------------------------------------
class TestADroppedEventIsReported:
    def test_overflow_is_logged_with_what_was_lost(self, caplog) -> None:
        bus = EventBus()
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), lambda e: None,
                      queued=True, max_size=5, name="tiny")
        with caplog.at_level(logging.WARNING):
            for index in range(40):
                bus.publish(EventType.PACKET_BATCH_PROCESSED, {"n": index})
        warnings = [r.getMessage() for r in caplog.records
                    if "Event buffer full" in r.getMessage()]
        assert warnings, "a dropped event was discarded in silence"
        assert "tiny" in warnings[0], "the subscription is not named"
        assert EventType.PACKET_BATCH_PROCESSED in warnings[0], (
            "the kind of event lost is not named"
        )

    def test_the_warning_does_not_itself_flood(self, caplog) -> None:
        """A full buffer drops one event per publish."""
        bus = EventBus()
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), lambda e: None,
                      queued=True, max_size=5, name="tiny")
        with caplog.at_level(logging.WARNING):
            for index in range(500):
                bus.publish(EventType.PACKET_BATCH_PROCESSED, {"n": index})
        warnings = [r for r in caplog.records
                    if "Event buffer full" in r.getMessage()]
        assert len(warnings) == 1, (
            f"{len(warnings)} warnings for one burst; the rate limit is not "
            "holding"
        )

    def test_the_drop_counter_still_tracks_every_loss(self) -> None:
        """Rate limiting the log must not rate limit the accounting."""
        bus = EventBus()
        bus.subscribe((EventType.PACKET_BATCH_PROCESSED,), lambda e: None,
                      queued=True, max_size=5, name="tiny")
        for index in range(40):
            bus.publish(EventType.PACKET_BATCH_PROCESSED, {"n": index})
        stats = bus.statistics()
        assert stats["dropped_events"] == 35

    def test_the_interval_is_a_real_bound(self) -> None:
        assert DROP_LOG_INTERVAL_SECONDS > 0


# ---------------------------------------------------------------------------
# The window is wired the way the fix requires
# ---------------------------------------------------------------------------
class TestTheWindowSubscribesSeparately:
    def test_notifications_are_not_in_the_shared_tuple(self) -> None:
        from aethra_sec.ui.app import _NOTIFICATION_EVENTS, _UI_EVENTS

        assert EventType.NOTIFICATION_STORED not in _UI_EVENTS, (
            "notifications share the flooded queue again"
        )
        assert EventType.NOTIFICATION_STORED in _NOTIFICATION_EVENTS

    def test_the_window_opens_both_subscriptions(self) -> None:
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow.__init__)
        assert 'name="main-window"' in source
        assert 'name="main-window-notifications"' in source
        assert "_NOTIFICATION_EVENTS" in source

    def test_both_are_released_on_shutdown(self) -> None:
        """A leaked subscription keeps a dead window fed with events."""
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow)
        assert source.count("event_bus.unsubscribe") >= 2

    def test_the_handler_only_acts_on_a_stored_notification(self) -> None:
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow._on_notification_event)
        assert "if event.type != EventType.NOTIFICATION_STORED:" in source
        assert "return" in source

    def test_the_popup_result_is_reported_honestly(self) -> None:
        """Queued behind an open popup is not the same as displayed."""
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow._on_notification_event)
        assert '"displayed" if shown else "queued behind an open popup"' in source

    def test_sound_cannot_prevent_the_popup(self) -> None:
        """The popup is raised outside the audio branch."""
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow._on_notification_event)
        guard = popup = None
        for line in source.splitlines():
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped.startswith("if audio is not None"):
                guard = indent
            elif "show_persistent" in stripped and popup is None:
                popup = indent
        assert guard is not None and popup is not None
        assert popup <= guard, "the popup is nested inside the audio branch"


# ---------------------------------------------------------------------------
# Eligibility: LOW stays filtered, MEDIUM and HIGH get through
# ---------------------------------------------------------------------------
class TestEligibilityIsUnchanged:
    """The filter is configuration, not a defect, and must keep working."""

    @pytest.mark.parametrize("severity,expected", [
        ("LOW", False), ("MEDIUM", True), ("HIGH", True), ("CRITICAL", True),
    ])
    def test_the_minimum_severity_is_ranked_not_compared_as_text(
        self, severity: str, expected: bool
    ) -> None:
        from aethra_sec.models.enums import Severity

        value = Severity.parse(severity, Severity.INFO)
        assert value.at_least(Severity.MEDIUM) is expected

    def test_alphabetical_comparison_would_get_this_wrong(self) -> None:
        """HIGH < MEDIUM as text, which is why ranking is used."""
        assert "HIGH" < "MEDIUM"
        from aethra_sec.models.enums import Severity

        assert Severity.HIGH.at_least(Severity.MEDIUM) is True

    def test_the_service_uses_the_ranking(self) -> None:
        from aethra_sec.services import notification_service

        source = inspect.getsource(notification_service.NotificationService)
        assert "at_least(minimum)" in source
