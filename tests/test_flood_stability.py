"""Two faults seen during an authorised flood on 14 October 2026.

THE FREEZE. The thread named ``capture-worker`` held 89% of a core on its own
while every other thread was idle, and the window stopped repainting. A
py-spy dump taken at the time showed the main thread sitting in
``tkinter.mainloop`` doing nothing. Nothing was deadlocked and nothing leaked
- a pure-Python thread that never blocks never hands the interpreter lock to
the interface, so the interface is never scheduled.

THE STALE POPUP. Recorded in the log:

    04:11:39  Episode 2445 severity LOW -> MEDIUM at 500 pps
    04:11:40  Episode 2445 severity MEDIUM -> HIGH at 1000 pps
    04:11:41  Popup displayed: 2107          (the MEDIUM one)
    04:11:41  Popup queued behind an open popup: 2108   (the HIGH one)

The operator was shown "MEDIUM detection - Traffic anomaly #2445" while the
table beside it showed that anomaly as HIGH at 1,465.6 pps. The correction
was queued behind the thing it corrected.

The levels and rates below are test fixtures reproducing that recorded
sequence. No attack was performed to produce them.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.services.packet_capture import (
    WORKER_YIELD_INTERVAL,
    WORKER_YIELD_SECONDS,
    PacketCaptureService,
)
from aethra_sec.ui.widgets.toast import ToastManager


# ---------------------------------------------------------------------------
# The freeze
# ---------------------------------------------------------------------------
class TestTheWorkerYieldsToTheInterface:
    def test_the_loop_stands_aside_on_a_timer(self) -> None:
        source = inspect.getsource(PacketCaptureService._process_loop)
        assert "WORKER_YIELD_INTERVAL" in source, (
            "the worker no longer yields; a flood will freeze the window again"
        )
        assert "time.sleep(WORKER_YIELD_SECONDS)" in source
        assert "last_yield = now" in source, (
            "last_yield is never advanced, so the yield fires every pass"
        )

    def test_the_yield_is_frequent_enough_for_the_interface(self) -> None:
        """The UI ticks about four times a second; this must beat that."""
        per_second = 1.0 / WORKER_YIELD_INTERVAL
        assert per_second >= 10, (
            f"{per_second:.0f} yields a second is too few for a 4 Hz interface"
        )

    def test_the_yield_is_cheap_enough_to_keep_up(self) -> None:
        """A flood must still be processed, not merely survived."""
        cost = WORKER_YIELD_SECONDS / WORKER_YIELD_INTERVAL
        assert cost <= 0.10, (
            f"the worker gives up {cost:.0%} of its throughput; that is too "
            "much to keep pace with a flood"
        )

    def test_an_idle_system_pays_nothing(self) -> None:
        """An empty queue blocks in get() and releases the lock anyway."""
        source = inspect.getsource(PacketCaptureService._process_loop)
        assert "self._queue.get(timeout=0.25)" in source, (
            "the worker no longer blocks when idle, so it would spin"
        )


# ---------------------------------------------------------------------------
# The stale popup
# ---------------------------------------------------------------------------
@pytest.fixture()
def manager(tk_root):
    """A toast manager on a real frame, with no window of its own."""
    from tkinter import ttk

    from aethra_sec.ui.theme import build_fonts

    host = ttk.Frame(tk_root, width=800, height=600)
    host.pack(fill="both", expand=True)
    made = ToastManager(host, build_fonts(tk_root))
    try:
        yield made
    finally:
        made.clear()
        host.destroy()


def _texts(widget) -> list[str]:
    found: list[str] = []
    for child in widget.winfo_children():
        try:
            text = str(child.cget("text"))
        except Exception:  # noqa: BLE001
            text = ""
        if text:
            found.append(text)
        found.extend(_texts(child))
    return found


class TestAnEscalationReplacesItsOwnPopup:
    REFERENCE = "Traffic anomaly #2445"

    def test_the_recorded_sequence_ends_showing_high(self, manager) -> None:
        """The 04:11 sequence, replayed."""
        first = manager.show_persistent(
            "MEDIUM detection", "RULE-UDP-RATE - UDP flood indicator",
            level="WARNING", reference=self.REFERENCE)
        assert first is True

        second = manager.show_persistent(
            "HIGH detection", "RULE-UDP-RATE - UDP flood indicator",
            level="ERROR", reference=self.REFERENCE)
        assert second is True, "the escalation was queued instead of shown"

        texts = _texts(manager.persistent_frame)
        assert "HIGH detection" in texts, (
            "the popup still shows a severity the attack has outgrown"
        )
        assert "MEDIUM detection" not in texts
        assert manager.pending_count == 0, (
            "the superseded popup was left in the queue to appear later"
        )

    def test_a_different_record_still_queues(self, manager) -> None:
        """Replacing is only ever a correction of the same record."""
        manager.show_persistent("MEDIUM detection", "one", level="WARNING",
                                reference="Traffic anomaly #2445")
        shown = manager.show_persistent("HIGH detection", "two", level="ERROR",
                                        reference="Traffic anomaly #9999")
        assert shown is False, "an unrelated alert replaced the open popup"
        assert "MEDIUM detection" in _texts(manager.persistent_frame)
        assert manager.pending_count == 1

    def test_the_same_record_at_a_lower_severity_does_not_disturb_it(
        self, manager
    ) -> None:
        """A rate falling back must not pull the warning off the screen."""
        manager.show_persistent("HIGH detection", "one", level="ERROR",
                                reference=self.REFERENCE)
        shown = manager.show_persistent("MEDIUM detection", "two",
                                        level="WARNING",
                                        reference=self.REFERENCE)
        assert shown is False
        assert "HIGH detection" in _texts(manager.persistent_frame)

    def test_the_same_record_at_the_same_severity_does_not_flicker(
        self, manager
    ) -> None:
        manager.show_persistent("HIGH detection", "one", level="ERROR",
                                reference=self.REFERENCE)
        frame = manager.persistent_frame
        manager.show_persistent("HIGH detection", "again", level="ERROR",
                                reference=self.REFERENCE)
        assert manager.persistent_frame is frame, "the popup was rebuilt"

    def test_a_notification_with_no_reference_never_supersedes(
        self, manager
    ) -> None:
        """Subsystem notices carry no record id and must not replace an alert."""
        manager.show_persistent("MEDIUM detection", "one", level="WARNING",
                                reference=self.REFERENCE)
        shown = manager.show_persistent("SNORT OFFLINE", "two", level="ERROR",
                                        reference="")
        assert shown is False
        assert "MEDIUM detection" in _texts(manager.persistent_frame)

    def test_an_unknown_level_never_supersedes(self, manager) -> None:
        manager.show_persistent("MEDIUM detection", "one", level="WARNING",
                                reference=self.REFERENCE)
        shown = manager.show_persistent("odd", "two", level="NOT-A-LEVEL",
                                        reference=self.REFERENCE)
        assert shown is False

    def test_replacing_does_not_skip_a_queued_notification(
        self, manager
    ) -> None:
        """The queue must still be intact behind the corrected popup."""
        manager.show_persistent("MEDIUM detection", "a", level="WARNING",
                                reference=self.REFERENCE)
        manager.show_persistent("Other alert", "b", level="WARNING",
                                reference="Traffic anomaly #9999")
        assert manager.pending_count == 1

        manager.show_persistent("HIGH detection", "c", level="ERROR",
                                reference=self.REFERENCE)
        assert "HIGH detection" in _texts(manager.persistent_frame)
        assert manager.pending_count == 1, (
            "the queued unrelated alert was lost during the replacement"
        )

    def test_close_still_advances_the_queue(self, manager) -> None:
        manager.show_persistent("MEDIUM detection", "a", level="WARNING",
                                reference=self.REFERENCE)
        manager.show_persistent("Other alert", "b", level="WARNING",
                                reference="Traffic anomaly #9999")
        manager.close_persistent(manager.persistent_frame)
        assert "Other alert" in _texts(manager.persistent_frame)
        assert manager.pending_count == 0
