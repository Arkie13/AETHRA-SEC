"""The centred, persistent notification popup and its two buttons.

These build real Tk widgets through the shared ``tk_root`` fixture and read
back what Tk itself reports - placement, geometry, which widgets exist - so a
passing test means the popup really was centred and really did survive, not
that a mock said so.

The notification strings used here are test fixtures. They are not real
security events, and nothing in this file writes to the database or claims
that an attack occurred.
"""

from __future__ import annotations

import inspect
import time

import pytest

from aethra_sec.ui.widgets import toast as toast_module
from aethra_sec.ui.widgets.toast import (
    CHECK_LABEL,
    CLOSE_LABEL,
    MAX_PENDING,
    ToastManager,
)

#: A stand-in for the application window's body frame, at a known size.
HOST_WIDTH, HOST_HEIGHT = 900, 600


@pytest.fixture()
def host(tk_root):
    """A sized frame standing in for the window body the popup is placed in."""
    import tkinter as tk
    from tkinter import ttk

    frame = ttk.Frame(tk_root, width=HOST_WIDTH, height=HOST_HEIGHT)
    frame.pack(fill="both", expand=True)
    frame.pack_propagate(False)
    tk_root.deiconify()
    tk_root.geometry(f"{HOST_WIDTH}x{HOST_HEIGHT}+120+90")
    tk_root.update_idletasks()
    try:
        yield frame
    finally:
        try:
            frame.destroy()
            tk_root.withdraw()
        except tk.TclError:
            pass


@pytest.fixture()
def fonts(tk_root):
    """The real font set, built the way the application builds it."""
    from aethra_sec.ui.theme import build_fonts

    return build_fonts(tk_root)


@pytest.fixture()
def manager(host, fonts):
    """A toast manager bound to the stand-in body frame."""
    made = ToastManager(host, fonts)
    try:
        yield made
    finally:
        made.clear()


def _pump(root, seconds: float) -> None:
    """Run the real Tk event loop for a while, so timers can actually fire."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        root.update()
        time.sleep(0.01)


def _centre_of(widget) -> tuple[float, float]:
    """The widget's centre, in screen coordinates."""
    widget.update_idletasks()
    return (
        widget.winfo_rootx() + widget.winfo_width() / 2,
        widget.winfo_rooty() + widget.winfo_height() / 2,
    )


def _label_texts(widget) -> list[str]:
    """Every piece of text Tk reports under this widget."""
    found: list[str] = []
    for child in widget.winfo_children():
        try:
            text = str(child.cget("text"))
        except Exception:  # noqa: BLE001 - not every widget has text
            text = ""
        if text:
            found.append(text)
        found.extend(_label_texts(child))
    return found


# ---------------------------------------------------------------------------
# TEST 1 - centre position
# ---------------------------------------------------------------------------
class TestItIsCentredInTheWindow:
    def test_tk_places_it_at_the_centre_of_the_host(self, manager, host) -> None:
        manager.show_persistent("Detection", "fixture message", level="CRITICAL")
        frame = manager.persistent_frame
        assert frame is not None
        info = frame.place_info()
        assert float(info["relx"]) == 0.5
        assert float(info["rely"]) == 0.5
        assert info["anchor"] == "center"

    def test_the_measured_centre_matches_the_window_centre(
        self, manager, host
    ) -> None:
        """Not just the placement call - where the pixels actually landed."""
        manager.show_persistent("Detection", "fixture message", level="WARNING")
        host.update_idletasks()
        popup_x, popup_y = _centre_of(manager.persistent_frame)
        host_x, host_y = _centre_of(host)
        assert abs(popup_x - host_x) <= 1, (popup_x, host_x)
        assert abs(popup_y - host_y) <= 1, (popup_y, host_y)

    def test_it_fits_entirely_inside_the_window(self, manager, host) -> None:
        manager.show_persistent(
            "Detection", "a longer fixture message " * 6, level="CRITICAL")
        host.update_idletasks()
        frame = manager.persistent_frame
        assert frame.winfo_width() <= host.winfo_width()
        assert frame.winfo_height() <= host.winfo_height()
        assert frame.winfo_rootx() >= host.winfo_rootx()
        assert frame.winfo_rooty() >= host.winfo_rooty()

    def test_it_is_not_in_the_corner_any_more(self, manager, host) -> None:
        """The transient toast still is; this one must not be."""
        manager.show_persistent("Detection", "fixture", level="INFO")
        info = manager.persistent_frame.place_info()
        assert info["anchor"] != "se"

    def test_the_transient_toast_still_sits_in_the_corner(
        self, manager, host
    ) -> None:
        """Unrelated behaviour must not have moved."""
        manager.show("Assessment complete", "fixture", level="SUCCESS")
        host.update_idletasks()
        placed = manager._toasts[0].place_info()
        assert placed["anchor"] == "se"
        assert float(placed["relx"]) == 1.0


# ---------------------------------------------------------------------------
# TEST 2 - window movement
# ---------------------------------------------------------------------------
class TestMovingTheWindow:
    def test_it_travels_with_the_window_and_stays_centred(
        self, manager, host, tk_root
    ) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        host.update_idletasks()
        before = _centre_of(manager.persistent_frame)

        tk_root.geometry(f"{HOST_WIDTH}x{HOST_HEIGHT}+400+260")
        _pump(tk_root, 0.2)

        after = _centre_of(manager.persistent_frame)
        host_centre = _centre_of(host)
        assert after != before, "the popup did not move with the window"
        assert abs(after[0] - host_centre[0]) <= 1
        assert abs(after[1] - host_centre[1]) <= 1
        assert manager.persistent_frame.winfo_exists()


# ---------------------------------------------------------------------------
# TEST 3 - window resizing
# ---------------------------------------------------------------------------
class TestResizingTheWindow:
    @pytest.mark.parametrize("width,height", [(1300, 800), (700, 480)])
    def test_it_re_centres_and_stays_visible(
        self, manager, host, tk_root, width: int, height: int
    ) -> None:
        manager.show_persistent("Detection", "fixture", level="WARNING")
        host.update_idletasks()

        host.configure(width=width, height=height)
        tk_root.geometry(f"{width}x{height}+120+90")
        _pump(tk_root, 0.2)

        frame = manager.persistent_frame
        assert frame is not None and frame.winfo_exists()
        popup_centre = _centre_of(frame)
        host_centre = _centre_of(host)
        assert abs(popup_centre[0] - host_centre[0]) <= 1
        assert abs(popup_centre[1] - host_centre[1]) <= 1
        assert frame.winfo_width() <= host.winfo_width()
        assert frame.winfo_height() <= host.winfo_height()


# ---------------------------------------------------------------------------
# TEST 4 - persistence
# ---------------------------------------------------------------------------
class TestItDoesNotDismissItself:
    def test_it_outlives_the_transient_toast_duration(
        self, manager, host, tk_root, monkeypatch
    ) -> None:
        """Run past the dismissal interval for real, with the clock shortened.

        The transient toast's own timer is cut to 60 ms so the comparison can
        be made inside a test: the toast goes, the popup stays. Nothing about
        the popup's code path is patched.
        """
        monkeypatch.setitem(toast_module.DURATION_MS, "CRITICAL", 60)
        manager.show("Transient", "fixture", level="CRITICAL")
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        assert len(manager._toasts) == 1

        _pump(tk_root, 0.5)

        assert manager._toasts == [], "the transient toast should have gone"
        assert manager.persistent_frame is not None
        assert manager.persistent_frame.winfo_exists()

    def test_showing_it_schedules_no_dismissal_timer(
        self, manager, host, tk_root
    ) -> None:
        """Decisive: no after() callback is registered for this popup."""
        before = set(tk_root.tk.call("after", "info"))
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        after = set(tk_root.tk.call("after", "info"))
        assert after - before == set(), "a timer was scheduled for the popup"

    def test_a_transient_toast_does_schedule_one(
        self, manager, host, tk_root
    ) -> None:
        """The contrast that makes the previous test meaningful."""
        before = set(tk_root.tk.call("after", "info"))
        manager.show("Transient", "fixture", level="CRITICAL")
        after = set(tk_root.tk.call("after", "info"))
        assert after - before, "the transient toast lost its timer"

    def test_clicking_elsewhere_does_not_dismiss_it(
        self, manager, host, tk_root
    ) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        frame = manager.persistent_frame
        host.event_generate("<Button-1>", x=5, y=5)
        host.focus_set()
        frame.event_generate("<FocusOut>")
        _pump(tk_root, 0.1)
        assert manager.persistent_frame is frame
        assert frame.winfo_exists()

    def test_it_is_not_modal_so_the_app_stays_usable(self) -> None:
        """No grab_set anywhere on the persistent path."""
        source = inspect.getsource(toast_module)
        assert "grab_set" not in source


# ---------------------------------------------------------------------------
# TEST 5 - the CLOSE button
# ---------------------------------------------------------------------------
def _button_named(widget, label: str):
    """The real ttk.Button carrying this exact text."""
    for child in widget.winfo_children():
        try:
            if str(child.cget("text")) == label and "button" in str(child):
                return child
        except Exception:  # noqa: BLE001
            pass
        found = _button_named(child, label)
        if found is not None:
            return found
    return None


class TestTheCloseButton:
    def test_the_button_exists_with_that_exact_label(self, manager, host) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        assert _button_named(manager.persistent_frame, CLOSE_LABEL) is not None
        assert CLOSE_LABEL == "CLOSE"

    def test_clicking_it_dismisses_the_popup(self, manager, host) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        frame = manager.persistent_frame
        _button_named(frame, CLOSE_LABEL).invoke()
        assert manager.persistent_frame is None
        assert not frame.winfo_exists()

    def test_it_does_not_disturb_the_transient_toasts(self, manager, host) -> None:
        manager.show("Assessment complete", "fixture", level="SUCCESS")
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        _button_named(manager.persistent_frame, CLOSE_LABEL).invoke()
        assert len(manager._toasts) == 1, "closing the popup took a toast with it"

    def test_a_stale_callback_cannot_close_the_current_popup(
        self, manager, host
    ) -> None:
        """The identity check that stops one popup destroying another."""
        manager.show_persistent("First", "fixture", level="CRITICAL")
        first = manager.persistent_frame
        manager.close_persistent(first)
        manager.show_persistent("Second", "fixture", level="CRITICAL")
        second = manager.persistent_frame

        manager.close_persistent(first)          # the stale one fires again

        assert manager.persistent_frame is second
        assert second.winfo_exists()

    def test_closing_twice_is_harmless(self, manager, host) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        frame = manager.persistent_frame
        manager.close_persistent(frame)
        manager.close_persistent(frame)
        assert manager.persistent_frame is None

    def test_the_popup_cannot_change_an_alert_record(self) -> None:
        """It has no way to: no session, no repository, no service.

        This is why CLOSE cannot alter severity, addresses, timestamps or
        review status - the widget has no database access at all.
        """
        source = inspect.getsource(toast_module)
        # Call-shaped, not word-shaped: the module's own docstrings say that
        # review status is untouched, and banning the word would forbid
        # saying so.
        for forbidden in ("session", "repositor", "Repository", "execute(",
                          "UPDATE ", "DELETE ", "commit(", "mark_reviewed",
                          "set_review", ".review(", "update_status"):
            assert forbidden not in source, (
                f"the popup module references {forbidden!r}"
            )


# ---------------------------------------------------------------------------
# TEST 6 and 7 - the CHECK button
# ---------------------------------------------------------------------------
class TestTheCheckButton:
    def test_the_button_exists_with_that_exact_label(self, manager, host) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        assert _button_named(manager.persistent_frame, CHECK_LABEL) is not None
        assert CHECK_LABEL == "CHECK"

    def test_it_runs_the_navigation_action(self, manager, host) -> None:
        navigated: list[str] = []
        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL",
            on_check=lambda: navigated.append("alerts"),
        )
        _button_named(manager.persistent_frame, CHECK_LABEL).invoke()
        assert navigated == ["alerts"]

    def test_check_navigates_and_dismisses_the_popup(self, manager, host) -> None:
        """One press, one intention: go and look, and clear the way.

        The popup used to stay up, which left it covering the screen the
        operator had just asked to see and took a second click to remove.
        """
        navigated: list[str] = []
        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL",
            on_check=lambda: navigated.append("alerts"),
        )
        frame = manager.persistent_frame
        _button_named(frame, CHECK_LABEL).invoke()
        assert navigated == ["alerts"], "navigation did not run"
        assert manager.persistent_frame is None
        assert not frame.winfo_exists()

    def test_the_next_queued_popup_is_centred_after_check(
        self, manager, host
    ) -> None:
        """Dismissing by CHECK advances the queue exactly as CLOSE does."""
        manager.show_persistent("First", "one", level="CRITICAL",
                                on_check=lambda: None)
        manager.show_persistent("Second", "two", level="WARNING")
        _button_named(manager.persistent_frame, CHECK_LABEL).invoke()

        following = manager.persistent_frame
        assert following is not None, "the queued notification was lost"
        assert "Second" in _label_texts(following)
        host.update_idletasks()
        popup_centre = _centre_of(following)
        host_centre = _centre_of(host)
        assert abs(popup_centre[0] - host_centre[0]) <= 1
        assert abs(popup_centre[1] - host_centre[1]) <= 1

    def test_a_second_press_cannot_navigate_twice(self, manager, host) -> None:
        """The button goes with the popup, and a stale press does nothing."""
        calls: list[int] = []
        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL",
            on_check=lambda: calls.append(1),
        )
        frame = manager.persistent_frame
        button = _button_named(frame, CHECK_LABEL)
        button.invoke()
        assert calls == [1]

        manager._on_check(frame)          # the stale callback fires again
        assert calls == [1], "a dismissed popup navigated a second time"
        assert manager.persistent_frame is None

    def test_close_after_check_is_a_harmless_no_op(self, manager, host) -> None:
        """CHECK already dismissed it, so a later CLOSE must do nothing.

        Nothing visible is left to press, but a queued callback could still
        arrive, and it must not reach whatever is on screen by then.
        """
        navigated: list[str] = []
        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL",
            on_check=lambda: navigated.append("alerts"),
        )
        frame = manager.persistent_frame
        _button_named(frame, CHECK_LABEL).invoke()
        assert navigated == ["alerts"]
        assert manager.persistent_frame is None

        manager.close_persistent(frame)
        assert manager.persistent_frame is None

    def test_a_stale_close_cannot_dismiss_the_next_popup(
        self, manager, host
    ) -> None:
        """CHECK on the first must not arm a CLOSE against the second."""
        manager.show_persistent("First", "one", level="CRITICAL",
                                on_check=lambda: None)
        manager.show_persistent("Second", "two", level="CRITICAL")
        first = manager.persistent_frame
        _button_named(first, CHECK_LABEL).invoke()

        second = manager.persistent_frame
        assert second is not None and second is not first

        manager.close_persistent(first)   # the dismissed popup's CLOSE
        assert manager.persistent_frame is second
        assert second.winfo_exists()

    def test_a_failing_navigation_keeps_the_popup_so_it_is_not_lost(
        self, manager, host
    ) -> None:
        """If the screen never opened, throwing the notice away hides it.

        This is why dismissal happens after the action rather than before.
        """
        def explode() -> None:
            raise RuntimeError("navigation failed")

        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL", on_check=explode)
        frame = manager.persistent_frame
        _button_named(frame, CHECK_LABEL).invoke()
        assert manager.persistent_frame is frame
        assert frame.winfo_exists()


# ---------------------------------------------------------------------------
# TEST 8 - review status
# ---------------------------------------------------------------------------
class TestNeitherButtonReviewsTheAlert:
    def test_the_navigation_the_app_wires_up_carries_no_review(self) -> None:
        """What app.py actually passes as on_check."""
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._on_notification_event)
        start = source.index("show_persistent")
        block = source[start:start + 500]
        assert 'self.navigate("alerts")' in block
        for forbidden in ("mark_reviewed", "set_status_for", "review",
                          "resolve", "acknowledge"):
            assert forbidden not in block, (
                f"the notification popup's wiring mentions {forbidden!r}"
            )

    def test_navigation_is_passed_no_arguments(self) -> None:
        """No kwargs means no setter on the screen is driven by the popup."""
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._on_notification_event)
        assert 'self.navigate("alerts")' in source
        assert 'self.navigate("alerts",' not in source


# ---------------------------------------------------------------------------
# TEST 9 - real event data
# ---------------------------------------------------------------------------
class TestItShowsTheEventsOwnData:
    def test_the_passed_strings_are_what_is_displayed(self, manager, host) -> None:
        manager.show_persistent(
            "Possible SYN flood", "1,594 pps from a single source",
            level="ERROR", reference="Traffic anomaly #2247",
            severity="HIGH", is_detection=True,
        )
        texts = _label_texts(manager.persistent_frame)
        assert "Possible SYN flood" in texts
        assert "1,594 pps from a single source" in texts
        assert "Severity Level: HIGH" in texts
        assert "Traffic anomaly #2247" in texts

    def test_the_level_is_never_shown_as_the_severity(
        self, manager, host
    ) -> None:
        """A HIGH detection's notification level is ERROR (it drives the
        sound threshold). That is what put "Notification level: ERROR" on the
        popup; the level must not appear, only the detection's severity.
        """
        manager.show_persistent(
            "HIGH detection", "fixture", level="ERROR",
            severity="HIGH", is_detection=True,
        )
        texts = _label_texts(manager.persistent_frame)
        assert "Severity Level: HIGH" in texts
        assert not any("ERROR" in t for t in texts), texts

    @pytest.mark.parametrize("severity,level", [
        ("HIGH", "ERROR"), ("MEDIUM", "WARNING"), ("LOW", "INFO"),
    ])
    def test_each_severity_is_shown_as_itself(
        self, manager, host, severity, level
    ) -> None:
        manager.show_persistent(
            f"{severity} detection", "fixture", level=level,
            severity=severity, is_detection=True,
        )
        texts = _label_texts(manager.persistent_frame)
        assert f"Severity Level: {severity}" in texts

    def test_a_detection_without_a_severity_says_unknown(
        self, manager, host
    ) -> None:
        manager.show_persistent("detection", "fixture", level="ERROR",
                                is_detection=True)
        texts = _label_texts(manager.persistent_frame)
        assert "Severity Level: UNKNOWN" in texts
        assert not any("ERROR" in t for t in texts), texts

    def test_a_non_detection_notification_has_no_severity_line(
        self, manager, host
    ) -> None:
        manager.show_persistent("Assessment complete", "fixture", level="INFO")
        texts = _label_texts(manager.persistent_frame)
        assert not any(t.startswith("Severity Level") for t in texts)

    def test_nothing_is_added_that_was_not_supplied(self, manager, host) -> None:
        """No invented address, port or timestamp appears."""
        import re

        manager.show_persistent("Detection", "fixture message", level="INFO")
        blob = " ".join(_label_texts(manager.persistent_frame))
        assert not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", blob)
        assert not re.search(r"\d{4}-\d{2}-\d{2}", blob)

    def test_an_absent_reference_shows_no_reference_line(
        self, manager, host
    ) -> None:
        manager.show_persistent("Detection", "fixture", level="INFO")
        texts = _label_texts(manager.persistent_frame)
        assert not any("#" in text for text in texts)

    @pytest.mark.parametrize(
        "kind,reference_id,notification_id,expected",
        [
            ("alert", 318, 5, "Snort alert #318"),
            ("security_alert", 7, 5, "Snort alert #7"),
            ("anomaly", 2334, 7, "Traffic anomaly #2334"),
            # A legacy reference type whose feature was withdrawn: it falls
            # back to the notification id rather than naming the retired
            # concept. See tests/test_threat_incidents_removed.py.
            ("incident", 11, 7, "Notification #7"),
            ("scan", 373, 7, "Assessment #373"),
            ("", None, 512, "Notification #512"),
            ("", None, None, ""),
            ("not_a_real_type", 9, None, ""),
        ],
    )
    def test_the_reference_is_built_only_from_payload_fields(
        self, kind: str, reference_id, notification_id, expected: str
    ) -> None:
        """The reference_type values here are the ones the table holds."""
        from aethra_sec.core.events import NotificationPayload
        from aethra_sec.ui.app import _notification_reference

        payload = NotificationPayload(
            title="t", message="m", reference_type=kind,
            reference_id=reference_id, notification_id=notification_id,
        )
        assert _notification_reference(payload) == expected


# ---------------------------------------------------------------------------
# TEST 10 - several notifications
# ---------------------------------------------------------------------------
class TestSeveralNotifications:
    def test_a_second_one_queues_instead_of_replacing(self, manager, host) -> None:
        assert manager.show_persistent("First", "one", level="CRITICAL") is True
        frame = manager.persistent_frame
        assert manager.show_persistent("Second", "two", level="CRITICAL") is False
        assert manager.persistent_frame is frame, "the open popup was replaced"
        assert "First" in _label_texts(frame)
        assert "Second" not in _label_texts(frame)
        assert manager.pending_count == 1

    def test_the_popup_says_how_many_are_waiting(self, manager, host) -> None:
        manager.show_persistent("First", "one", level="CRITICAL")
        manager.show_persistent("Second", "two", level="CRITICAL")
        manager.show_persistent("Third", "three", level="CRITICAL")
        blob = " ".join(_label_texts(manager.persistent_frame))
        assert "2 more notifications waiting" in blob

    def test_closing_shows_the_next_with_its_own_data(self, manager, host) -> None:
        manager.show_persistent("First", "one", level="CRITICAL")
        manager.show_persistent("Second", "two", level="WARNING",
                                reference="Snort alert #318")
        _button_named(manager.persistent_frame, CLOSE_LABEL).invoke()

        texts = _label_texts(manager.persistent_frame)
        assert "Second" in texts
        assert "two" in texts
        assert "Snort alert #318" in texts
        assert "First" not in texts
        assert manager.pending_count == 0

    def test_each_queued_notification_keeps_its_own_action(
        self, manager, host
    ) -> None:
        seen: list[str] = []
        manager.show_persistent("First", "one", level="CRITICAL",
                                on_check=lambda: seen.append("first"))
        manager.show_persistent("Second", "two", level="CRITICAL",
                                on_check=lambda: seen.append("second"))
        # CHECK dismisses and advances, so the second one's own action is
        # what the next press must run - not the first one's again.
        _button_named(manager.persistent_frame, CHECK_LABEL).invoke()
        _button_named(manager.persistent_frame, CHECK_LABEL).invoke()
        assert seen == ["first", "second"]

    def test_a_flood_does_not_create_unbounded_popups(self, manager, host) -> None:
        for index in range(MAX_PENDING + 25):
            manager.show_persistent(f"Event {index}", "fixture", level="CRITICAL")
        assert manager.persistent_frame is not None
        assert manager.pending_count == MAX_PENDING
        # One on screen, the rest queued - never one window per packet.
        assert len(manager._host.winfo_children()) == 1

    def test_overflow_is_reported_rather_than_hidden(self, manager, host) -> None:
        for index in range(MAX_PENDING + 3):
            manager.show_persistent(f"Event {index}", "fixture", level="CRITICAL")
        blob = " ".join(_label_texts(manager.persistent_frame))
        assert "not queued" in blob
        assert "remain in the notification panel" in blob

    def test_the_transient_eviction_rule_never_reaches_the_popup(
        self, manager, host
    ) -> None:
        """MAX_VISIBLE evicts toasts; it must not evict an unclosed popup."""
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        frame = manager.persistent_frame
        for index in range(toast_module.MAX_VISIBLE + 4):
            manager.show(f"Toast {index}", "fixture", level="INFO")
        assert manager.persistent_frame is frame
        assert frame.winfo_exists()


# ---------------------------------------------------------------------------
# TEST 11 - sound and settings
# ---------------------------------------------------------------------------
class TestSoundAndSettingsAreUntouched:
    def test_the_popup_widget_does_no_audio_io(self) -> None:
        """The popup signals the audio service through hooks; it never plays.

        The siren is tied to the popup lifecycle (present/dismiss hooks) since
        the 16 Oct 2026 stability revision, but the widget must not do audio
        I/O itself - that stays on the audio worker, off the Tk thread.
        """
        source = inspect.getsource(toast_module)
        for forbidden in ("winsound", "playsound", "PlaySound", "mciSendString",
                          "import audio", "audio_alert"):
            assert forbidden not in source, (
                f"the popup module does audio I/O: {forbidden!r}"
            )

    def test_non_detection_sound_runs_before_the_popup(self) -> None:
        """A non-detection system sound is still queued independently, first.

        A detection's sound is the persistent siren, tied to the popup; a
        non-detection notification keeps its single system sound, queued before
        the popup is built so an absent popup cannot lose it.
        """
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._on_notification_event)
        assert "audio.notify(payload)" in source
        assert source.index("audio.notify(payload)") < source.index(
            "show_persistent"
        ), "the non-detection sound now runs after the popup"

    def test_the_popup_is_built_regardless_of_the_audio_service(self) -> None:
        """An absent or silent audio service must never suppress the popup.

        show_persistent is called unconditionally, not inside the audio branch,
        so the detection is always visible even with sound off or failing.
        """
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._on_notification_event)
        popup_call = source.index("self._toasts.show_persistent")
        # The show_persistent call is not nested in an "if audio" guard: the
        # nearest enclosing audio check is the non-detection notify branch,
        # which ends before the popup call.
        audio_block = source[source.index("audio = getattr"):
                             source.index("self.set_status(f\"{title}")]
        assert "show_persistent" not in audio_block

    @pytest.mark.parametrize("key", [
        "notifications.enabled",
        "notifications.min_severity",
        "notifications.sound_enabled",
        "notifications.sound_min_level",
        "notifications.sound_dedup_seconds",
    ])
    def test_every_notification_setting_still_exists(self, key: str) -> None:
        from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY

        assert key in SETTING_SPEC_BY_KEY

    def test_the_visual_popup_does_not_depend_on_sound(self) -> None:
        """Turning sound off must not turn the popup off.

        The popup is raised outside the audio branch, so an absent or silent
        audio service cannot suppress it.
        """
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._on_notification_event)
        guard_indent = popup_indent = None
        for line in source.splitlines():
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped.startswith("if audio is not None"):
                guard_indent = indent
            elif "show_persistent" in stripped and popup_indent is None:
                popup_indent = indent
        assert guard_indent is not None, "the audio guard has gone"
        assert popup_indent is not None, "the popup call has gone"
        # Indented no further than the guard means the popup sits beside the
        # audio branch rather than inside it, so no sound setting - and no
        # missing audio service - can suppress the popup.
        assert popup_indent <= guard_indent, (
            f"the popup is nested inside the audio branch "
            f"(guard at {guard_indent}, popup at {popup_indent})"
        )


# ---------------------------------------------------------------------------
# TEST 12 - navigation regression
# ---------------------------------------------------------------------------
class TestNavigationStillWorks:
    def test_navigating_does_not_close_overlays_that_include_toasts(self) -> None:
        """_close_overlays must stay off the toast manager."""
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._close_overlays)
        assert "_toasts" not in source
        assert "persistent" not in source

    def test_the_popup_is_hosted_above_every_screen_not_inside_one(self) -> None:
        """If it were a child of a screen, changing tabs would destroy it."""
        from aethra_sec.ui import app as app_module

        source = inspect.getsource(app_module.MainWindow._build_layout)
        assert "self._toasts = ToastManager(body, self.fonts)" in source
        assert "ToastManager(self.content" not in source

    def test_the_popup_survives_the_screen_being_repacked(
        self, manager, host, tk_root
    ) -> None:
        """What navigate() does to the screen underneath, done for real."""
        from tkinter import ttk

        screen = ttk.Frame(host)
        screen.pack(fill="both", expand=True)
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        frame = manager.persistent_frame

        screen.pack_forget()                 # navigate() hides the old screen
        other = ttk.Frame(host)
        other.pack(fill="both", expand=True)  # and packs the new one
        _pump(tk_root, 0.15)

        assert manager.persistent_frame is frame
        assert frame.winfo_exists()
        assert float(frame.place_info()["relx"]) == 0.5
        screen.destroy()
        other.destroy()

    def test_no_popup_widget_is_left_behind_after_check(
        self, manager, host
    ) -> None:
        """The widget is destroyed, not merely unplaced."""
        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL", on_check=lambda: None)
        _button_named(manager.persistent_frame, CHECK_LABEL).invoke()
        assert host.winfo_children() == [], "a popup widget survived CHECK"

    def test_check_on_a_queue_leaves_exactly_one_popup(
        self, manager, host
    ) -> None:
        """Advancing the queue must not stack two popups on top of each other."""
        for index in range(4):
            manager.show_persistent(f"Event {index}", "fixture",
                                    level="CRITICAL", on_check=lambda: None)
        _button_named(manager.persistent_frame, CHECK_LABEL).invoke()
        assert len(host.winfo_children()) == 1
        assert manager.pending_count == 2


# ---------------------------------------------------------------------------
# TEST 13 - shutdown
# ---------------------------------------------------------------------------
class TestShutdown:
    def test_clear_takes_down_the_popup_and_the_queue(self, manager, host) -> None:
        manager.show_persistent("First", "one", level="CRITICAL")
        manager.show_persistent("Second", "two", level="CRITICAL")
        manager.show("Transient", "fixture", level="INFO")
        frame = manager.persistent_frame

        manager.clear()

        assert manager.persistent_frame is None
        assert manager.pending_count == 0
        assert not frame.winfo_exists()
        assert manager._toasts == []

    def test_clear_does_not_show_the_queued_ones_on_the_way_out(
        self, manager, host
    ) -> None:
        """The window is going; a fresh popup during teardown is a leak."""
        for index in range(5):
            manager.show_persistent(f"Event {index}", "fixture", level="CRITICAL")
        manager.clear()
        assert manager.persistent_frame is None
        assert host.winfo_children() == []

    def test_a_callback_after_teardown_is_harmless(self, manager, host) -> None:
        """A queued button press must not touch a destroyed widget."""
        manager.show_persistent(
            "Detection", "fixture", level="CRITICAL", on_check=lambda: None)
        frame = manager.persistent_frame
        manager.clear()
        manager._on_check(frame)          # stale CHECK
        manager.close_persistent(frame)   # stale CLOSE
        assert manager.persistent_frame is None

    def test_clear_is_idempotent(self, manager, host) -> None:
        manager.show_persistent("Detection", "fixture", level="CRITICAL")
        manager.clear()
        manager.clear()
        assert manager.persistent_frame is None


class TestEveryLevelHasItsOwnColour:
    """ERROR used to fall through to the informational blue.

    The fallback is silent, so an error-level notification looked
    informational and nothing complained. On a centred popup that is a
    statement about severity, so every level the service can raise is
    checked here.
    """

    def test_no_level_falls_back_to_the_informational_colour(self) -> None:
        from aethra_sec.models.enums import NotificationLevel
        from aethra_sec.ui.widgets.toast import LEVEL_COLOURS

        missing = [
            str(level) for level in NotificationLevel
            if str(level).upper() not in LEVEL_COLOURS
        ]
        assert not missing, f"no colour for {missing}; they would read as INFO"

    def test_error_is_not_drawn_as_information(self) -> None:
        from aethra_sec.ui.theme import PALETTE
        from aethra_sec.ui.widgets.toast import LEVEL_COLOURS

        assert LEVEL_COLOURS["ERROR"] != PALETTE.info

    def test_the_popup_uses_that_colour(self, manager, host) -> None:
        from aethra_sec.ui.widgets.toast import LEVEL_COLOURS

        manager.show_persistent("Subsystem fault", "fixture", level="ERROR")
        frame = manager.persistent_frame
        # Only the accent stripe is a tk.Frame; a ttk.Frame has no
        # -background option at all, so the lookup has to be guarded.
        stripes = []
        for child in frame.winfo_children():
            try:
                background = str(child.cget("background") or "")
            except Exception:  # noqa: BLE001 - ttk widgets have no background
                continue
            if background == LEVEL_COLOURS["ERROR"]:
                stripes.append(child)
        assert stripes, "the ERROR colour did not reach the popup"
