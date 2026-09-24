"""Live Monitoring capture lifecycle (§37).

Opening Live Monitoring must start a real capture without the operator
pressing anything, and must do so through the same code path the Start button
uses. These pin the guards that make that safe: no duplicate readers when the
screen is revisited, and an explicit Stop that navigation cannot undo.
"""

from __future__ import annotations

from typing import Any

import pytest

from aethra_sec.ui.screens.traffic import TrafficScreen


class _Statistics:
    """Just the part of the capture statistics the lifecycle reads."""

    def __init__(self, running: bool = False, interface: str = "") -> None:
        self.is_running = running
        self.interface = interface


class _Capture:
    """A capture service that records what it was asked to do."""

    def __init__(self, running: bool = False) -> None:
        self._stats = _Statistics(running)
        self.starts: list[str] = []

    def statistics(self) -> _Statistics:
        return self._stats


class _Screen:
    """The lifecycle methods under test, without a Tk window.

    Bound from the real class so the behaviour tested is the shipped
    behaviour, not a copy of it.
    """

    _maybe_autostart = TrafficScreen._maybe_autostart
    _start_capture = TrafficScreen._start_capture

    def __init__(self, capture: Any, *, running: bool = False) -> None:
        self.context = type("Ctx", (), {"capture": capture})()
        self.session = object()
        self._capture = capture
        self._starting = False
        self._stopping = False
        self._stopped_by_operator = False
        self._selected = r"\Device\NPF_{ABC}"
        self.began: list[tuple[str, bool]] = []
        self.state_updates = 0
        self.errors: list[str] = []
        self._permitted = True

    # -- collaborators the lifecycle calls -----------------------------
    def _begin_capture(self, interface: str, *, announce: bool) -> None:
        self.began.append((interface, announce))

    def _selected_interface(self) -> str:
        return self._selected

    def _update_capture_state(self) -> None:
        self.state_updates += 1

    def can(self, _permission: str) -> bool:
        return self._permitted

    def show_error_message(self, message: str, _title: str = "") -> None:
        self.errors.append(message)


class TestAutomaticStart:
    """Opening the screen starts a capture; nothing needs to be pressed."""

    def test_an_idle_screen_starts_capturing(self) -> None:
        screen = _Screen(_Capture(running=False))
        screen._maybe_autostart()
        assert screen.began == [(r"\Device\NPF_{ABC}", False)]

    def test_the_automatic_start_does_not_raise_a_dialog(self) -> None:
        """An unattended failure belongs on the screen, not in a modal."""
        screen = _Screen(_Capture(running=False))
        screen._maybe_autostart()
        _interface, announce = screen.began[0]
        assert announce is False

    def test_it_uses_the_same_entry_point_as_the_button(self) -> None:
        """One canonical start: both routes call _begin_capture."""
        automatic = _Screen(_Capture(running=False))
        automatic._maybe_autostart()

        manual = _Screen(_Capture(running=False))
        manual._start_capture()

        assert automatic.began[0][0] == manual.began[0][0]

    def test_no_interface_means_no_start(self) -> None:
        screen = _Screen(_Capture(running=False))
        screen._selected = ""
        screen._maybe_autostart()
        assert screen.began == []

    def test_it_declines_without_the_control_permission(self) -> None:
        screen = _Screen(_Capture(running=False))
        screen._permitted = False
        screen._maybe_autostart()
        assert screen.began == []


class TestNoDuplicateCaptures:
    """Revisiting the screen must reuse the reader, never spawn a second."""

    def test_a_running_capture_is_adopted_not_restarted(self) -> None:
        screen = _Screen(_Capture(running=True))
        screen._maybe_autostart()
        assert screen.began == []
        # It still refreshes the controls so the screen shows the live state.
        assert screen.state_updates == 1

    def test_a_start_already_in_flight_is_not_repeated(self) -> None:
        """The window before TShark is up is where a duplicate would spawn."""
        screen = _Screen(_Capture(running=False))
        screen._starting = True
        screen._maybe_autostart()
        assert screen.began == []

    def test_repeated_visits_start_at_most_one_capture(self) -> None:
        capture = _Capture(running=False)
        screen = _Screen(capture)

        screen._maybe_autostart()          # first visit starts it
        capture._stats.is_running = True   # the reader is now up
        for _ in range(5):                 # navigating back and forth
            screen._maybe_autostart()

        assert len(screen.began) == 1


class TestStopIsRespected:
    """Stop is a decision, not a pause."""

    def test_navigation_does_not_restart_a_stopped_capture(self) -> None:
        screen = _Screen(_Capture(running=False))
        screen._stopped_by_operator = True
        screen._maybe_autostart()
        assert screen.began == []

    def test_pressing_start_clears_the_latch(self) -> None:
        """Start is the operator taking the decision back."""
        screen = _Screen(_Capture(running=False))
        screen._stopped_by_operator = True
        screen._start_capture()
        assert screen._stopped_by_operator is False
        assert screen.began == [(r"\Device\NPF_{ABC}", True)]

    def test_the_button_start_announces_failures(self) -> None:
        """An operator who pressed Start is waiting for an answer."""
        screen = _Screen(_Capture(running=False))
        screen._start_capture()
        _interface, announce = screen.began[0]
        assert announce is True

    def test_pressing_start_without_an_interface_explains_why(self) -> None:
        screen = _Screen(_Capture(running=False))
        screen._selected = ""
        screen._start_capture()
        assert screen.began == []
        assert screen.errors and "interface" in screen.errors[0].lower()
