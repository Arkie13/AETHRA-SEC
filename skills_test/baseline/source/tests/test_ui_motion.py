"""Reduced-motion and the active-state status pulse.

Subtle animation is a real feature of the console, but it must be (a) reserved
for genuinely active states, so motion on a status dot *means* something, and
(b) switchable off in one place, so an operator who wants a still interface -
or finds motion distracting during an incident - gets one, with the value still
updating underneath.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from aethra_sec.ui import theme

ROOT = Path(__file__).resolve().parent.parent
CHIPS = ROOT / "aethra_sec" / "ui" / "widgets" / "chips.py"
CARDS = ROOT / "aethra_sec" / "ui" / "widgets" / "cards.py"
DRAWER = ROOT / "aethra_sec" / "ui" / "widgets" / "drawer.py"
APP = ROOT / "aethra_sec" / "ui" / "app.py"


class TestTheMotionSwitch:
    def teardown_method(self) -> None:
        theme.set_motion(True)  # never leak a disabled state into other tests

    def test_motion_is_on_by_default(self) -> None:
        assert theme.motion_enabled() is True

    def test_it_can_be_turned_off_and_on(self) -> None:
        theme.set_motion(False)
        assert theme.motion_enabled() is False
        theme.set_motion(True)
        assert theme.motion_enabled() is True


class TestOnlyActiveStatesPulse:
    def test_live_states_are_active(self) -> None:
        for state in ("RUNNING", "CAPTURING", "CONNECTED", "AVAILABLE", "SCANNING"):
            assert theme.is_active_state(state), state

    def test_stopped_states_are_not(self) -> None:
        for state in ("STOPPED", "OFFLINE", "ERROR", "UNKNOWN", "DISABLED", ""):
            assert not theme.is_active_state(state), state

    def test_the_dot_only_breathes_it_never_vanishes(self) -> None:
        """The pulse dims toward the surface but keeps the colour readable."""
        full = theme.pulse_colour("#40C4AA", 1.0)
        dim = theme.pulse_colour("#40C4AA", 0.0)
        assert full == "#40C4AA"
        assert dim != theme.PALETTE.surface, "the dot faded all the way out"
        assert dim != full, "there was no visible pulse"


class TestReducedMotionIsRespectedEverywhere:
    """Every animation consults the one switch, so 'reduce motion' is global."""

    def test_the_status_dot_pulse_is_gated(self) -> None:
        src = CHIPS.read_text(encoding="utf-8")
        # The pulse frame checks the switch and settles solid when off.
        assert "if not motion_enabled():" in src
        pulse = inspect.getsource(
            __import__("aethra_sec.ui.widgets.chips", fromlist=["Chip"]).Chip._redraw
        )
        assert "motion_enabled()" in pulse

    def test_the_kpi_flash_is_gated(self) -> None:
        from aethra_sec.ui.widgets.cards import StatCard

        src = inspect.getsource(StatCard.update_value)
        assert "motion_enabled()" in src, "the tile flashes even in reduced motion"

    def test_the_drawer_slide_is_gated(self) -> None:
        drawer_src = DRAWER.read_text(encoding="utf-8")
        assert "if motion_enabled():" in drawer_src
        assert "self._animate(step=0)" in drawer_src


class TestActiveStatesDrivePulsing:
    """A live probe result makes the dot pulse; a stopped one stops it."""

    def test_status_chip_pulses_on_active_state(self) -> None:
        from aethra_sec.ui.widgets import chips

        update = inspect.getsource(chips.StatusChip.update_state)
        assert "set_pulsing(is_active_state(state))" in update

    def test_the_rail_pulses_active_indicators(self) -> None:
        from aethra_sec.ui.widgets import chips

        apply = inspect.getsource(chips.StatusRail._apply)
        assert "set_pulsing(is_active_state(state))" in apply


class TestThePreferenceIsWiredAndPersisted:
    def test_startup_applies_the_stored_preference(self) -> None:
        init = inspect.getsource(
            __import__("aethra_sec.ui.app", fromlist=["MainWindow"]).MainWindow.__init__
        )
        assert "set_motion(not self.state.get_bool(KEY_REDUCED_MOTION" in init

    def test_the_toggle_persists_and_applies(self) -> None:
        toggle = inspect.getsource(
            __import__("aethra_sec.ui.app", fromlist=["MainWindow"]).MainWindow
            ._toggle_motion
        )
        assert "set_motion(" in toggle
        assert "KEY_REDUCED_MOTION" in toggle
        assert "self.state.save()" in toggle


class TestChipTeardownStopsTheTimer:
    """A pulsing chip that is destroyed must cancel its timer (§16 - no leak)."""

    def test_destroy_cancels_the_pulse(self) -> None:
        from aethra_sec.ui.widgets import chips

        destroy = inspect.getsource(chips.Chip._on_destroy)
        assert "_stop_pulse" in destroy
        # And a Destroy binding exists so it actually runs.
        assert '"<Destroy>"' in CHIPS.read_text(encoding="utf-8")
