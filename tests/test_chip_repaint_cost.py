"""The header chips and sidebar badges repaint only when something changed.

The console repaints the whole status strip and every sidebar badge on each UI
tick, deliberately, so the header is correct even before the first status
change is published. That is fine as long as repainting what is already on
screen is free. It was not.

Measured on this machine with capture running, on the Tk thread, per tick:

    MainWindow._tick            mean 847 ms   worst 1,701 ms
      _refresh_status_strip     mean 568 ms   worst 1,128 ms
      _refresh_nav_badges       mean 113 ms

The interface froze for over a second, recovered, and froze again on the next
tick - which is exactly how it was reported. The data behind the chips was not
the cost: ``HealthService.statuses`` measured 0.01 ms, because it is cached.
The cost was the painting, and almost every paint was redundant.

Two things were wrong, and both are held here:

* ``set_text``/``set_value``/``set_count`` repainted unconditionally, even when
  asked for the value already displayed;
* every repaint built a throwaway ``tkinter.font.Font`` to measure its text,
  and each one allocates a Tcl command that Tk must later reclaim.

After both: ``_refresh_status_strip`` 0.07 ms, ``_tick`` 164 ms, and the
Dashboard's tick fell from 680 ms to 6 ms.

The guards have one sharp edge, so it is tested: ``CountBadge.set_surface``
repaints by re-asking for the count it already has, which the guard would
otherwise swallow, leaving a badge painted on the wrong background.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.ui.widgets import chips


@pytest.fixture
def tk_root():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - headless
        pytest.skip(f"no display: {exc}")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:  # noqa: BLE001
        pass


class _CountingChip(chips.StatusChip):
    """A chip that records how often it actually repainted."""

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        self.redraws = 0
        super().__init__(*args, **kwargs)

    def _redraw(self) -> None:  # noqa: D102
        self.redraws += 1
        super()._redraw()


# ---------------------------------------------------------------------------
# Repaint only on a real change
# ---------------------------------------------------------------------------
class TestTheChipSkipsRedundantPaints:
    def test_setting_the_same_text_does_not_repaint(self, tk_root) -> None:  # noqa: ANN001
        chip = _CountingChip(tk_root, label="DB")
        chip.set_text("DB CONNECTED")
        chip.redraws = 0
        for _ in range(50):
            chip.set_text("DB CONNECTED")
        assert chip.redraws == 0, (
            "the status strip asks for the value already shown on every tick; "
            "repainting it anyway is what froze the interface"
        )

    def test_a_changed_text_does_repaint(self, tk_root) -> None:  # noqa: ANN001
        chip = _CountingChip(tk_root, label="DB")
        chip.set_text("DB CONNECTED")
        chip.redraws = 0
        chip.set_text("DB OFFLINE")
        assert chip.redraws == 1

    def test_a_changed_colour_alone_repaints(self, tk_root) -> None:  # noqa: ANN001
        chip = _CountingChip(tk_root, label="SNORT")
        chip.set_text("SNORT CONNECTED")
        chip.redraws = 0
        chip.set_text("SNORT CONNECTED", colour="#ff0000")
        assert chip.redraws == 1

    def test_set_value_is_guarded_too(self, tk_root) -> None:  # noqa: ANN001
        chip = _CountingChip(tk_root, label="CAPTURE")
        chip.set_value("CAPTURE IDLE")
        chip.redraws = 0
        for _ in range(20):
            chip.set_value("CAPTURE IDLE")
        assert chip.redraws == 0
        chip.set_value("CAPTURE CAPTURING")
        assert chip.redraws == 1


class TestTheBadgeSkipsRedundantPaints:
    def test_the_same_count_does_not_repaint(self, tk_root) -> None:  # noqa: ANN001
        badge = chips.CountBadge(tk_root)
        badge.set_count(6)
        calls = []
        original = badge.delete
        badge.delete = lambda *a, **k: (calls.append(1), original(*a, **k))[1]  # type: ignore[method-assign]
        for _ in range(50):
            badge.set_count(6)
        assert calls == [], "the sidebar badges are refreshed on every tick"

    def test_a_changed_count_repaints(self, tk_root) -> None:  # noqa: ANN001
        badge = chips.CountBadge(tk_root)
        badge.set_count(6)
        calls = []
        original = badge.delete
        badge.delete = lambda *a, **k: (calls.append(1), original(*a, **k))[1]  # type: ignore[method-assign]
        badge.set_count(7)
        assert len(calls) == 1

    def test_the_first_zero_still_paints(self, tk_root) -> None:
        """The zero is what hides the badge, so it must not be skipped."""
        badge = chips.CountBadge(tk_root)
        assert badge._count == -1, (  # noqa: SLF001
            "a sentinel is needed so the first paint always happens"
        )
        badge.set_count(0)
        assert badge._count == 0  # noqa: SLF001

    def test_changing_the_ground_forces_a_repaint(self, tk_root) -> None:  # noqa: ANN001
        """set_surface repaints by re-asking for the count it already has.

        Without a force path the guard swallows it and the badge keeps the old
        background - a coloured square on the selected sidebar row.
        """
        badge = chips.CountBadge(tk_root, surface="#101010")
        badge.set_count(4)
        calls = []
        original = badge.delete
        badge.delete = lambda *a, **k: (calls.append(1), original(*a, **k))[1]  # type: ignore[method-assign]
        badge.set_surface("#202020")
        assert len(calls) == 1, "the badge did not repaint on its new ground"

    def test_set_surface_passes_force(self) -> None:
        body = inspect.getsource(chips.CountBadge.set_surface)
        assert "force=True" in body


# ---------------------------------------------------------------------------
# The measuring font is built once
# ---------------------------------------------------------------------------
class TestTheFontIsNotRebuiltPerPaint:
    def test_the_chip_caches_its_measurer(self, tk_root) -> None:  # noqa: ANN001
        chip = chips.StatusChip(tk_root, label="DB")
        chip.set_text("two")
        first = chip._measurer  # noqa: SLF001
        assert first is not None
        for index in range(10):
            chip.set_text(f"value {index}")
        assert chip._measurer is first, (  # noqa: SLF001
            "a font per paint allocates a Tcl command each time"
        )

    def test_the_badge_caches_its_measurer(self, tk_root) -> None:  # noqa: ANN001
        badge = chips.CountBadge(tk_root)
        badge.set_count(1)
        first = badge._measurer  # noqa: SLF001
        assert first is not None
        for value in range(2, 12):
            badge.set_count(value)
        assert badge._measurer is first  # noqa: SLF001

    def test_no_font_is_constructed_in_the_paint_path(self) -> None:
        """The construction must sit behind the cache, not before it."""
        for method in (chips.Chip._measure, chips.CountBadge.set_count):
            body = inspect.getsource(method)
            if "tkfont.Font(" not in body:
                continue
            cached = body.index("self._measurer")
            built = body.index("tkfont.Font(")
            assert cached < built, (
                f"{method.__qualname__} builds a font before checking the cache"
            )


# ---------------------------------------------------------------------------
# The assessment refresh follows the work, not the clock
# ---------------------------------------------------------------------------
class TestTheAssessmentRefreshCadence:
    def test_it_slows_down_when_nothing_is_queued_or_scanning(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        assert (
            VulnerabilitiesScreen.AUTOMATION_IDLE_REFRESH_SECONDS
            > VulnerabilitiesScreen.AUTOMATION_REFRESH_SECONDS
        )

    def test_the_interval_is_chosen_from_the_summary(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen._automation_interval)
        assert "queued" in body and "scanning" in body

    def test_the_tick_uses_the_chosen_interval(self) -> None:
        from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

        body = inspect.getsource(VulnerabilitiesScreen.on_tick)
        assert "_automation_interval()" in body, (
            "a fixed interval cannot back off when there is nothing to watch"
        )
