"""The console redesign: what the interface promises an operator.

Styling is not pinned here - colours and paddings are meant to be tuned. What
is pinned is behaviour a user would notice the loss of:

* no control is ever clipped out of reach on a narrow window; a bar that runs
  out of room wraps, and a caption stays with the field it names;
* a hint may be dropped to save the data beside it, but data never is;
* a critical row is findable by its band, and the band is not overwritten by
  the zebra stripe underneath it;
* the dashboard separates what happened during the reporting period from
  where things stand now, and the header carries a real search field.

The widgets need a display, so the layout arithmetic is exercised directly and
the structural facts are read from the source, as the other UI suites do.
"""

from __future__ import annotations

import inspect
import tkinter as tk

from aethra_sec.ui import app as app_module
from aethra_sec.ui.screens import alerts as alerts_module
from aethra_sec.ui.screens import dashboard as dashboard_module
from aethra_sec.ui.screens import hosts as hosts_module
from aethra_sec.ui.screens import logs as logs_module
from aethra_sec.ui.screens import vulnerabilities as vulnerabilities_module
from aethra_sec.ui.theme import PALETTE
from aethra_sec.ui import theme as theme_module
from aethra_sec.ui.widgets import cards as cards_module
from aethra_sec.ui.widgets import tables as tables_module
from aethra_sec.ui.widgets.cards import (
    ControlBar,
    FilterBar,
    Toolbar,
    parse_pad,
    wrap_controls,
)

#: Screens whose filter row must wrap rather than clip.
FILTERED_SCREENS = (
    alerts_module,
    hosts_module,
    logs_module,
    vulnerabilities_module,
)


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------
class TestPadNormalisation:
    """``pack_info`` returns padding in whichever shape it was given."""

    def test_a_single_number_pads_both_sides(self) -> None:
        """Tk's own reading of ``padx=6``."""
        assert parse_pad(6) == (6, 6)
        assert parse_pad("6") == (6, 6)

    def test_a_pair_is_kept_as_given(self) -> None:
        """Leading and trailing padding differ on most of our controls."""
        assert parse_pad((8, 14)) == (8, 14)
        assert parse_pad("8 14") == (8, 14)

    def test_nothing_measures_as_nothing(self) -> None:
        """An unset pad must not be read as a pixel."""
        assert parse_pad("") == (0, 0)
        assert parse_pad(()) == (0, 0)

    def test_an_unmeasurable_unit_is_not_guessed_at(self) -> None:
        """A pad given in millimetres is counted as zero, never as 2px."""
        assert parse_pad("2m") == (0, 0)


# ---------------------------------------------------------------------------
# Wrapping
# ---------------------------------------------------------------------------
class TestControlWrapping:
    """The arithmetic behind a bar that never clips."""

    def test_controls_that_fit_stay_on_one_line(self) -> None:
        """Wrapping must not cost a line the bar did not need."""
        assert wrap_controls([100, 100, 100], available=400) == [[0, 1, 2]]

    def test_controls_that_do_not_fit_wrap(self) -> None:
        """The overflow moves down instead of off the edge."""
        assert wrap_controls([100, 100, 100], available=250) == [[0, 1], [2]]

    def test_a_pinned_control_is_measured_before_the_rest(self) -> None:
        """The record count keeps its width; the actions wrap around it."""
        assert wrap_controls([100, 100], available=250, reserved=100) == [[0], [1]]

    def test_a_reserved_width_only_costs_the_first_line(self) -> None:
        """Nothing is pinned to the right of a wrapped line."""
        lines = wrap_controls([100, 100, 100, 100], available=250, reserved=100)
        assert lines == [[0], [1, 2], [3]]

    def test_a_caption_travels_with_the_field_it_names(self) -> None:
        """"Period" must not be stranded above its own menu."""
        lines = wrap_controls(
            [100, 100, 40, 120],
            available=250,
            captions=[False, False, True, False],
        )
        assert lines == [[0, 1], [2, 3]]

    def test_a_caption_is_carried_down_from_the_end_of_a_full_line(self) -> None:
        """It fitted, but the field it names did not, so both move."""
        lines = wrap_controls(
            [200, 40, 200], available=250, captions=[False, True, False]
        )
        assert lines == [[0], [1, 2]]

    def test_a_line_is_never_emptied_to_carry_a_caption(self) -> None:
        """A caption alone on its line stays there rather than looping down."""
        lines = wrap_controls([40, 240], available=250, captions=[True, False])
        assert lines == [[0], [1]]

    def test_a_control_wider_than_the_bar_is_still_placed(self) -> None:
        """Dropping it would put an action out of reach entirely."""
        assert wrap_controls([900], available=250) == [[0]]

    def test_every_control_is_placed_exactly_once_and_in_order(self) -> None:
        """The bar reorders nothing and loses nothing."""
        widths = [90, 140, 60, 200, 45, 130, 70]
        for available in (80, 150, 260, 400, 2000):
            placed = [index for line in wrap_controls(widths, available) for index in line]
            assert placed == list(range(len(widths)))


class TestControlBar:
    """What the bar itself guarantees."""

    def test_both_bars_share_the_one_layout(self) -> None:
        """Actions and filters wrap by the same rule, so they look alike."""
        assert issubclass(Toolbar, ControlBar)
        assert issubclass(FilterBar, ControlBar)

    def test_a_screens_own_controls_are_adopted(self) -> None:
        """A filter row becomes a wrapping bar by changing its class alone."""
        source = inspect.getsource(ControlBar._adopt_strays)
        assert "self.pack_slaves()" in source
        assert "slave.pack_info()" in source

    def test_an_adopted_control_keeps_its_spacing(self) -> None:
        """Adopting a row must not re-space the screen that built it."""
        source = inspect.getsource(ControlBar._adopt_strays)
        assert 'parse_pad(info.get("padx", 0))' in source

    def test_optional_controls_give_way_before_data_does(self) -> None:
        """A keyboard hint is worth less than the row count beside it."""
        source = inspect.getsource(ControlBar._relayout)
        assert "entry.optional" in source
        assert "pack_forget()" in source

    def test_a_wrapped_control_is_raised_above_its_line(self) -> None:
        """Otherwise the line frame paints over the control inside it."""
        assert "lift(line)" in inspect.getsource(ControlBar._relayout)

    def test_an_unmapped_bar_reports_its_natural_size(self) -> None:
        """A bar packed without fill would otherwise never get a width."""
        source = inspect.getsource(ControlBar._relayout)
        assert "single_line = width <= 1" in source


class TestScreensUseTheWrappingBars:
    """Every filter row in the console wraps."""

    def test_no_screen_builds_a_filter_row_from_a_plain_frame(self) -> None:
        """A plain frame clips; that is the bug this replaced."""
        for module in FILTERED_SCREENS:
            source = inspect.getsource(module)
            assert "FilterBar(" in source, module.__name__
            assert 'row = ttk.Frame(' not in source, module.__name__

    def test_a_tables_own_bars_wrap_too(self) -> None:
        """The quick filter, the column picker, the count and the hint."""
        source = inspect.getsource(tables_module.DataTable.__init__)
        assert "self._footer = ControlBar(" in source
        assert 'self._footer.add(self._hint, side="right", optional=True)' in source
        assert "self._toolbar = ControlBar(" in inspect.getsource(
            tables_module.DataTable._build_toolbar
        )


# ---------------------------------------------------------------------------
# Severity banding
# ---------------------------------------------------------------------------
class TestSeverityBanding:
    """A critical row is findable without reading a word."""

    def test_priority_follows_the_order_the_tags_are_configured_in(self) -> None:
        """Tk settles a clash by configuration order, not by the item's tags.

        The stripe is declared last on purpose: declared first, as it once
        was, it silently overwrote every severity band.
        """
        source = inspect.getsource(tables_module.DataTable.__init__)
        hover = source.index('tag_configure("hover"')
        severity = source.index('"sev_critical"')
        stripe = source.index('tag_configure("odd"')
        assert hover < severity < stripe

    def test_only_the_severities_worth_navigating_by_are_banded(self) -> None:
        """A band on most rows would be a band on none of them."""
        source = inspect.getsource(tables_module.DataTable.__init__)
        assert "PALETTE.critical_soft" in source
        assert "PALETTE.high_soft" in source
        assert '("sev_medium", PALETTE.medium, "")' in source

    def test_the_palette_carries_a_fill_for_exactly_those_two(self) -> None:
        """An unused fill is an invitation to band something that should not be."""
        fills = [name for name in vars(PALETTE) if name.endswith("_soft")]
        assert sorted(fills) == ["accent_soft", "critical_soft", "high_soft"]

    def test_a_band_is_darker_than_the_text_it_sits_under(self) -> None:
        """The row is a hint; the text stays the thing being read."""
        for fill, colour in (
            (PALETTE.critical_soft, PALETTE.critical),
            (PALETTE.high_soft, PALETTE.high),
        ):
            assert _luminance(fill) < _luminance(colour)


def _luminance(colour: str) -> int:
    """Rough brightness of a ``#rrggbb`` colour, for ordering only."""
    red, green, blue = (int(colour[index:index + 2], 16) for index in (1, 3, 5))
    return red * 2 + green * 3 + blue


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------
class TestDashboardZones:
    """The dashboard is read in a fixed order, so it is built in one."""

    def test_the_zones_are_titled_and_ordered(self) -> None:
        """Period activity, then current state, then live traffic, then
        events, then the subsystems.

        "SECURITY OVERVIEW" was one band mixing period figures with
        current-state ones. Packets-today and open-findings look identical in
        a row of tiles but behave oppositely at midnight, so they are now two
        zones and the first two headings come from ``_build_stat_row``.
        """
        build = inspect.getsource(dashboard_module.DashboardScreen.build)
        strip = inspect.getsource(dashboard_module.DashboardScreen._build_stat_row)
        assert strip.index('"PERIOD ACTIVITY"') < strip.index(
            '"CURRENT SECURITY STATE"'
        )
        assert "_build_stat_row" in build
        positions = [
            build.index(title)
            for title in (
                '"LIVE MONITORING"',
                '"SECURITY EVENTS"',
                '"SYSTEM STATUS"',
            )
        ]
        assert positions == sorted(positions)
        assert build.index("_build_stat_row") < positions[0]

    def test_every_status_tile_reports_a_real_probe(self) -> None:
        """The zone note says so, and the screen must not make it a lie."""
        source = inspect.getsource(dashboard_module.DashboardScreen.build)
        assert "every indicator is a real probe result" in source


class TestConsoleHeader:
    """The header is where an operator starts, so it carries the search."""

    def test_the_header_has_a_real_search_field(self) -> None:
        """Not a button that opens one - a field that already has the focus."""
        source = inspect.getsource(app_module.MainWindow._build_layout)
        assert "Search.TEntry" in source
        assert "Ctrl+K" in source

    def test_typing_in_it_carries_the_text_into_the_palette(self) -> None:
        """Retyping a query to search it would be the wrong kind of surprise."""
        source = inspect.getsource(app_module.MainWindow._on_search_typed)
        assert "self._palette.set_query(" in source

    def test_the_signed_in_identity_is_shown_with_its_role(self) -> None:
        """Which account is acting is a security question, not a decoration."""
        source = inspect.getsource(app_module.MainWindow._build_layout)
        assert "RoleBadge.TLabel" in source


class TestPanels:
    """Every panel is findable by its own edge."""

    def test_a_section_draws_no_box_around_its_content(self) -> None:
        """A section is a label and a rule, not a filled outlined rectangle.

        This previously asserted the opposite - that a card painted a rounded,
        filled surface. That box, repeated around every group on every screen,
        was the thing that made the console read as a stack of rectangles, and
        it is what the redesign removes. What is pinned now is the absence:
        a section paints a hairline under its own header and nothing else.
        """
        assert issubclass(cards_module.Card, tk.Canvas)
        source = inspect.getsource(cards_module.Card._redraw)
        assert "rounded_rectangle(" not in source, "a section must not fill a box"
        assert "create_line(" in source, "a section is separated by a rule"
        init = inspect.getsource(cards_module.Card.__init__)
        assert "CardTitle.TLabel" in init
        # The section's own frame takes the page colour rather than a fill.
        assert "self._fill = self._page" in init

    def test_a_cards_children_are_moved_into_its_padded_body(self) -> None:
        """Otherwise they would sit on the rounded corners, unpadded.

        Screens still parent their widgets to the card, so this is what keeps
        69 call sites working unchanged.
        """
        source = inspect.getsource(cards_module.Card._adopt)
        assert "pack_slaves()" in source
        assert "in_=self.body" in source

    def test_adoption_keeps_the_options_the_screen_chose(self) -> None:
        """A child packed side="left" must not come back stacked."""
        source = inspect.getsource(cards_module.Card._adopt)
        assert "pack_info()" in source
        assert 'info.pop("in", None)' in source

    def test_a_stat_tile_carries_its_severity_on_its_edge(self) -> None:
        """Colour on the number alone is lost at a glance across a row."""
        source = inspect.getsource(cards_module.StatCard.__init__)
        # A tile is one of the few things that IS an object, so unlike a
        # section it keeps a surface fill - Tile.* rather than the page.
        assert 'style="Tile.TFrame"' in source
        assert 'self._bar.pack(side="left", fill="y")' in source

    def test_a_tile_keeps_a_fill_while_a_section_does_not(self) -> None:
        """The one distinction the whole visual language rests on.

        Sections group and therefore recede; tiles are objects and therefore
        read as surfaces. If both took the same background the screen would
        flatten into an undifferentiated field.
        """
        from aethra_sec.ui.theme import PALETTE

        assert PALETTE.surface != PALETTE.background
        theme_source = inspect.getsource(theme_module.apply_theme)
        assert 'style.configure("Card.TFrame", background=p.background' in theme_source
        assert 'style.configure("Tile.TFrame", background=p.surface' in theme_source
