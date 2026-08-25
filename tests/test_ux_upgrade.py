"""The investigation experience added on top of v1.0.0.

What is pinned here is behaviour an analyst depends on, not styling:

* the drawer answers "what is this device?" in place, and lets go of the page
  the way an operator expects - ✕, Esc, or a click outside;
* the drawer's content is shaped from stored records only, and says so plainly
  where a record holds nothing;
* the palette reaches real hosts, incidents and alerts, through the services,
  under the session's own permissions;
* the dashboard's time range is passed to the query rather than filtered in
  the interface, and a range the data cannot cover is not offered;
* a table's quick filter narrows *with* the screen's filters, never instead of
  them, and hiding a column never discards its data.

The widgets need a display, so the structural facts are read from the source
the way the sign-out and bug-fix suites do; everything callable is called.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.models.enums import HostStatus, RiskLevel
from aethra_sec.models.host import Host
from aethra_sec.models.scan import PortResult, ScanFinding, ScanHostResult
from aethra_sec.ui import app as app_module
from aethra_sec.ui import base as base_module
from aethra_sec.ui import detail_panels
from aethra_sec.ui.screens import dashboard as dashboard_module
from aethra_sec.ui.screens import hosts as hosts_module
from aethra_sec.ui.screens import incidents as incidents_module
from aethra_sec.ui.screens import vulnerabilities as vulnerabilities_module
from aethra_sec.ui.widgets import drawer as drawer_module
from aethra_sec.ui.widgets import palette as palette_module
from aethra_sec.ui.widgets import tables as tables_module
from aethra_sec.ui.widgets.drawer import DrawerSection


def _host(**overrides: object) -> Host:
    """A host record with sensible defaults for the fields under test."""
    fields: dict[str, object] = {
        "id": 3,
        "ip_address": "10.0.0.9",
        "hostname": "db01",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "vendor": "Dell",
        "os_name": "Debian",
        "os_accuracy": 96,
        "status": HostStatus.UP,
        "risk_level": RiskLevel.HIGH,
    }
    fields.update(overrides)
    return Host(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The details drawer
# ---------------------------------------------------------------------------
class TestDrawerDismissal:
    """Every way an operator expects to get rid of a panel."""

    def test_a_close_button_exists(self) -> None:
        """The ✕ is the one dismissal that needs no prior knowledge."""
        source = inspect.getsource(drawer_module.DetailDrawer.__init__)
        assert 'text="✕"' in source
        assert "command=self.close" in source

    def test_escape_closes_it(self) -> None:
        """Bound on the toplevel, so Esc works wherever the focus is."""
        source = inspect.getsource(drawer_module.DetailDrawer._bind_dismissals)
        assert '"<Escape>"' in source
        source = inspect.getsource(drawer_module.DetailDrawer._on_escape)
        assert "self.close()" in source

    def test_escape_passes_through_when_closed(self) -> None:
        """A closed drawer must not eat Esc from the palette or a dialog."""
        source = inspect.getsource(drawer_module.DetailDrawer._on_escape)
        assert "if not self._open:" in source
        assert "return None" in source

    def test_clicking_the_page_behind_closes_it(self) -> None:
        """But clicking inside the drawer does not."""
        source = inspect.getsource(drawer_module.DetailDrawer._on_click_outside)
        assert "path.startswith(str(self))" in source
        assert "self.close()" in source

    def test_closing_releases_the_page_binding(self) -> None:
        """The page must not keep a dead click handler once the drawer is gone."""
        source = inspect.getsource(drawer_module.DetailDrawer.close)
        assert "unbind" in source
        assert "place_forget()" in source

    def test_leaving_a_screen_closes_its_drawer(self) -> None:
        """A drawer must never outlive the page it belongs to."""
        for module, screen in (
            (hosts_module, "HostsScreen"),
            (incidents_module, "IncidentsScreen"),
            (vulnerabilities_module, "VulnerabilitiesScreen"),
        ):
            source = inspect.getsource(getattr(module, screen).on_hide)
            assert "self._drawer.close()" in source


class TestDrawerContent:
    """The drawer shows stored records, and admits what is not stored."""

    def test_a_host_reports_every_field_an_analyst_asks_for(self) -> None:
        """IP, hostname, MAC, OS, status, risk, ports and related records."""
        sections = detail_panels.host_sections({"host": _host()})
        titles = " ".join(section.title for section in sections)
        rows = dict(sections[0].rows)
        assert rows["IP address"] == "10.0.0.9"
        assert rows["Hostname"] == "db01"
        assert rows["MAC address"] == "aa:bb:cc:dd:ee:ff"
        assert rows["Operating system"] == "Debian (96%)"
        assert rows["Status"] == "UP"
        assert rows["Risk level"] == "HIGH"
        assert "Open ports" in titles
        assert "Vulnerability findings" in titles
        assert "Related incidents" in titles
        assert "Related alerts" in titles

    def test_missing_values_are_stated_not_guessed(self) -> None:
        """Each absence says which absence it is."""
        rows = dict(
            detail_panels.host_sections(
                {"host": _host(hostname="", mac_address="", os_name="", vendor="")}
            )[0].rows
        )
        assert rows["Hostname"] == "not resolved"
        assert rows["MAC address"] == "not observed"
        # "not scanned" rather than "not fingerprinted": it names the action
        # that would fill the field, and matches what the inventory table now
        # shows for the same host.
        assert rows["Operating system"] == "not scanned"
        assert rows["Vendor"] == "not identified"

    def test_empty_sections_explain_themselves(self) -> None:
        """"No findings are recorded" beats an empty box."""
        sections = detail_panels.host_sections({"host": _host()})
        ports = next(s for s in sections if s.title.startswith("Open ports"))
        assert "No assessment has recorded open ports" in ports.text

    def test_a_missing_host_does_not_raise(self) -> None:
        """A record deleted between the click and the query is handled."""
        sections = detail_panels.host_sections({})
        assert "no longer in the inventory" in sections[0].text

    def test_chips_carry_risk_and_status(self) -> None:
        """The two facts worth reading before any of the rows."""
        assert detail_panels.host_chips(_host()) == [
            ("HIGH", "severity"), ("UP", "state")
        ]

    def test_a_scanned_host_reports_what_that_run_saw(self) -> None:
        """The scan's own record, kept distinct from the inventory's."""
        host = ScanHostResult(
            ip_address="10.0.0.9", hostname="db01", mac_address="aa:bb",
            status=HostStatus.UP,
            ports=[PortResult(port=22, protocol="tcp", state="open", service="ssh")],
            findings=[
                ScanFinding(
                    title="ssh exposed", observation="22/tcp open",
                    risk_level=RiskLevel.MEDIUM,
                )
            ],
        )
        sections = detail_panels.scan_host_sections(host, "Debian (96%)")
        rows = dict(sections[0].rows)
        assert rows["Hostname"] == "db01"
        assert rows["Operating system"] == "Debian (96%)"
        assert rows["Open ports"] == "1"
        assert "22/tcp" in sections[1].text
        assert "ssh exposed" in sections[2].text

    def test_an_address_outside_the_inventory_says_so(self) -> None:
        """An incident can name an address the inventory has never seen."""
        sections = detail_panels.unknown_device_sections(
            {"ip": "203.0.113.9", "role": "source"}
        )
        assert dict(sections[0].rows)["IP address"] == "203.0.113.9"
        assert "not in the host inventory" in sections[1].text

    def test_a_section_carries_rows_or_text(self) -> None:
        """The two shapes the drawer knows how to draw."""
        assert DrawerSection("t", rows=[("a", "b")]).rows
        assert DrawerSection("t", text="x").text


class TestIncidentDeviceInspection:
    """Following a device must not cost the analyst their place."""

    def test_double_click_inspects_in_place(self) -> None:
        """The drawer, not a navigation away from the incident."""
        source = inspect.getsource(incidents_module.IncidentsScreen._build_summary_tab)
        assert "on_activate=self._inspect_device" in source

    def test_the_full_page_is_still_one_click_away(self) -> None:
        """Inspecting in place is the default, not the only option."""
        source = inspect.getsource(incidents_module.IncidentsScreen._build_summary_tab)
        assert "Open in host inventory" in source
        primary = inspect.getsource(incidents_module.IncidentsScreen._show_device_drawer)
        assert "Open in Host Inventory" in primary

    def test_an_unknown_address_still_opens(self) -> None:
        """It is real - the incident named it - so it is still inspectable."""
        source = inspect.getsource(incidents_module.IncidentsScreen._inspect_device)
        assert "unknown_device_sections" in source


# ---------------------------------------------------------------------------
# Command palette
# ---------------------------------------------------------------------------
class TestPaletteRecordSearch:
    """The palette reaches records, through the services, under permission."""

    def test_records_come_from_the_existing_services(self) -> None:
        """No new query path: the screens' own search methods."""
        source = inspect.getsource(app_module.MainWindow._record_commands)
        assert "hosts.search(session" in source
        assert "correlation.search(" in source
        assert "snort.search(session" in source

    def test_each_source_is_permission_checked(self) -> None:
        """The palette can only surface what this role may read."""
        source = inspect.getsource(app_module.MainWindow._record_commands)
        for permission in ("host.view", "incident.view", "alert.view"):
            assert f'self._may("{permission}")' in source

    def test_results_open_through_existing_routing(self) -> None:
        """Navigation, not a new detail path."""
        source = inspect.getsource(app_module.MainWindow._record_commands)
        assert 'self.navigate(\n                            "hosts", focus_host=' in source
        assert '"incidents", focus_incident=' in source

    def test_the_search_runs_off_the_tk_thread(self) -> None:
        """It is a database query; the palette must stay responsive."""
        source = inspect.getsource(app_module.MainWindow._search_records)
        assert "threading.Thread" in source
        assert "dispatch.post" in source

    def test_one_failing_source_does_not_lose_the_others(self) -> None:
        """A Snort outage must not stop the palette finding a host."""
        source = inspect.getsource(app_module.MainWindow._safe_search)
        assert "return []" in source

    def test_typing_issues_one_query_not_one_per_letter(self) -> None:
        """The debounce is what makes typing an address bearable."""
        assert palette_module.SEARCH_DEBOUNCE_MS >= 100
        source = inspect.getsource(palette_module.CommandPalette._schedule_search)
        assert "after_cancel" in source
        assert "SEARCH_DEBOUNCE_MS" in source

    def test_a_single_character_does_not_search(self) -> None:
        """One letter matches most of the inventory and helps nobody."""
        assert palette_module.MIN_SEARCH_LENGTH >= 2
        source = inspect.getsource(palette_module.CommandPalette._schedule_search)
        assert "MIN_SEARCH_LENGTH" in source

    def test_a_late_result_is_discarded(self) -> None:
        """It answers a question the operator has already moved on from."""
        source = inspect.getsource(palette_module.CommandPalette.set_records)
        assert "if query != self._query.get().strip().lower():" in source
        assert "return" in source

    def test_screens_rank_above_records(self) -> None:
        """"Open Hosts" must not be buried under thirty addresses."""
        source = inspect.getsource(palette_module.CommandPalette._refilter)
        assert "matches + list(records)" in source


# ---------------------------------------------------------------------------
# Dashboard time range
# ---------------------------------------------------------------------------
class TestDashboardRanges:
    """The range is a query parameter, not a display filter."""

    def test_the_offered_ranges(self) -> None:
        """The five the operator asked for, in ascending order."""
        labels = [label for label, _hours in dashboard_module.TIME_RANGES]
        assert labels == ["15m", "1h", "6h", "24h", "7d"]
        hours = [h for _label, h in dashboard_module.TIME_RANGES]
        assert hours == sorted(hours)
        assert hours[0] == pytest.approx(0.25)
        assert hours[-1] == pytest.approx(168.0)

    def test_the_window_reaches_the_query(self) -> None:
        """Not filtered in the interface - asked of the database."""
        source = inspect.getsource(dashboard_module.DashboardScreen.refresh)
        assert "dashboard.snapshot(session, window_hours=window)" in source
        assert "network_overview(session, window_hours=window)" in source

    def test_the_service_accepts_a_sub_hour_window(self) -> None:
        """A 15-minute view during a live incident has to be answerable."""
        from aethra_sec.services.dashboard_service import DashboardService

        signature = inspect.signature(DashboardService.snapshot)
        assert signature.parameters["window_hours"].default == pytest.approx(24.0)
        source = inspect.getsource(DashboardService.snapshot)
        assert "max(0.05, float(window_hours))" in source

    def test_a_range_the_data_cannot_cover_is_disabled(self) -> None:
        """An empty chart is not an answer; not offering it is."""
        source = inspect.getsource(dashboard_module.DashboardScreen._paint_range_buttons)
        assert "disabled" in source
        assert "covered" in source

    def test_coverage_is_read_from_the_stored_series(self) -> None:
        """What the database actually holds decides, not a guess."""
        source = inspect.getsource(dashboard_module.DashboardScreen._note_coverage)
        assert "snapshot.traffic_series" in source

    def test_nothing_stored_leaves_every_range_available(self) -> None:
        """A fresh installation must not have its controls greyed out."""
        source = inspect.getsource(dashboard_module.DashboardScreen._paint_range_buttons)
        assert "covered is None" in source


class TestStatTiles:
    """A number that moved should be noticeable."""

    def test_a_changed_value_flashes(self) -> None:
        """Glanceable: the tile marks itself rather than relying on memory."""
        source = inspect.getsource(
            __import__(
                "aethra_sec.ui.widgets.cards", fromlist=["StatCard"]
            ).StatCard.update_value
        )
        assert "changed = value != self._value.cget(\"text\")" in source
        assert "self._flash()" in source

    def test_the_first_value_is_not_a_change(self) -> None:
        """Loading the page must not set every tile flashing."""
        source = inspect.getsource(
            __import__(
                "aethra_sec.ui.widgets.cards", fromlist=["StatCard"]
            ).StatCard.update_value
        )
        assert "self._seen_a_value" in source

    def test_tiles_reflow_rather_than_clip(self) -> None:
        """Six metrics on a narrow window wrap; they do not get cut off."""
        source = inspect.getsource(dashboard_module.DashboardScreen._layout_stat_row)
        assert "divmod(index, columns)" in source
        configure = inspect.getsource(
            dashboard_module.DashboardScreen._on_stat_row_configure
        )
        assert "MIN_TILE_WIDTH" in configure


# ---------------------------------------------------------------------------
# Table interactions
# ---------------------------------------------------------------------------
class TestTableInteractions:
    """Filtering and column choice narrow the view, never the data."""

    def test_the_quick_filter_composes_with_the_screens_filters(self) -> None:
        """It must not silently clear a structured filter a screen applied."""
        source = inspect.getsource(tables_module.DataTable._matches)
        assert "self._filter_predicate" in source
        assert "self._filter_text" in source
        assert "self._quick_text" in source
        body = inspect.getsource(tables_module.DataTable._apply_quick_filter)
        # Statements only - the docstring names set_filter to explain the split.
        statements = body.split('"""')[-1]
        assert "set_filter" not in statements
        assert "self._quick_text" in statements
        assert "self._render()" in statements

    def test_the_counter_states_what_is_hidden(self) -> None:
        """A filtered view can never be mistaken for the whole record set."""
        source = inspect.getsource(tables_module.DataTable._update_counter)
        assert "Showing" in source
        assert "of" in source

    def test_hiding_a_column_keeps_its_data(self) -> None:
        """Only the display list changes; rows and exports are untouched."""
        source = inspect.getsource(tables_module.DataTable._apply_visible_columns)
        assert "displaycolumns" in source
        export = inspect.getsource(tables_module.DataTable.export_rows)
        assert "self._columns" in export
        assert "_visible_keys" not in export

    def test_the_last_column_cannot_be_hidden(self) -> None:
        """An empty grid is not a view anyone asked for."""
        source = inspect.getsource(tables_module.DataTable._toggle_column)
        assert "if not wanted:" in source

    def test_keyboard_navigation_covers_the_ends_of_a_queue(self) -> None:
        """Home and End are what a long queue is worked with."""
        source = inspect.getsource(tables_module.DataTable.__init__)
        assert '"<Home>"' in source
        assert '"<End>"' in source

    def test_the_menu_key_binding_is_best_effort(self) -> None:
        """``<App>`` is not a keysym every X11 build knows."""
        source = inspect.getsource(tables_module.DataTable.__init__)
        assert '"<Shift-F10>"' in source
        assert "except tk.TclError" in source

    def test_a_small_embedded_table_keeps_its_chrome_off(self) -> None:
        """A filter box over four rows is noise, not a feature."""
        source = inspect.getsource(incidents_module.IncidentsScreen._build_summary_tab)
        assert "show_toolbar=False" in source


class TestLoadingFeedback:
    """Slow work is visible, and never blocks the console."""

    def test_a_screen_shows_a_loader_while_it_works(self) -> None:
        """The page waiting is the page that says so."""
        source = inspect.getsource(base_module.Screen._paint_busy)
        assert "Progressbar" in source
        assert "start(" in source

    def test_overlapping_loads_raise_and_clear_once(self) -> None:
        """Two queries in flight must not fight over the indicator."""
        source = inspect.getsource(base_module.Screen.set_busy)
        assert "self._busy_depth" in source

    def test_the_loader_never_covers_the_page(self) -> None:
        """It is a hairline at the top, not a modal over the content."""
        source = inspect.getsource(base_module.Screen._paint_busy)
        assert "height=3" in source


class TestSidebar:
    """Collapsing is a movement, and the structure never changes."""

    def test_the_rail_and_full_widths_are_named(self) -> None:
        assert app_module.SIDEBAR_RAIL_WIDTH < app_module.SIDEBAR_WIDTH

    def test_the_collapse_is_animated(self) -> None:
        """A jump makes the whole page look like it flinched."""
        source = inspect.getsource(app_module.MainWindow._animate_sidebar)
        assert "_step_sidebar" in source
        step = inspect.getsource(app_module.MainWindow._step_sidebar)
        assert "SIDEBAR_STEP_MS" in step

    def test_the_entries_scroll_on_a_short_window(self) -> None:
        """Navigation that has scrolled off the bottom is navigation lost."""
        source = inspect.getsource(app_module.MainWindow._build_navigation)
        assert "ScrollableFrame(" in source
        assert "nav_host" in source

    def test_the_scrollbar_reserves_its_width(self) -> None:
        """A canvas asks for more width than a sidebar has, and would take it."""
        from aethra_sec.ui.widgets.cards import ScrollableFrame

        source = inspect.getsource(ScrollableFrame.__init__)
        scrollbar_at = source.index("self._scrollbar.pack(")
        canvas_at = source.index("self._canvas.pack(")
        assert scrollbar_at < canvas_at, "the scrollbar must be packed first"

    def test_the_navigation_is_grouped_by_the_question_being_asked(self) -> None:
        """Monitor, then Security, then Assets - the order of an investigation.

        This once pinned the original headings under the name "unchanged".
        The redesign regroups them deliberately, so what is worth protecting
        is the order of concerns, not the words that were there first.
        """
        headings = [heading for heading, _keys in app_module.NAV_GROUPS]
        assert headings == [
            "MONITOR", "SECURITY", "ASSETS", "REPORTING",
            "ADMINISTRATION", "HELP",
        ]

    def test_every_screen_is_reachable_exactly_once(self) -> None:
        """A regrouping must not strand a screen or list one twice."""
        keys = [key for _h, group in app_module.NAV_GROUPS for key in group]
        assert len(keys) == len(set(keys)), "a screen is listed twice"
        assert set(keys) == {
            key for key, _label, _permission in app_module.NAVIGATION
        }
