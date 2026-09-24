"""Dashboard screen (§9, §63, §72).

Every tile, chart and list on this page is fed from real stored records or live
in-memory counters. On a fresh installation every number is genuinely zero and
each chart shows its empty state - that is the intended first-run appearance.
"""

from __future__ import annotations

import tkinter as tk
from datetime import date, datetime, timedelta
from tkinter import ttk
from typing import Any

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.enums import Severity
from aethra_sec.models.periods import (
    DashboardPeriod,
    parse_moment,
    PeriodMode,
    local_today,
    next_local_midnight,
)
from aethra_sec.models.system import DashboardSnapshot
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import METRICS, PALETTE, severity_colour, state_colour
from aethra_sec.ui.widgets import (
    Kpi,
    KpiStrip,
    BarChart,
    Card,
    DonutChart,
    EmptyState,
    FormDialog,
    FormField,
    ScrollableFrame,
    StatCard,
    StatusIndicator,
    TimelineChart,
    TimeSeriesChart,
    bytes_formatter,
)
from aethra_sec.utils.formatting import (
    NO_DATA_TEXT,
    WAITING_FOR_CAPTURE_TEXT,
    format_bandwidth,
    format_bytes,
    format_count,
    format_rate,
    truncate,
)
from aethra_sec.ui.widgets.tooltip import attach_tooltip
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import (
    format_duration,
    format_local,
    format_local_ms,
    utcnow,
)

LOGGER = get_logger("ui.dashboard")


#: The reporting periods the page offers, in the order they are shown. Each
#: builds a :class:`DashboardPeriod`, which is the single filter every
#: period-scoped query on the page is given - no widget picks its own window.
#: The three marked ``needs_choice`` open a picker for *which* day, month or
#: year, so an operator can investigate history without the page dragging them
#: back to the present.
PERIOD_BUTTONS: tuple[tuple[str, PeriodMode, bool], ...] = (
    ("Today", PeriodMode.TODAY, False),
    ("Day", PeriodMode.DAY, True),
    ("Month", PeriodMode.MONTH, True),
    ("Year", PeriodMode.YEAR, True),
    ("All data", PeriodMode.ALL, False),
    ("Custom", PeriodMode.CUSTOM, True),
)

#: Longest a single rollover timer may run before it re-arms.
#:
#: The timer is normally set to fire on the midnight boundary itself, which is
#: the opposite of polling. This ceiling only exists so that a machine which
#: slept through the boundary, or whose clock was moved, re-arms within the
#: hour instead of waiting out a timer measured against a time that no longer
#: applies. Each wake-up compares two dates and does no database work.
MAX_ROLLOVER_SLEEP_MS = 3_600_000

#: A second past the boundary, so the timer cannot fire while the clock still
#: reads 23:59:59.999 and conclude nothing has changed.
ROLLOVER_GUARD_MS = 1_000

#: KPI keys whose figure is counted over the reporting period, mapped to the
#: caption they carry. Everything not listed here is current state and keeps
#: its fixed caption - which is what stops the midnight rollover from being
#: read as "the backlog cleared overnight".
PERIOD_KPIS: dict[str, str] = {
    "packets": "Packets",
    "alerts": "Detections",
    "findings_new": "Findings discovered",
    "hosts_seen": "Hosts observed",
}

#: Narrowest a metric tile may be before the row wraps onto another line.
#: Below this the value itself starts to clip, which defeats the tile.
MIN_TILE_WIDTH = 250


#: One glyph per headline metric, shown in the tile's coloured badge.
METRIC_GLYPHS: dict[str, str] = {
    "packets": "≈",
    "hosts": "▣",
    "ports": "⚑",
    "alerts": "⚠",
    "findings": "◈",
}


def _bucket_text(minutes: int) -> str:
    """Name the chart's bucket width in the unit an operator reads it in."""
    minutes = max(1, int(minutes))
    if minutes % 10080 == 0:
        weeks = minutes // 10080
        return "per week" if weeks == 1 else f"per {weeks} weeks"
    if minutes % 1440 == 0:
        days = minutes // 1440
        return "per day" if days == 1 else f"per {days} days"
    if minutes % 60 == 0:
        hours = minutes // 60
        return "per hour" if hours == 1 else f"per {hours} hours"
    return f"per {minutes} minutes"


def _parse_date(raw: Any) -> date | None:
    """Parse ``YYYY-MM-DD`` from the day picker, or ``None`` if it is not one.

    Returns ``None`` rather than raising or guessing: a period the operator did
    not actually ask for would report on the wrong day.
    """
    try:
        return date.fromisoformat(str(raw or "").strip())
    except (TypeError, ValueError):
        return None


def _parse_year(raw: Any) -> int | None:
    """Parse a four-digit year, within the range ``date`` can represent."""
    text = str(raw or "").strip()
    if not text.isdigit():
        return None
    year = int(text)
    return year if 1 <= year <= 9998 else None


def _balanced_columns(count: int, fits: int) -> int:
    """Columns that divide ``count`` evenly, at most ``fits`` wide.

    Six tiles across five columns leaves one tile alone on a second line,
    which reads as a mistake rather than a layout. Choosing a divisor gives
    3+3 instead, and only falls back to the raw fit when the count has no
    usable divisor.
    """
    fits = max(1, min(count, fits))
    for candidate in range(fits, 1, -1):
        if count % candidate == 0:
            return candidate
    return fits if count % fits == 0 or fits == 1 else fits


class _TwoStrips:
    """One key-addressable view over the period and state strips.

    The screen updates figures by key and has no reason to know which band a
    key lives in; keeping that knowledge here means splitting the strips did
    not ripple into every update call site.
    """

    def __init__(self, period: KpiStrip, state: KpiStrip, *more: KpiStrip) -> None:
        """Bind the strips."""
        self._strips = (period, state, *more)

    def __getitem__(self, key: str):
        """The cell for a key, from whichever strip carries it."""
        for strip in self._strips:
            cell = strip.get(key)
            if cell is not None:
                return cell
        raise KeyError(key)

    def get(self, key: str):
        """The cell for a key, or ``None`` when neither strip has it."""
        for strip in self._strips:
            cell = strip.get(key)
            if cell is not None:
                return cell
        return None


class DashboardScreen(Screen):
    """The security operations overview."""

    title = "Dashboard"
    subtitle = "Live security posture, assembled from real subsystem data"
    required_permission = "dashboard.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._snapshot: DashboardSnapshot | None = None
        #: The headline strip; indexable by figure key.
        self._stat_cards: Any = None
        self._indicators: dict[str, StatusIndicator] = {}
        self._refresh_counter = 0
        #: The one authoritative reporting filter for this page. Opens on
        #: today - local midnight to the present moment - and rolls over on
        #: its own when the calendar date changes.
        self._period: DashboardPeriod = DashboardPeriod.default()
        self._period_buttons: dict[PeriodMode, ttk.Button] = {}
        #: Handle of the pending midnight timer, so it can be cancelled and
        #: re-armed rather than accumulating.
        self._rollover_job: str | None = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the dashboard."""
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        # The page is organised into four named zones rather than one column
        # of panels. An analyst arriving at the console asks four questions in
        # this order - what is my posture, what is happening right now, what
        # has been detected, and is the system itself healthy - and the zones
        # answer them in that order.
        self._build_period_bar(root)
        # Armed once the bar exists, so the first firing has labels to
        # repaint.
        self._schedule_rollover()

        # _build_stat_row raises its own two zone headings - PERIOD ACTIVITY
        # and CURRENT SECURITY STATE - because the split between them is the
        # point, not a subdivision of one "overview".
        self._build_stat_row(root)

        self._zone(root, "LIVE MONITORING", "traffic and detection as it arrives")
        self._build_status_and_traffic(root)
        self._build_charts_row(root)

        self._zone(root, "SECURITY EVENTS", "what the subsystems have reported")
        self._build_lists_row(root)
        self._build_timeline(root)

        self._zone(root, "SYSTEM STATUS", "every indicator is a real probe result")
        self._build_system_status(root)

    def _zone(self, parent: tk.Misc, title: str, note: str = "") -> None:
        """A labelled band that groups the panels beneath it.

        The rule carries the eye across the page and tells the operator where
        one concern ends and the next begins - the panels alone do not.
        """
        band = ttk.Frame(parent, style="TFrame")
        band.pack(fill="x", pady=(6, 8))
        tk.Frame(band, background=PALETTE.accent, width=3, height=11).pack(
            side="left", padx=(0, 8)
        )
        ttk.Label(band, text=title, style="Section.TLabel").pack(side="left")
        if note:
            ttk.Label(band, text=note, style="SectionNote.TLabel").pack(
                side="left", padx=(10, 0)
            )
        rule = tk.Frame(band, background=PALETTE.border, height=1)
        rule.pack(side="left", fill="x", expand=True, padx=(14, 0), pady=(6, 0))

    def _build_period_bar(self, parent: tk.Misc) -> None:
        """The reporting period every period figure on this page is drawn over.

        The buttons are not a display filter: the period they build is handed
        to ``DashboardService.snapshot(period=...)`` and becomes the
        ``[start, end)`` bounds of every period query, so the tiles, the charts
        and the severity donut cannot describe different spans.

        The resolved dates are spelled out beside the buttons. "Today" alone
        would not say *which* today, and it is exactly at the moment the day
        changes that an operator needs to see which day they are looking at.
        """
        bar = ttk.Frame(parent, style="TFrame")
        bar.pack(fill="x", pady=(0, 10))

        ttk.Label(bar, text="REPORTING PERIOD", style="CardDim.TLabel").pack(
            side="left", padx=(0, 10)
        )
        tips = {
            PeriodMode.TODAY: (
                "From local midnight today to now. This is the default, and it "
                "moves to the new day automatically at 00:00."
            ),
            PeriodMode.DAY: (
                "One whole calendar day. Pick a date to investigate; the page "
                "stays on it and does not jump forward at midnight."
            ),
            PeriodMode.MONTH: "One whole calendar month.",
            PeriodMode.YEAR: "One whole calendar year.",
            PeriodMode.ALL: "Every record retained, with no lower bound.",
            PeriodMode.CUSTOM: (
                "An explicit span you enter. Like the other historical views "
                "it stays where you put it at midnight."
            ),
        }
        for label, mode, _needs_choice in PERIOD_BUTTONS:
            button = ttk.Button(
                bar, text=label, style="Tool.TButton",
                width=max(6, len(label) + 1),
                command=lambda m=mode: self._select_mode(m),
            )
            button.pack(side="left", padx=(0, 4))
            attach_tooltip(button, tips[mode])
            self._period_buttons[mode] = button

        # The resolved window, in the operator's own timezone.
        note = ttk.Frame(bar, style="TFrame")
        note.pack(side="right")
        self._period_name = ttk.Label(note, text="", style="Section.TLabel")
        self._period_name.pack(side="left", padx=(0, 10))
        self._period_detail = ttk.Label(note, text="", style="CardDim.TLabel")
        self._period_detail.pack(side="left")
        self._paint_period()

    # ------------------------------------------------------------------
    # Reporting period
    # ------------------------------------------------------------------
    def _select_mode(self, mode: PeriodMode) -> None:
        """Handle a period button, asking which day/month/year where needed."""
        if mode is PeriodMode.TODAY:
            self.set_period(DashboardPeriod.today())
        elif mode is PeriodMode.ALL:
            self.set_period(DashboardPeriod.all_data())
        elif mode is PeriodMode.DAY:
            self._choose_day()
        elif mode is PeriodMode.MONTH:
            self._choose_month()
        elif mode is PeriodMode.YEAR:
            self._choose_year()
        elif mode is PeriodMode.CUSTOM:
            self._choose_custom()

    def set_period(self, period: DashboardPeriod) -> None:
        """Switch the page to a reporting period and reload.

        Only the query bounds change. Nothing is written, and no stored record
        is affected by which period is being viewed.
        """
        self._period = period
        self._paint_period()
        self._schedule_rollover()
        self.refresh()

    def _paint_period(self) -> None:
        """Highlight the active period and spell out the dates it covers."""
        for mode, button in self._period_buttons.items():
            button.configure(
                style="ToolAccent.TButton"
                if mode is self._period.mode
                else "Tool.TButton"
            )
        self._period_name.configure(text=self._period.heading)
        self._period_detail.configure(text=self._period.detail)

    def _choose_day(self) -> None:
        """Ask which day to report on.

        Defaults to yesterday: an operator reaching for "Day" while "Today" is
        already selected is nearly always looking at the day that just ended.
        """
        default = local_today() - timedelta(days=1)
        values = FormDialog(
            self, "Report on one day",
            [FormField(
                "day", "Date", value=default.isoformat(), required=True,
                help_text="YYYY-MM-DD, in your local timezone.",
            )],
            fonts=self.fonts, submit_label="Show day",
            intro=(
                "The page will report on this whole calendar day, 00:00 to "
                "24:00 local, and will stay on it - a historical view is not "
                "moved forward at midnight."
            ),
            validator=lambda v: (
                "" if _parse_date(v.get("day")) else "Enter a date as YYYY-MM-DD."
            ),
        ).show()
        chosen = _parse_date((values or {}).get("day"))
        if chosen is not None:
            self.set_period(DashboardPeriod.for_day(chosen))

    def _choose_month(self) -> None:
        """Ask which month to report on."""
        today = local_today()
        values = FormDialog(
            self, "Report on one month",
            [
                FormField("year", "Year", value=str(today.year), required=True),
                FormField(
                    "month", "Month", kind="choice", value=f"{today.month:02d}",
                    options=[f"{m:02d}" for m in range(1, 13)],
                ),
            ],
            fonts=self.fonts, submit_label="Show month",
            validator=lambda v: (
                "" if _parse_year(v.get("year")) else "Enter a four-digit year."
            ),
        ).show()
        if not values:
            return
        year = _parse_year(values.get("year"))
        if year is not None:
            self.set_period(
                DashboardPeriod.for_month(year, int(values.get("month") or 1))
            )

    def _choose_year(self) -> None:
        """Ask which year to report on."""
        values = FormDialog(
            self, "Report on one year",
            [FormField(
                "year", "Year", value=str(local_today().year), required=True
            )],
            fonts=self.fonts, submit_label="Show year",
            validator=lambda v: (
                "" if _parse_year(v.get("year")) else "Enter a four-digit year."
            ),
        ).show()
        year = _parse_year((values or {}).get("year"))
        if year is not None:
            self.set_period(DashboardPeriod.for_year(year))

    def _choose_custom(self) -> None:
        """Ask for an explicit span.

        Entered as local wall-clock time, because that is the clock the
        operator is reading. The upper bound stays exclusive, as it is for
        every other period, so two adjacent custom ranges neither overlap nor
        leave a gap.
        """
        today = local_today()
        values = FormDialog(
            self, "Report on a custom range",
            [
                FormField(
                    "start", "From", value=f"{today} 00:00", required=True,
                    help_text="YYYY-MM-DD HH:MM, in your local timezone.",
                ),
                FormField(
                    "end", "To (exclusive)", value=f"{today} 23:59", required=True,
                    help_text=(
                        "The upper bound is exclusive: a record stamped "
                        "exactly at this time belongs to the next range."
                    ),
                ),
            ],
            fonts=self.fonts, submit_label="Show range",
            validator=lambda v: (
                ""
                if parse_moment(v.get("start")) and parse_moment(v.get("end"))
                else "Enter both bounds as YYYY-MM-DD HH:MM."
            ),
        ).show()
        if not values:
            return
        start = parse_moment(values.get("start"))
        end = parse_moment(values.get("end"))
        if start is not None and end is not None:
            self.set_period(DashboardPeriod.custom(start, end))

    # ------------------------------------------------------------------
    # Automatic midnight rollover
    # ------------------------------------------------------------------
    def _schedule_rollover(self) -> None:
        """Arm a timer for the next local midnight.

        The delay is computed from the calendar - the exact interval to
        00:00:00 local - rather than by assuming a day is 24 hours, so it stays
        correct across a DST change and after the clock is adjusted. It is
        capped at :data:`MAX_ROLLOVER_SLEEP_MS` only so that a machine which
        slept through the boundary re-arms promptly instead of waiting out a
        timer measured against a time that has already passed.
        """
        if self._rollover_job is not None:
            try:
                self.after_cancel(self._rollover_job)
            except tk.TclError:
                pass
            self._rollover_job = None
        if not self.is_alive:
            return
        remaining = (next_local_midnight() - utcnow()).total_seconds() * 1000.0
        delay = int(max(0.0, remaining) + ROLLOVER_GUARD_MS)
        self._rollover_job = self.after(
            min(delay, MAX_ROLLOVER_SLEEP_MS), self._on_rollover_timer
        )

    def _on_rollover_timer(self) -> None:
        """Timer callback: roll the day over if it has actually changed."""
        self._rollover_job = None
        if not self.is_alive:
            return
        try:
            if self._apply_rollover():
                # The window moved, so every period figure on the page is now
                # describing the wrong day. Re-query rather than repaint.
                self.refresh()
        finally:
            self._schedule_rollover()

    def _apply_rollover(self) -> bool:
        """Move the reporting period to the current date, if it should move.

        The system clock is the authority: this compares the *actual* local
        date against the date the page is reporting on, so it is right whether
        the timer fired on time, late after a resume from sleep, or early
        because the clock was put back. Nothing is assumed from the fact that a
        timer fired.

        Only TODAY moves. A day, month or year the operator navigated to is an
        investigation in progress, and dragging it forward at midnight would
        silently change what they are looking at.

        Returns:
            True when the period changed and the page needs reloading.
        """
        if not self._period.needs_rollover():
            return False
        previous = self._period.anchor
        self._period = DashboardPeriod.today()
        self._paint_period()
        LOGGER.info(
            "Dashboard reporting period rolled over from %s to %s; "
            "query bounds only, no records were modified.",
            previous, self._period.anchor,
        )
        self.status(f"New day - reporting period is now {self._period.detail}.")
        return True

    def _build_stat_row(self, parent: tk.Misc) -> None:
        """Two strips: what happened in the period, and where things stand.

        These were one undifferentiated band of six figures, and that was the
        problem. "Packets: 22,661" and "Open findings: 557" look identical in
        a row of tiles, but the first legitimately returns to zero at midnight
        and the second must not - showing a backlog of 557 as zero would be a
        false all-clear. Splitting them means a figure's kind is visible before
        its value is read, and the midnight rollover has an obvious meaning:
        the top strip resets, the bottom strip does not.
        """
        period_kpis = (
            (
                "packets", "Packets", PALETTE.accent, "traffic",
                "Packets captured inside the reporting period, counted from "
                "stored traffic aggregates. Click to open Live Monitoring.",
            ),
            (
                "alerts", "Detections", PALETTE.high, "alerts",
                "Detections raised inside the reporting period, from both "
                "engines - Snort alerts and AETHRA-SEC's own traffic rules. "
                "The severity split beneath is the same query grouped, so it "
                "always sums to this figure and matches the IDS Alerts screen "
                "filtered to the same period.",
            ),
            (
                "findings_new", "Findings discovered", PALETTE.low,
                "vulnerabilities",
                "Assessment findings first recorded inside the reporting "
                "period, with the number of assessments that produced them.",
            ),
            (
                "hosts_seen", "Hosts observed", PALETTE.info, "hosts",
                "Hosts seen at all during the reporting period, and how many "
                "of them were seen for the first time. Distinct from Active "
                "hosts below, which is a recency question about now.",
            ),
        )
        state_kpis = (
            (
                "hosts", "Active hosts", PALETTE.info, "hosts",
                "Hosts seen in the last 24 hours, from capture or assessment. "
                "Current state - how much of the network is live now - so it "
                "is not bounded by the reporting period and does not reset at "
                "midnight. Click to open the host inventory.",
            ),
            (
                "ports", "Open ports", PALETTE.medium, "vulnerabilities",
                "Open ports recorded by the most recent assessment of each "
                "host. Current state, not a daily figure. An open port is an "
                "exposure to review, not a vulnerability in itself.",
            ),
            (
                "findings", "Open findings", PALETTE.low, "vulnerabilities",
                "Assessment findings that have not been resolved. Current "
                "state: an unresolved exposure is still unresolved tomorrow.",
            ),
        )

        self._zone(
            parent, "PERIOD ACTIVITY",
            "counted inside the reporting period - starts again each day",
        )
        self._period_kpis = KpiStrip(
            parent,
            [
                Kpi(key=key, label=label, colour=colour, tooltip=tip,
                    on_click=(lambda t=target: self.app.navigate(t)))
                for key, label, colour, target, tip in period_kpis
            ],
            fonts=self.fonts,
        )
        self._period_kpis.pack(fill="x", pady=(0, METRICS.gutter))

        self._zone(
            parent, "CURRENT SECURITY STATE",
            "where things stand now - unaffected by the reporting period",
        )
        self._state_kpis = KpiStrip(
            parent,
            [
                Kpi(key=key, label=label, colour=colour, tooltip=tip,
                    on_click=(lambda t=target: self.app.navigate(t)))
                for key, label, colour, target, tip in state_kpis
            ],
            fonts=self.fonts,
        )
        self._state_kpis.pack(fill="x", pady=(0, METRICS.gutter))

        assessment_kpis = (
            (
                "va_discovered", "Discovered hosts", PALETTE.info,
                "vulnerabilities",
                "Hosts discovered from real traffic inside the monitored "
                "authorised network. Counted over the whole inventory with the "
                "same derivation as the Vulnerability Assessment table.",
            ),
            (
                "va_awaiting", "Awaiting / scanning", PALETTE.accent,
                "vulnerabilities",
                "Hosts not yet assessed or queued, and hosts Nmap is assessing "
                "right now.",
            ),
            (
                "va_vulnerable", "Vulnerable", PALETTE.critical,
                "vulnerabilities",
                "Hosts whose completed assessment produced evidence of a "
                "vulnerability the scanner can point at: a CVE from an NSE "
                "script, a CVSS score, or a knowledge-base match. An open "
                "port is exposure, not a vulnerability, and never counts here.",
            ),
            (
                "va_safe", "Safe", PALETTE.ok, "vulnerabilities",
                "Hosts whose assessment completed, the host answered, and "
                "nothing confirmable was found. It means the configured "
                "assessment found nothing it can confirm - not that the host "
                "is secure. Open ports may still be recorded against it.",
            ),
            (
                "va_no_conclusion", "No conclusion", PALETTE.medium,
                "vulnerabilities",
                "Assessments that reached no conclusion: queued, scanning, no "
                "response, timed out or failed. None of these is ever counted "
                "as safe.",
            ),
        )
        self._zone(
            parent, "AUTOMATED ASSESSMENT",
            "discovery -> queue -> Nmap -> findings, across every host",
        )
        self._assessment_kpis = KpiStrip(
            parent,
            [
                Kpi(key=key, label=label, colour=colour, tooltip=tip,
                    on_click=(lambda t=target: self.app.navigate(t)))
                for key, label, colour, target, tip in assessment_kpis
            ],
            fonts=self.fonts,
        )
        self._assessment_kpis.pack(fill="x", pady=(0, METRICS.gutter))

        # Existing call sites address a figure by key without caring which
        # strip holds it, so the strips are presented as one lookup.
        self._stat_cards = _TwoStrips(
            self._period_kpis, self._state_kpis, self._assessment_kpis
        )

    def _build_status_and_traffic(self, parent: tk.Misc) -> None:
        """The live traffic chart, given the full width of the page.

        The subsystem indicators used to sit beside it and halve its width. A
        rate chart is read by its shape, so it gets the room; the indicators
        move to their own zone, where they can be laid out across the page.
        """
        self._traffic_card = Card(
            parent, "Network traffic", subtitle="packets per second",
            fonts=self.fonts, accent=PALETTE.accent,
        )
        traffic_card = self._traffic_card
        traffic_card.pack(fill="x", pady=(0, 10))
        self._traffic_chart = TimeSeriesChart(
            traffic_card, height=190,
            empty_message=WAITING_FOR_CAPTURE_TEXT,
            empty_detail=(
                "Start packet capture on the Network Monitoring screen to see "
                "live traffic here."
            ),
            value_formatter=lambda v: f"{v:,.0f}",
            series_label="packets/s",
        )
        self._traffic_chart.pack(fill="both", expand=True)

        self._traffic_summary = ttk.Label(
            traffic_card, text="", style="CardMuted.TLabel"
        )
        self._traffic_summary.pack(anchor="w", pady=(8, 0))

    def _build_system_status(self, parent: tk.Misc) -> None:
        """Subsystem probes, laid out across the page rather than stacked.

        Each one is a real probe result: green only where the subsystem
        actually answered.
        """
        card = Card(
            parent, "System status", subtitle="live probe results",
            fonts=self.fonts, accent=PALETTE.ok,
        )
        card.pack(fill="x", pady=(0, 10))

        grid = ttk.Frame(card, style="Card.TFrame")
        grid.pack(fill="x")
        probes = (
            ("application", "AETHRA-SEC"), ("database", "Database"),
            ("nmap", "Nmap"), ("tshark", "PyShark / TShark"),
            ("capture", "Packet capture"), ("snort", "Snort IDS"),
        )
        for index, (key, label) in enumerate(probes):
            cell = ttk.Frame(grid, style="Card.TFrame")
            cell.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 10, 0))
            grid.columnconfigure(index, weight=1, uniform="probe")
            indicator = StatusIndicator(cell, label, compact=True)
            indicator.pack(fill="x")
            self._indicators[key] = indicator

        self._uptime_label = ttk.Label(
            card, text="Monitoring uptime: -", style="CardDim.TLabel"
        )
        self._uptime_label.pack(anchor="w", pady=(10, 0))

    def _build_charts_row(self, parent: tk.Misc) -> None:
        """IDS activity, alert severity mix and protocol mix."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=(0, 12))

        # Every caption on this row states the reporting period, and is
        # restated on each load. A fixed "(24h)" beside a figure counted over a
        # calendar day is wrong, and it would become wrong on its own at
        # midnight - which is precisely the failure this work is about.
        # A non-empty subtitle at construction is what creates the label the
        # caption is later restated into; the period is already known here.
        self._ids_card = Card(
            row, "Detections",
            subtitle=f"{_bucket_text(15)} · {self._period.label.lower()}",
            fonts=self.fonts,
        )
        self._ids_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._alert_chart = TimeSeriesChart(
            self._ids_card, height=150, colour=PALETTE.high,
            empty_message="No detections in this period",
            empty_detail=(
                "Detections appear here when Snort sends an alert or "
                "AETHRA-SEC's own traffic rules raise one."
            ),
            value_formatter=lambda v: f"{v:,.0f}",
        )
        self._alert_chart.pack(fill="both", expand=True)

        self._severity_card = Card(row, "Detection severity", fonts=self.fonts)
        self._severity_card.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        self._severity_chart = DonutChart(
            self._severity_card, height=150, colour_by_severity=True,
            centre_label="detections",
            empty_message="No detections in this period",
            on_select=lambda severity: self.app.navigate("alerts", search=severity),
        )
        self._severity_chart.pack(fill="both", expand=True)

        self._protocol_card = Card(row, "Protocol distribution", fonts=self.fonts)
        self._protocol_card.grid(row=0, column=2, sticky="nsew")
        self._protocol_chart = DonutChart(
            self._protocol_card, height=150, centre_label="packets",
            empty_message=NO_DATA_TEXT,
            empty_detail="Protocol mix is computed from captured packets.",
        )
        self._protocol_chart.pack(fill="both", expand=True)

        for index in range(3):
            row.columnconfigure(index, weight=1)

    def _build_lists_row(self, parent: tk.Misc) -> None:
        """Recent alerts, findings and activity."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="both", expand=True, pady=(0, 12))

        self._alerts_card = Card(row, "Recent IDS alerts", fonts=self.fonts)
        self._alerts_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._alerts_body = ttk.Frame(self._alerts_card, style="Card.TFrame")
        self._alerts_body.pack(fill="both", expand=True)

        self._findings_card = Card(row, "Recent vulnerabilities", fonts=self.fonts)
        self._findings_card.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        self._findings_body = ttk.Frame(self._findings_card, style="Card.TFrame")
        self._findings_body.pack(fill="both", expand=True)

        self._activity_card = Card(row, "Recent activity", fonts=self.fonts)
        self._activity_card.grid(row=0, column=2, sticky="nsew")
        self._activity_body = ttk.Frame(self._activity_card, style="Card.TFrame")
        self._activity_body.pack(fill="both", expand=True)

        for index in range(3):
            row.columnconfigure(index, weight=1)
        row.rowconfigure(0, weight=1)

    def _build_timeline(self, parent: tk.Misc) -> None:
        """Threat timeline plus top-talker rankings."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x")

        timeline_card = Card(
            row, "Threat timeline", subtitle="IDS alerts", fonts=self.fonts
        )
        timeline_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._timeline = TimelineChart(
            timeline_card, height=130,
            empty_message="No alerts in this period",
            empty_detail=(
                "Only alerts Snort actually raised are plotted. An empty "
                "timeline means none were received, not that the sensor was "
                "checked and found nothing."
            ),
        )
        self._timeline.pack(fill="both", expand=True)

        talkers_card = Card(row, "Top source addresses", fonts=self.fonts)
        talkers_card.grid(row=0, column=1, sticky="nsew")
        self._talkers_chart = BarChart(
            talkers_card, height=130, empty_message=NO_DATA_TEXT,
            empty_detail="Populated from captured packets.",
            on_select=lambda address: self.app.navigate("hosts", search=address),
        )
        self._talkers_chart.pack(fill="both", expand=True)

        row.columnconfigure(0, weight=3)
        row.columnconfigure(1, weight=2)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload the dashboard from stored records.

        The active period is read here, on the Tk thread, and the same object
        is handed to both queries - so the two halves of the page can never be
        assembled from different windows, and a rollover landing mid-load
        cannot split them either.
        """
        session = self.session
        dashboard = self.context.dashboard
        if session is None or dashboard is None:
            return
        period = self._period.refreshed()
        self._period = period
        self._paint_period()
        self.status(f"Loading dashboard ({period.detail})...")
        self.run_async(
            lambda: (
                dashboard.snapshot(session, period=period),
                dashboard.network_overview(session, period=period),
            ),
            self._apply,
            name="dashboard-load",
        )

    def _apply(self, payload: tuple[DashboardSnapshot, dict[str, Any]]) -> None:
        """Render a freshly loaded snapshot."""
        snapshot, overview = payload
        self._snapshot = snapshot
        self._update_stats(snapshot)
        self._update_indicators()
        self._update_charts(snapshot, overview)
        self._update_lists(snapshot)
        self.status(
            f"Dashboard updated {format_local(snapshot.generated_at, '%H:%M:%S')}"
            f" · {snapshot.period_detail}"
            + ("" if snapshot.has_any_data else " - no security records yet.")
        )

    def _update_assessment_stats(self, snapshot: DashboardSnapshot) -> None:
        """The automated assessment strip, from the shared assessment summary."""
        summary = snapshot.assessment
        cells = [
            self._stat_cards.get(key)
            for key in (
                "va_discovered", "va_awaiting", "va_vulnerable",
                "va_safe", "va_no_conclusion",
            )
        ]
        if any(cell is None for cell in cells):
            return
        discovered, awaiting, vulnerable, safe, no_conclusion = cells
        if summary is None:
            for cell in cells:
                cell.update_value("—", "The host inventory could not be read")
            return
        scope_note = (
            f"{format_count(summary.outside_scope)} outside scope"
            if summary.scope_available
            else "assessment scope unavailable"
        )
        discovered.update_value(
            format_count(summary.discovered),
            f"{format_count(summary.active)} active · {scope_note}",
        )
        awaiting.update_value(
            format_count(summary.awaiting),
            f"{format_count(summary.scanning)} scanning now",
        )
        vulnerable.update_value(
            format_count(summary.vulnerable),
            "confirmed vulnerability evidence",
            accent=PALETTE.critical if summary.vulnerable else PALETTE.medium,
        )
        # Counted from the same per-host derivation the table uses, so the
        # tile and the Security result column cannot disagree.
        safe.update_value(
            format_count(summary.safe),
            "assessment completed, host answered, nothing confirmed",
        )
        no_conclusion.update_value(
            format_count(
                summary.not_determined + summary.failed + summary.timeout
                + summary.offline + summary.queued + summary.scanning
            ),
            f"{summary.offline} no response / {summary.timeout} timeout / "
            f"{summary.failed} failed",
        )

    def _update_stats(self, snapshot: DashboardSnapshot) -> None:
        """Update both strips.

        Every figure in the period strip comes from a query bounded by
        ``[period_start, period_end)``; every figure in the state strip comes
        from a query with no time bound at all. That is the whole distinction,
        and it is why the first strip empties at midnight and the second does
        not.
        """
        period = snapshot.period_label or "period"
        for key, caption in PERIOD_KPIS.items():
            cell = self._stat_cards.get(key)
            if cell is not None:
                cell.update_label(f"{caption} · {period}")

        # ---------------------------------------------------- period activity
        self._stat_cards["packets"].update_value(
            format_count(snapshot.packets_in_period),
            f"{format_count(snapshot.total_packets_stored)} observed in total"
            if snapshot.total_packets_stored
            else "No packets captured yet",
        )
        # The severity split is the same query as the total, grouped, so these
        # two lines cannot contradict each other or the IDS Alerts screen
        # filtered to the same period.
        self._stat_cards["alerts"].update_value(
            format_count(snapshot.detections_in_period),
            (
                f"{snapshot.high_alerts} high / "
                f"{snapshot.medium_alerts} medium · {period.lower()}"
                if snapshot.detections_in_period
                else f"No detections · {period.lower()}"
            ),
            accent=PALETTE.high if snapshot.high_alerts else PALETTE.medium,
        )
        self._stat_cards["findings_new"].update_value(
            format_count(snapshot.findings_in_period),
            f"{format_count(snapshot.scans_in_period)} assessment(s) run · "
            f"{period.lower()}",
        )
        self._stat_cards["hosts_seen"].update_value(
            format_count(snapshot.hosts_seen_in_period),
            f"{format_count(snapshot.hosts_discovered_in_period)} seen for "
            f"the first time · {period.lower()}",
        )

        # ------------------------------------------------ current state
        self._stat_cards["hosts"].update_value(
            format_count(snapshot.active_hosts),
            f"{format_count(snapshot.observed_hosts)} known in inventory",
        )
        self._stat_cards["ports"].update_value(
            format_count(snapshot.open_ports),
            f"{format_count(snapshot.scans_total)} assessment(s) all time",
        )
        self._update_assessment_stats(snapshot)
        self._stat_cards["findings"].update_value(
            format_count(snapshot.open_findings),
            f"{snapshot.critical_findings} critical / {snapshot.high_findings} high",
            accent=PALETTE.critical if snapshot.critical_findings else PALETTE.low,
        )

        # Sparklines and trends plot the same stored series the numbers came
        # from. Where no comparable earlier period exists, no trend is shown.
        self._stat_cards["packets"].update_sparkline(
            [value for _stamp, value in snapshot.traffic_series]
        )
        self._stat_cards["packets"].update_trend(
            snapshot.packets_in_period, snapshot.packets_previous_period
        )
        self._stat_cards["alerts"].update_sparkline(
            [float(value) for _stamp, value in snapshot.alert_series]
        )
        self._stat_cards["alerts"].update_trend(
            snapshot.detections_in_period, snapshot.alerts_previous_period
        )

    def _update_indicators(self) -> None:
        """Update the status lights from the latest real probes (§10)."""
        health = self.context.health
        if health is None:
            return
        statuses = health.statuses()
        for key, indicator in self._indicators.items():
            status = statuses.get(key)
            if status is not None:
                indicator.update_state(str(status.state), status.detail)
        self._uptime_label.configure(
            text=f"Monitoring uptime: {health.uptime_text()}"
        )

    def _update_charts(
        self, snapshot: DashboardSnapshot, overview: dict[str, Any]
    ) -> None:
        """Feed the charts real measurements."""
        self._traffic_chart.set_points(snapshot.traffic_series)
        capture = self.context.capture
        if capture is not None:
            statistics = capture.statistics()
            if statistics.is_running:
                analyzer = capture.analyzer
                self._traffic_summary.configure(
                    text=(
                        f"Live: {format_rate(analyzer.packets_per_second())} · "
                        f"{format_bandwidth(analyzer.bytes_per_second())} · "
                        f"{format_count(statistics.total_packets)} captured · "
                        f"{format_count(statistics.dropped)} dropped"
                    )
                )
            else:
                self._traffic_summary.configure(
                    text=(
                        f"Capture {statistics.status_text.lower()}. Stored series "
                        f"covers {len(snapshot.traffic_series)} interval(s)."
                    )
                )

        self._restate_chart_captions(snapshot)
        self._alert_chart.set_points(
            [(stamp, float(count)) for stamp, count in snapshot.alert_series]
        )
        self._severity_chart.set_items(
            [
                (level, count)
                for level, count in snapshot.severity_distribution
                if count
            ]
        )
        self._protocol_chart.set_items(list(snapshot.protocol_distribution))
        self._talkers_chart.set_items(
            [(t.label, float(t.packets)) for t in overview.get("top_sources", [])]
        )
        self._timeline.set_entries(
            [
                TimelineChart.Entry(
                    at=entry["at"],
                    severity=entry["severity"],
                    label=entry["label"],
                )
                for entry in snapshot.threat_timeline
                if entry.get("at")
            ]
        )

    def _restate_chart_captions(self, snapshot: DashboardSnapshot) -> None:
        """Say what each chart is counted over, and in what bucket.

        The bucket comes from the snapshot rather than a constant, because the
        service widens it for longer spans - a year in fifteen-minute slots is
        unreadable - and a caption that names a width the chart is not using
        would be a small lie told on every load.
        """
        period = snapshot.period_label or "period"
        self._traffic_card.subtitle_label.configure(
            text=f"packets per second · {period.lower()}"
        )
        self._ids_card.subtitle_label.configure(
            text=f"{_bucket_text(snapshot.alert_bucket_minutes)} · {period.lower()}"
        )
        self._severity_chart.set_centre_label(f"detections · {period.lower()}")
        self._protocol_chart.set_centre_label(f"packets · {period.lower()}")

    def _update_lists(self, snapshot: DashboardSnapshot) -> None:
        """Render the three recent-record lists."""
        self._render_alerts(snapshot)
        self._render_findings(snapshot)
        self._render_activity(snapshot)

    def _render_alerts(self, snapshot: DashboardSnapshot) -> None:
        """Recent Snort alerts, or an honest empty state."""
        for child in self._alerts_body.winfo_children():
            child.destroy()
        if not snapshot.recent_alerts:
            snort = self.context.snort
            detail = (
                snort.status().detail
                if snort is not None
                else "Snort ingest has not been configured."
            )
            EmptyState(
                self._alerts_body, "No IDS alerts recorded", detail=detail
            ).pack(fill="both", expand=True)
            return
        for alert in snapshot.recent_alerts:
            self._list_row(
                self._alerts_body,
                left=str(alert.severity),
                left_colour=severity_colour(alert.severity),
                title=truncate(alert.message or alert.signature_text, 46),
                detail=(
                    f"{format_local_ms(alert.effective_time)}  "
                    f"{alert.src_ip or '-'} -> {alert.dst_ip or '-'}"
                ),
                on_click=lambda: self.app.navigate("alerts"),
            )

    def _render_findings(self, snapshot: DashboardSnapshot) -> None:
        """Recent Nmap findings, or an honest empty state."""
        for child in self._findings_body.winfo_children():
            child.destroy()
        if not snapshot.recent_findings:
            EmptyState(
                self._findings_body, "No vulnerabilities recorded",
                detail=(
                    "Run an authorised assessment on the Vulnerability "
                    "Assessment screen to populate this list."
                ),
                action_label="Open assessment",
                on_action=lambda: self.app.navigate("vulnerabilities"),
            ).pack(fill="both", expand=True)
            return
        for finding in snapshot.recent_findings:
            self._list_row(
                self._findings_body,
                left=str(finding.risk_level),
                left_colour=severity_colour(finding.risk_level),
                title=truncate(finding.title, 46),
                detail=(
                    f"{finding.ip_address}"
                    + (f":{finding.port}" if finding.port else "")
                    + f"  ·  {format_local(finding.created_at, '%d %b %H:%M')}"
                ),
                on_click=lambda: self.app.navigate("vulnerabilities"),
            )

    def _render_activity(self, snapshot: DashboardSnapshot) -> None:
        """Recent audited activity, or an honest empty state."""
        for child in self._activity_body.winfo_children():
            child.destroy()
        if not snapshot.recent_activity:
            EmptyState(self._activity_body, "No recorded activity").pack(
                fill="both", expand=True
            )
            return
        for record in snapshot.recent_activity:
            self._list_row(
                self._activity_body,
                left=record.result,
                left_colour=(
                    PALETTE.ok if record.succeeded else PALETTE.high
                ),
                title=truncate(record.action.replace("_", " ").title(), 40),
                detail=(
                    f"{format_local(record.occurred_at, '%d %b %H:%M:%S')}  "
                    f"{record.username or 'system'}"
                ),
            )

    def _list_row(
        self,
        parent: tk.Misc,
        *,
        left: str,
        left_colour: str,
        title: str,
        detail: str,
        on_click: Any = None,
    ) -> None:
        """Render one compact list row."""
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x", pady=2)
        badge = ttk.Label(row, text=left[:8], style="Card.TLabel", width=9)
        badge.configure(foreground=left_colour, font=self.fonts.small_bold)
        badge.pack(side="left", anchor="n")
        text = ttk.Frame(row, style="Card.TFrame")
        text.pack(side="left", fill="x", expand=True)
        ttk.Label(text, text=title, style="Card.TLabel").pack(anchor="w")
        ttk.Label(text, text=detail, style="CardDim.TLabel").pack(anchor="w")
        if on_click is not None:
            for widget in (row, badge, text):
                widget.bind("<Button-1>", lambda _event: on_click())
                widget.configure(cursor="hand2")

    # ------------------------------------------------------------------
    # Live updates
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """React to live events without re-querying everything (§113).

        Live updates only apply while the page is reporting on a period that
        includes the present. Painting the live counters onto a page headed
        "05 Sep 2026" would put today's traffic on yesterday's chart, and it is
        exactly at midnight that this would start happening on its own.
        """
        live = self._period.tracks_now
        if event.type == EventType.TRAFFIC_STATS_UPDATED:
            snapshot = getattr(event.payload, "snapshot", None)
            if snapshot is None or not snapshot.pps_series or not live:
                return
            # The trailing live window straddles midnight for its first minute
            # of the new day. Points from before the boundary are dropped
            # rather than redrawn under today's heading; they remain visible on
            # yesterday's period and in the stored series.
            points = [
                (p.timestamp, p.value)
                for p in snapshot.pps_series
                if self._period.contains(p.timestamp)
            ]
            self._traffic_chart.set_points(points)
            self._traffic_summary.configure(
                text=(
                    f"Live: {format_rate(snapshot.packets_per_second)} · "
                    f"{format_bandwidth(snapshot.bytes_per_second)} · "
                    f"{format_count(snapshot.total_packets)} captured · "
                    f"{format_count(snapshot.active_hosts)} active host(s)"
                )
            )
            # The protocol donut and the talkers bar are NOT repainted here.
            #
            # They used to be, from this same live snapshot - whose counters
            # cover the analyzer's trailing 300-second window. So a donut
            # captioned "packets · today" was showing the last five minutes,
            # and the figure in its centre disagreed with the packets tile
            # beside it by orders of magnitude. They are period widgets and
            # they are now painted only by _update_charts, from the period
            # query, which is the whole point of having one reporting period.
        elif event.type in (
            EventType.SNORT_ALERT_RECEIVED,
            EventType.NMAP_SCAN_COMPLETED, EventType.TRAFFIC_ANOMALY_DETECTED,
        ):
            # A detection arriving now cannot change what a closed period
            # contains, so a historical view is left undisturbed.
            if live:
                self.refresh()
        elif event.type in (
            EventType.SERVICE_STATUS_CHANGED, EventType.DATABASE_STATUS_CHANGED,
            EventType.SNORT_STATUS_CHANGED, EventType.CAPTURE_STARTED,
            EventType.CAPTURE_STOPPED,
        ):
            self._update_indicators()

    def on_show(self) -> None:
        """Reload on arrival, on the correct day.

        The screen is built once and kept, so returning to it after midnight
        would otherwise show a page still reporting on yesterday. The rollover
        is applied first and the single reload that follows then uses the new
        window.
        """
        self._apply_rollover()
        self._schedule_rollover()
        super().on_show()

    def on_hide(self) -> None:
        """Keep the rollover timer armed while the page is not visible.

        Deliberately does not cancel it. Screens are constructed once and kept,
        and the requirement is that the Dashboard rolls over at 00:00 - not
        that it rolls over at 00:00 only if the operator happens to be looking
        at it.
        """

    def on_tick(self) -> None:
        """Refresh stored counters periodically, indicators every tick.

        The date check here is a comparison of two ``date`` objects and touches
        no database. It is a backstop for the timer, not the mechanism: it
        catches a clock adjustment between timer firings while the page is on
        screen, and costs nothing when the date has not changed.
        """
        self._refresh_counter += 1
        self._update_indicators()
        if self._apply_rollover():
            self._schedule_rollover()
            self.refresh()
            return
        if self._refresh_counter % 10 == 0:
            self.refresh()

    def _on_destroy(self, event: tk.Event) -> None:
        """Cancel the pending rollover timer as the screen goes away."""
        if event.widget is self and self._rollover_job is not None:
            try:
                self.after_cancel(self._rollover_job)
            except tk.TclError:  # pragma: no cover - already torn down
                pass
            self._rollover_job = None
        super()._on_destroy(event)
