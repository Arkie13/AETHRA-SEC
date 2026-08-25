"""Dashboard screen (§9, §63, §72).

Every tile, chart and list on this page is fed from real stored records or live
in-memory counters. On a fresh installation every number is genuinely zero and
each chart shows its empty state - that is the intended first-run appearance.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import Any

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.enums import Severity
from aethra_sec.models.system import DashboardSnapshot
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, severity_colour, state_colour
from aethra_sec.ui.widgets.surface import MetricTile
from aethra_sec.ui.widgets import (
    BarChart,
    Card,
    DonutChart,
    EmptyState,
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
from aethra_sec.utils.timeutil import (
    format_duration,
    format_local,
    format_local_ms,
    utcnow,
)


#: Selectable windows, each passed to the existing snapshot query as hours.
TIME_RANGES: tuple[tuple[str, float], ...] = (
    ("15m", 0.25),
    ("1h", 1.0),
    ("6h", 6.0),
    ("24h", 24.0),
    ("7d", 168.0),
)

#: The window the page opens on, matching the service's own default.
DEFAULT_WINDOW_HOURS = 24.0

#: Narrowest a metric tile may be before the row wraps onto another line.
#: Below this the value itself starts to clip, which defeats the tile.
MIN_TILE_WIDTH = 250


#: One glyph per headline metric, shown in the tile's coloured badge.
METRIC_GLYPHS: dict[str, str] = {
    "packets": "≈",
    "hosts": "▣",
    "ports": "⚑",
    "alerts": "⚠",
    "incidents": "✦",
    "findings": "◈",
}


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


class DashboardScreen(Screen):
    """The security operations overview."""

    title = "Dashboard"
    subtitle = "Live security posture, assembled from real subsystem data"
    required_permission = "dashboard.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._snapshot: DashboardSnapshot | None = None
        self._stat_cards: dict[str, StatCard] = {}
        self._indicators: dict[str, StatusIndicator] = {}
        self._refresh_counter = 0
        self._window_hours: float = DEFAULT_WINDOW_HOURS
        self._range_buttons: dict[str, ttk.Button] = {}
        #: Hours of stored history, learned from the first snapshot. ``None``
        #: until then, so no range is disabled on a guess.
        self._covered_hours: float | None = None

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
        self._build_range_bar(root)

        self._zone(root, "SECURITY OVERVIEW", "posture across the selected window")
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

    def _build_range_bar(self, parent: tk.Misc) -> None:
        """The window every rate, chart and rollup on this page is drawn over.

        The ranges are not decoration: they are passed straight to
        ``DashboardService.snapshot(window_hours=...)``, which is where the
        existing queries already take a window. A range the stored aggregates
        cannot cover is disabled rather than shown empty, so the control never
        offers a view the database cannot answer (§1).
        """
        bar = ttk.Frame(parent, style="TFrame")
        bar.pack(fill="x", pady=(0, 10))

        ttk.Label(bar, text="TIME RANGE", style="CardDim.TLabel").pack(
            side="left", padx=(0, 10)
        )
        self._range_buttons: dict[str, ttk.Button] = {}
        for label, hours in TIME_RANGES:
            button = ttk.Button(
                bar, text=label, style="Tool.TButton", width=5,
                command=lambda h=hours: self.set_window(h),
            )
            button.pack(side="left", padx=(0, 4))
            attach_tooltip(
                button,
                f"Show the last {label} of stored activity. "
                "Disabled when the database holds nothing that far back.",
            )
            self._range_buttons[label] = button

        self._range_note = ttk.Label(bar, text="", style="CardDim.TLabel")
        self._range_note.pack(side="right")
        self._paint_range_buttons()

    def set_window(self, hours: float) -> None:
        """Switch the page to a different window and reload."""
        if abs(hours - self._window_hours) < 1e-9:
            return
        self._window_hours = hours
        self._paint_range_buttons()
        self.refresh()

    def _paint_range_buttons(self) -> None:
        """Highlight the active range and disable the ones with no data."""
        covered = self._covered_hours
        for label, hours in TIME_RANGES:
            button = self._range_buttons.get(label)
            if button is None:
                continue
            active = abs(hours - self._window_hours) < 1e-9
            button.configure(style="ToolAccent.TButton" if active else "Tool.TButton")
            # A range is offered when the stored history reaches into it, or
            # when nothing is stored yet and every range is equally empty.
            usable = covered is None or hours <= covered or active
            button.state(["!disabled"] if usable else ["disabled"])

    def _build_stat_row(self, parent: tk.Misc) -> None:
        """Headline metrics (§9)."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=(0, 12))
        definitions = (
            (
                "packets", "Packets today", PALETTE.accent, "traffic", True,
                "Packets captured since local midnight, counted from stored "
                "traffic aggregates. Click to open Network Monitoring.",
            ),
            (
                "hosts", "Active hosts", PALETTE.info, "hosts", False,
                "Hosts seen in the last 24 hours, from capture or assessment. "
                "Click to open the host inventory.",
            ),
            (
                "ports", "Open ports", PALETTE.medium, "vulnerabilities", False,
                "Open ports recorded by the most recent assessment of each "
                "host. An open port is an exposure to review, not a "
                "vulnerability in itself.",
            ),
            (
                "alerts", "IDS alerts today", PALETTE.high, "alerts", True,
                "Snort alerts received since local midnight. Alerts appear only "
                "when a real sensor sends them.",
            ),
            (
                "incidents", "Open incidents", PALETTE.critical, "incidents", False,
                "Correlated incidents still requiring attention. Click to open "
                "the incident queue.",
            ),
            (
                "findings", "Open findings", PALETTE.low, "vulnerabilities", False,
                "Assessment findings that have not been resolved.",
            ),
        )
        self._stat_row = row
        self._stat_order: list[MetricTile] = []
        for key, label, colour, target, sparkline, tip in definitions:
            card = MetricTile(
                row, label, page=PALETTE.background, colour=colour,
                glyph=METRIC_GLYPHS.get(key, "●"), fonts=self.fonts,
                on_click=lambda t=target: self.app.navigate(t),
            )
            attach_tooltip(card, tip)
            self._stat_cards[key] = card
            self._stat_order.append(card)

        self._stat_columns = 0
        self._layout_stat_row(len(definitions))
        # Six tiles do not fit on a narrow window, and squeezing them until the
        # numbers clip defeats the point of a headline metric. They reflow onto
        # a second line instead.
        row.bind("<Configure>", self._on_stat_row_configure)

    def _on_stat_row_configure(self, event: tk.Event) -> None:
        """Re-flow the metric tiles when the window width changes."""
        count = len(self._stat_order)
        fits = max(1, min(count, int(event.width) // MIN_TILE_WIDTH))
        self._layout_stat_row(_balanced_columns(count, fits))

    def _layout_stat_row(self, columns: int) -> None:
        """Grid the tiles into ``columns`` per line."""
        if columns == self._stat_columns or not self._stat_order:
            return
        self._stat_columns = columns
        for index in range(len(self._stat_order)):
            self._stat_row.columnconfigure(index, weight=0, uniform="")
        for index, card in enumerate(self._stat_order):
            line, column = divmod(index, columns)
            card.grid(
                row=line, column=column, sticky="ew",
                padx=(0 if column == 0 else 14, 0),
                pady=(0 if line == 0 else 14, 0),
            )
        for column in range(columns):
            # ``uniform`` keeps the tiles on a line the same width, so one long
            # detail line cannot squeeze the tiles beside it.
            self._stat_row.columnconfigure(column, weight=1, uniform="stat")

    def _build_status_and_traffic(self, parent: tk.Misc) -> None:
        """The live traffic chart, given the full width of the page.

        The subsystem indicators used to sit beside it and halve its width. A
        rate chart is read by its shape, so it gets the room; the indicators
        move to their own zone, where they can be laid out across the page.
        """
        traffic_card = Card(
            parent, "Network traffic", subtitle="packets per second",
            fonts=self.fonts, accent=PALETTE.accent,
        )
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
        self._uptime_label.pack(anchor="w", pady=(16, 0))

    def _build_charts_row(self, parent: tk.Misc) -> None:
        """IDS activity, alert severity mix and protocol mix."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=(0, 12))

        ids_card = Card(row, "IDS alerts", subtitle="per 15 minutes", fonts=self.fonts)
        ids_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._alert_chart = TimeSeriesChart(
            ids_card, height=150, colour=PALETTE.high,
            empty_message="No IDS alerts recorded",
            empty_detail=(
                "Alerts appear here only when a real Snort sensor sends them "
                "over the configured transport."
            ),
            value_formatter=lambda v: f"{v:,.0f}",
        )
        self._alert_chart.pack(fill="both", expand=True)

        severity_card = Card(row, "Alert severity", fonts=self.fonts)
        severity_card.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        self._severity_chart = DonutChart(
            severity_card, height=150, colour_by_severity=True,
            centre_label="alerts (24h)",
            empty_message="No alerts in the last 24 hours",
            on_select=lambda severity: self.app.navigate("alerts", search=severity),
        )
        self._severity_chart.pack(fill="both", expand=True)

        protocol_card = Card(row, "Protocol distribution", fonts=self.fonts)
        protocol_card.grid(row=0, column=2, sticky="nsew")
        self._protocol_chart = DonutChart(
            protocol_card, height=150, centre_label="packets (24h)",
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
            row, "Threat timeline", subtitle="correlated incidents", fonts=self.fonts
        )
        timeline_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._timeline = TimelineChart(
            timeline_card, height=130,
            empty_message="No correlated incidents in the last 24 hours",
            empty_detail=(
                "Incidents are created only from real evidence produced by "
                "Nmap, PyShark or Snort."
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
        """Reload the dashboard from stored records."""
        session = self.session
        dashboard = self.context.dashboard
        if session is None or dashboard is None:
            return
        window = self._window_hours
        self.status(f"Loading dashboard ({self._range_label()})...")
        self.run_async(
            lambda: (
                dashboard.snapshot(session, window_hours=window),
                dashboard.network_overview(session, window_hours=window),
            ),
            self._apply,
            name="dashboard-load",
        )

    def _range_label(self) -> str:
        """The label of the active window."""
        for label, hours in TIME_RANGES:
            if abs(hours - self._window_hours) < 1e-9:
                return label
        return f"{self._window_hours:g}h"

    def _note_coverage(self, snapshot: DashboardSnapshot) -> None:
        """Learn how far back the stored aggregates actually reach.

        The oldest point the traffic series returned is the honest limit of
        what any longer window could show, so ranges beyond it are disabled
        rather than drawn as a flat empty chart.
        """
        stamps = [
            at for at, _value in (snapshot.traffic_series or ())
            if isinstance(at, datetime)
        ]
        if not stamps:
            self._covered_hours = None
        else:
            span = (utcnow() - min(stamps)).total_seconds() / 3600.0
            # A little slack, so a window that only just reaches the oldest
            # sample is still offered.
            self._covered_hours = max(span * 1.1, 1.0)
        self._paint_range_buttons()
        self._range_note.configure(
            text=(
                f"showing the last {self._range_label()}"
                if self._covered_hours is not None
                else "no stored history yet"
            )
        )

    def _apply(self, payload: tuple[DashboardSnapshot, dict[str, Any]]) -> None:
        """Render a freshly loaded snapshot."""
        snapshot, overview = payload
        self._snapshot = snapshot
        self._note_coverage(snapshot)
        self._update_stats(snapshot)
        self._update_indicators()
        self._update_charts(snapshot, overview)
        self._update_lists(snapshot)
        self.status(
            f"Dashboard updated {format_local(snapshot.generated_at, '%H:%M:%S')}"
            + ("" if snapshot.has_any_data else " - no security records yet.")
        )

    def _update_stats(self, snapshot: DashboardSnapshot) -> None:
        """Update the headline tiles."""
        self._stat_cards["packets"].update_value(
            format_count(snapshot.packets_today),
            f"{format_count(snapshot.total_packets_stored)} observed in total"
            if snapshot.total_packets_stored
            else "No packets captured yet",
        )
        self._stat_cards["hosts"].update_value(
            format_count(snapshot.active_hosts),
            f"{format_count(snapshot.observed_hosts)} known in inventory",
        )
        self._stat_cards["ports"].update_value(
            format_count(snapshot.open_ports),
            f"{format_count(snapshot.scans_total)} assessment(s) run",
        )
        self._stat_cards["alerts"].update_value(
            format_count(snapshot.ids_alerts_today),
            (
                f"{snapshot.critical_alerts} critical / {snapshot.high_alerts} high (24h)"
                if snapshot.ids_alerts_total
                else "No Snort alerts received"
            ),
            accent=PALETTE.critical if snapshot.critical_alerts else PALETTE.high,
        )
        self._stat_cards["incidents"].update_value(
            format_count(snapshot.open_incidents),
            f"{format_count(snapshot.anomalies_today)} traffic anomal(y/ies) today",
        )
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
            snapshot.packets_today, snapshot.packets_previous_period
        )
        self._stat_cards["alerts"].update_sparkline(
            [float(value) for _stamp, value in snapshot.alert_series]
        )
        self._stat_cards["alerts"].update_trend(
            snapshot.ids_alerts_today, snapshot.alerts_previous_period
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
                    at=entry["last_seen"] or entry["first_seen"],
                    severity=entry["severity"],
                    label=entry["reference"],
                )
                for entry in snapshot.threat_timeline
                if entry.get("last_seen") or entry.get("first_seen")
            ]
        )

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
        """React to live events without re-querying everything (§113)."""
        if event.type == EventType.TRAFFIC_STATS_UPDATED:
            snapshot = getattr(event.payload, "snapshot", None)
            if snapshot is not None and snapshot.pps_series:
                self._traffic_chart.set_points(
                    [(p.timestamp, p.value) for p in snapshot.pps_series]
                )
                self._traffic_summary.configure(
                    text=(
                        f"Live: {format_rate(snapshot.packets_per_second)} · "
                        f"{format_bandwidth(snapshot.bytes_per_second)} · "
                        f"{format_count(snapshot.total_packets)} captured · "
                        f"{format_count(snapshot.active_hosts)} active host(s)"
                    )
                )
                self._talkers_chart.set_items(
                    [(t.label, float(t.packets)) for t in snapshot.top_sources]
                )
                self._protocol_chart.set_items(
                    [(p.protocol, float(p.packets)) for p in snapshot.protocols]
                )
        elif event.type in (
            EventType.SNORT_ALERT_RECEIVED, EventType.INCIDENT_CREATED,
            EventType.NMAP_SCAN_COMPLETED, EventType.TRAFFIC_ANOMALY_DETECTED,
        ):
            self.refresh()
        elif event.type in (
            EventType.SERVICE_STATUS_CHANGED, EventType.DATABASE_STATUS_CHANGED,
            EventType.SNORT_STATUS_CHANGED,
            EventType.CAPTURE_STARTED, EventType.CAPTURE_STOPPED,
        ):
            self._update_indicators()

    def on_tick(self) -> None:
        """Refresh stored counters periodically, indicators every tick."""
        self._refresh_counter += 1
        self._update_indicators()
        if self._refresh_counter % 10 == 0:
            self.refresh()
