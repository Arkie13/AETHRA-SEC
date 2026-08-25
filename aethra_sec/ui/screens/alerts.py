"""IDS alert screen (§43, §66).

Lists real Snort alerts with search, filtering, workflow status, analyst
classification, related evidence and mitigation guidance. When no sensor is
connected the screen says so, using the transport's own status text.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timedelta
from tkinter import ttk
from typing import Any, Sequence

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import AlertStatus, EvaluationLabel, Severity
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget, state_colour
from aethra_sec.ui.widgets import (
    Card, Column, confirm, DataTable, DetailDialog, FilterBar, RowAction,
    ScrollableFrame, SummaryCell, SummaryStrip, Toolbar, show_message,
)
from aethra_sec.utils.formatting import format_count, truncate
from aethra_sec.utils.timeutil import format_local, format_local_ms, utcnow

ALERT_COLUMNS = (
    Column("time", "Time", width=145),
    Column("severity", "Severity", width=100, colour_by="severity", glyph=True),
    Column("priority", "Prio", width=48, anchor="e"),
    Column("signature", "Signature", width=125),
    Column("message", "Message", width=300, stretch=True),
    Column("protocol", "Proto", width=60),
    Column("source", "Source", width=150),
    Column("destination", "Destination", width=150),
    Column("count", "Seen", width=52, anchor="e"),
    Column("status", "Status", width=95, colour_by="status"),
    Column("evaluation", "Evaluation", width=120),
)

def _alert_counts(alerts: Sequence[SnortAlert]) -> dict[str, int]:
    """Severity and review tallies for the summary strip.

    Counted from the alerts the current filters returned, so the strip can
    never disagree with the queue underneath it.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unreviewed": 0}
    for alert in alerts:
        severity = str(alert.severity).upper()
        if severity == "CRITICAL":
            counts["critical"] += 1
        elif severity == "HIGH":
            counts["high"] += 1
        elif severity == "MEDIUM":
            counts["medium"] += 1
        else:
            counts["low"] += 1
        if str(alert.status).upper() == "NEW":
            counts["unreviewed"] += 1
    return counts


class AlertsScreen(Screen):
    """Review and classify real Snort alerts."""

    title = "IDS Alerts"
    subtitle = "Snort intrusion detection alerts received over the configured transport"
    required_permission = "alert.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._alerts: dict[int, SnortAlert] = {}
        self._alerts_cleared_at: datetime | None = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the alerts screen.

        Wrapped in a :class:`ScrollableFrame` so a fixed-height page never
        leaves content unreachable whenever it is taller than the window
        (§ layout).
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        self._build_status_bar(root)
        self._build_summary(root)
        self._build_filters(root)

        body = ttk.Frame(root, style="TFrame")
        body.pack(fill="both", expand=True, pady=(16, 0))

        table_card = Card(body, "Alerts", fonts=self.fonts, padding=18)
        table_card.pack(fill="both", expand=True)

        toolbar = Toolbar(table_card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Details", self._show_detail)
        toolbar.add_button("Mark reviewed", lambda: self._set_status(AlertStatus.REVIEWED))
        toolbar.add_button(
            "Acknowledge", lambda: self._set_status(AlertStatus.ACKNOWLEDGED)
        )
        toolbar.add_button("Escalate", lambda: self._set_status(AlertStatus.ESCALATED))
        toolbar.add_button("Mark all read", self._mark_all_reviewed)
        toolbar.add_separator()
        toolbar.add_button(
            "True positive", lambda: self._classify(EvaluationLabel.TRUE_POSITIVE)
        )
        toolbar.add_button(
            "False positive", lambda: self._classify(EvaluationLabel.FALSE_POSITIVE)
        )
        toolbar.add_button(
            "Benign/expected", lambda: self._classify(EvaluationLabel.BENIGN_EXPECTED)
        )
        toolbar.add_separator()
        toolbar.add_button("Open incident", self._open_incident)
        toolbar.add_button("Export", self._export)
        toolbar.add_separator()
        toolbar.add_button("Clear display", self._clear_alerts_display)
        self._count_label = toolbar.add_label("", side="right")

        self._table = DataTable(
            table_card, ALERT_COLUMNS, height=16,
            on_select=self._preview, on_activate=lambda _row: self._show_detail(),
            empty_text="No alerts have been received on the configured transport",
            actions=[
                RowAction("Show full alert", lambda _row: self._show_detail()),
                RowAction(
                    "Mark reviewed",
                    lambda _row: self._set_status(AlertStatus.REVIEWED),
                ),
                RowAction(
                    "Acknowledge",
                    lambda _row: self._set_status(AlertStatus.ACKNOWLEDGED),
                ),
                RowAction(
                    "Escalate", lambda _row: self._set_status(AlertStatus.ESCALATED)
                ),
                RowAction(
                    "Classify true positive",
                    lambda _row: self._classify(EvaluationLabel.TRUE_POSITIVE),
                ),
                RowAction(
                    "Classify false positive",
                    lambda _row: self._classify(EvaluationLabel.FALSE_POSITIVE),
                ),
                RowAction("Open incident", lambda _row: self._open_incident()),
            ],
        )
        self._table.pack(fill="both", expand=True)

        preview = Card(root, "Alert evidence", fonts=self.fonts, padding=18)
        preview.pack(fill="x", pady=(16, 0))
        self._preview_text = tk.Text(preview, height=8, wrap="word")
        configure_text_widget(self._preview_text, self.fonts, mono=True)
        self._preview_text.insert("1.0", "Select an alert to see its evidence.")
        self._preview_text.configure(state="disabled")
        self._preview_text.pack(fill="x")

    def _build_status_bar(self, parent: tk.Misc) -> None:
        """Show the true Snort ingest state (§21)."""
        card = Card(parent, "Snort status", fonts=self.fonts, padding=18)
        card.pack(fill="x")
        self._snort_label = ttk.Label(
            card, text="Checking...", style="CardMuted.TLabel",
            wraplength=1000, justify="left",
        )
        self._snort_label.pack(anchor="w")
        self._reliability_label = ttk.Label(card, text="", style="CardDim.TLabel")
        self._reliability_label.pack(anchor="w", pady=(4, 0))

    def _build_summary(self, parent: tk.Misc) -> None:
        """Severity counts, so the queue is graded before it is read."""
        self._summary = SummaryStrip(
            parent,
            (
                SummaryCell("critical", "Critical", PALETTE.critical,
                            tooltip="Alerts at CRITICAL severity."),
                SummaryCell("high", "High", PALETTE.high,
                            tooltip="Alerts at HIGH severity."),
                SummaryCell("medium", "Medium", PALETTE.medium,
                            tooltip="Alerts at MEDIUM severity."),
                SummaryCell("low", "Low", PALETTE.low,
                            tooltip="Alerts at LOW or informational severity."),
                SummaryCell("unreviewed", "Unreviewed", PALETTE.accent,
                            tooltip="Alerts nobody has triaged yet."),
            ),
            fonts=self.fonts,
        )
        self._summary.pack(fill="x", pady=(16, 0))

    def _build_filters(self, parent: tk.Misc) -> None:
        """Search and filter controls (§41, §42)."""
        card = Card(parent, "Search and filter", fonts=self.fonts, padding=18)
        card.pack(fill="x", pady=(16, 0))
        row = FilterBar(card)
        row.pack(fill="x")

        ttk.Label(row, text="Search", style="CardMuted.TLabel").pack(side="left")
        self._search_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self._search_var, width=28)
        entry.pack(side="left", padx=(8, 14))
        entry.bind("<Return>", lambda _e: self.refresh())

        self._severity_var = tk.StringVar(value="All")
        self._status_var = tk.StringVar(value="All")
        self._window_var = tk.StringVar(value="Last 24 hours")
        for label, variable, values, width in (
            ("Severity", self._severity_var,
             ["All", *[str(s) for s in Severity]], 12),
            ("Status", self._status_var,
             ["All", *[str(s) for s in AlertStatus]], 14),
            ("Period", self._window_var,
             ["Last hour", "Last 24 hours", "Last 7 days", "Last 30 days", "All time"], 15),
        ):
            ttk.Label(row, text=label, style="CardMuted.TLabel").pack(side="left")
            ttk.Combobox(
                row, textvariable=variable, values=values, state="readonly", width=width
            ).pack(side="left", padx=(8, 14))

        ttk.Button(
            row, text="Apply", style="Accent.TButton", command=self.refresh
        ).pack(side="left", padx=(0, 6))
        ttk.Button(
            row, text="Reset", style="Ghost.TButton", command=self._reset_filters
        ).pack(side="left")

    def _reset_filters(self) -> None:
        """Clear every filter."""
        self._search_var.set("")
        self._severity_var.set("All")
        self._status_var.set("All")
        self._window_var.set("Last 24 hours")
        self._alerts_cleared_at = None
        self.refresh()

    def _clear_alerts_display(self) -> None:
        """Clear the visible Snort alert rows without touching stored alerts.

        Only the view resets: everything already received is untouched in
        the database. New alerts still appear as they arrive (including via
        the live SNORT_ALERT_RECEIVED refresh below) - only what had already
        accumulated is hidden, the same "clear display" the Live Packets
        view already offers.
        """
        self._alerts_cleared_at = utcnow()
        self._table.clear()
        self._alerts = {}
        self._count_label.configure(text="0 alert(s)")
        self.status("Display cleared. Stored alerts are unaffected.")

    def set_search(self, text: str) -> None:
        """Open the screen filtered to one address or signature (drill-down)."""
        self._search_var.set(str(text or ""))
        self._window_var.set("All time")
        self.refresh()

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload alerts using the current filters."""
        snort = self.context.snort
        session = self.session
        if snort is None or session is None:
            return
        self._update_snort_status()

        filters: dict[str, Any] = {"limit": 1000}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._severity_var.get() != "All":
            filters["severity"] = self._severity_var.get()
        if self._status_var.get() != "All":
            filters["status"] = self._status_var.get()
        window = {
            "Last hour": timedelta(hours=1),
            "Last 24 hours": timedelta(hours=24),
            "Last 7 days": timedelta(days=7),
            "Last 30 days": timedelta(days=30),
        }.get(self._window_var.get())
        window_start = utcnow() - window if window is not None else None
        # Take the later (more restrictive) of the period filter and a
        # "Clear display" watermark, so clearing never re-shows history the
        # period filter alone would have hidden, and vice versa.
        starts = [t for t in (window_start, self._alerts_cleared_at) if t is not None]
        if starts:
            filters["start"] = max(starts)

        self.status("Loading alerts...")
        self.run_async(
            lambda: snort.search(session, **filters), self._apply, name="alerts-load"
        )

    def _apply(self, alerts: list[SnortAlert]) -> None:
        """Render the alert table."""
        self._alerts = {a.id: a for a in alerts if a.id is not None}
        self._summary.update_counts(_alert_counts(alerts))
        self._table.set_rows(
            [
                {
                    "_id": alert.id,
                    "time": format_local(alert.effective_time, "%d %b %H:%M:%S"),
                    "severity": str(alert.severity),
                    "priority": alert.priority if alert.priority is not None else "-",
                    "signature": alert.signature_text,
                    "message": alert.message or "-",
                    "protocol": alert.protocol or "-",
                    "source": (
                        f"{alert.src_ip}:{alert.src_port}"
                        if alert.src_port
                        else alert.src_ip or "-"
                    ),
                    "destination": (
                        f"{alert.dst_ip}:{alert.dst_port}"
                        if alert.dst_port
                        else alert.dst_ip or "-"
                    ),
                    "count": alert.duplicate_count,
                    "status": str(alert.status),
                    "evaluation": alert.evaluation.label,
                }
                for alert in alerts
            ]
        )
        self._count_label.configure(text=f"{len(alerts):,} alert(s)")
        self.status(
            f"{len(alerts):,} alert(s) loaded."
            if alerts
            else "No IDS alerts match the current filters."
        )

    def _update_snort_status(self) -> None:
        """Show the real transport state and reliability counters (§84)."""
        snort = self.context.snort
        if snort is None:
            return
        status = snort.status()
        self._snort_label.configure(
            text=(
                f"{status.status_text} · transport: {status.transport} · "
                f"{status.endpoint or 'not configured'}\n{status.detail}"
            ),
            foreground=state_colour(
                "RUNNING" if status.is_connected else
                "DISABLED" if status.transport == "disabled" else "OFFLINE"
            ),
        )
        counters = snort.reliability()
        self._reliability_label.configure(
            text=(
                f"received {format_count(counters['received'])} · "
                f"stored {format_count(counters['stored'])} · "
                f"duplicates folded {format_count(counters['duplicates'])} · "
                f"parse failures {format_count(counters['parse_failures'])} · "
                f"correlated {format_count(counters['correlated'])} · "
                f"unreviewed {format_count(counters['unresolved'])}"
                + (
                    f" · last alert {format_local(status.last_alert_at)}"
                    if status.last_alert_at
                    else ""
                )
            )
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _selected_alert(self) -> SnortAlert | None:
        """The currently selected alert."""
        row = self._table.selected_row()
        if row is None:
            return None
        return self._alerts.get(int(row.get("_id") or 0))

    def _preview(self, _row: dict[str, Any]) -> None:
        """Show the selected alert's evidence in the preview pane."""
        alert = self._selected_alert()
        self._preview_text.configure(state="normal")
        self._preview_text.delete("1.0", "end")
        if alert is None:
            self._preview_text.insert("1.0", "Select an alert to see its evidence.")
        else:
            latency = alert.detection_latency_seconds
            self._preview_text.insert(
                "1.0",
                "\n".join(
                    [
                        f"Signature      : {alert.signature_text}  {alert.message}",
                        f"Classification : {alert.classification or 'not supplied by the sensor'}",
                        f"Severity       : {alert.severity} (Snort priority "
                        f"{alert.priority if alert.priority is not None else 'not supplied'})",
                        f"Sensor time    : {format_local_ms(alert.alert_time) if alert.alert_time else 'not supplied'}"
                        f"   ({alert.time_source})",
                        f"Received       : {format_local_ms(alert.received_at)}",
                        f"Ingest latency : {f'{latency:.3f} s' if latency is not None else 'not measurable - sensor supplied no timestamp'}",
                        f"Endpoints      : {alert.src_ip or '-'}:{alert.src_port or '-'}"
                        f" -> {alert.dst_ip or '-'}:{alert.dst_port or '-'} ({alert.protocol or '-'})",
                        f"Transport      : {alert.transport or '-'}    Sensor: {alert.sensor or '-'}",
                        f"Occurrences    : {alert.duplicate_count}",
                        f"Incident       : {alert.incident_id or 'not correlated yet'}",
                        "",
                        "RAW ALERT EVIDENCE:",
                        alert.raw_alert or "(the transport supplied no raw text)",
                    ]
                ),
            )
        self._preview_text.configure(state="disabled")

    def _show_detail(self) -> None:
        """Open the full alert detail, including mitigation guidance."""
        alert = self._selected_alert()
        if alert is None:
            self.status("Select an alert first.")
            return

        sections = [
            ("MESSAGE", alert.message or "-"),
            ("CLASSIFICATION", alert.classification or "Not supplied by the sensor"),
            ("RAW ALERT", alert.raw_alert or "(no raw text supplied)"),
        ]
        mitigation = self.context.mitigation
        if mitigation is not None:
            from aethra_sec.services.correlation_service import categorise_alert

            category = categorise_alert(alert)
            recommendation = mitigation.recommendation_for(
                category, severity=alert.severity
            )
            if recommendation is not None:
                sections.extend(
                    [
                        (
                            f"MITIGATION GUIDANCE ({recommendation.code})",
                            recommendation.explanation,
                        ),
                        ("WHY IT MATTERS", recommendation.why_it_matters),
                        ("IMMEDIATE ACTION", recommendation.immediate_action),
                        ("LONG-TERM ACTION", recommendation.long_term_action),
                        ("VERIFICATION", recommendation.verification_steps),
                    ]
                )
            else:
                from aethra_sec.services.mitigation_service import NO_RECOMMENDATION_TEXT

                sections.append(("MITIGATION GUIDANCE", NO_RECOMMENDATION_TEXT))

        DetailDialog(
            self,
            f"Alert {alert.signature_text}",
            rows=[
                ("Severity", str(alert.severity)),
                ("Snort priority", str(alert.priority) if alert.priority is not None else "-"),
                ("Sensor timestamp", format_local(alert.alert_time) or "-"),
                ("Received", format_local(alert.received_at)),
                ("Source", f"{alert.src_ip or '-'}:{alert.src_port or '-'}"),
                ("Destination", f"{alert.dst_ip or '-'}:{alert.dst_port or '-'}"),
                ("Protocol", alert.protocol or "-"),
                ("Transport", alert.transport or "-"),
                ("Occurrences", str(alert.duplicate_count)),
                ("Workflow status", str(alert.status)),
                ("Analyst evaluation", alert.evaluation.label),
                ("Incident", str(alert.incident_id) if alert.incident_id else "Not correlated"),
                ("Evidence source", "Snort"),
            ],
            sections=sections,
            fonts=self.fonts,
        ).show()

    def _set_status(self, status: AlertStatus) -> None:
        """Change the selected alert's workflow status."""
        alert = self._selected_alert()
        snort = self.context.snort
        session = self.session
        if alert is None or alert.id is None or snort is None or session is None:
            self.status("Select an alert first.")
            return
        self.run_async(
            lambda: snort.set_status(session, alert.id or 0, status),
            lambda _r: (self.status(f"Alert {alert.id} marked {status}."), self.refresh()),
            name="alert-status",
        )

    def _mark_all_reviewed(self) -> None:
        """Move every NEW alert to REVIEWED, clearing the sidebar badge.

        Only the workflow status changes - nothing is deleted or resolved,
        so the full alert history stays exactly as it was received.
        """
        snort = self.context.snort
        session = self.session
        if snort is None or session is None:
            return
        if not confirm(
            self,
            "Mark all alerts read",
            "Mark every unreviewed alert as reviewed?",
            detail="This only updates the workflow status. Nothing is deleted, "
            "resolved, or hidden - reviewed alerts stay searchable as before.",
            confirm_label="Mark all read",
        ):
            return
        # A "Status: NEW" filter would otherwise hide every row this just
        # touched, making a full table look like it was wiped.
        if self._status_var.get() == str(AlertStatus.NEW):
            self._status_var.set("All")
        self.run_async(
            lambda: snort.mark_all_reviewed(session),
            lambda count: (
                self.status(f"{count} alert(s) marked reviewed."),
                self.refresh(),
                self.app.refresh_nav_badges(),
            ),
            name="alert-mark-all-reviewed",
        )

    def _classify(self, label: EvaluationLabel) -> None:
        """Record the analyst's true/false-positive judgement (§82)."""
        alert = self._selected_alert()
        snort = self.context.snort
        session = self.session
        if alert is None or alert.id is None or snort is None or session is None:
            self.status("Select an alert first.")
            return
        self.run_async(
            lambda: snort.classify(session, alert.id or 0, label),
            lambda _r: (
                self.status(f"Alert {alert.id} classified as {label.label}."),
                self.refresh(),
            ),
            name="alert-classify",
        )

    def _open_incident(self) -> None:
        """Jump to the incident this alert was correlated into."""
        alert = self._selected_alert()
        if alert is None:
            self.status("Select an alert first.")
            return
        if not alert.incident_id:
            show_message(
                self, "No incident",
                "This alert has not been correlated into an incident yet.",
                detail=(
                    "The correlation engine runs on a short interval. Alerts "
                    "are grouped by source, destination and threat category."
                ),
                fonts=self.fonts,
            )
            return
        self.app.navigate("incidents", focus_incident=int(alert.incident_id))

    def _export(self) -> None:
        """Export the visible alerts to CSV."""
        reports = self.context.reports
        session = self.session
        if reports is None or session is None:
            return
        rows = self._table.export_rows(visible_only=True)
        columns = self._table.export_columns()
        self.run_async(
            lambda: str(
                reports.export_records(
                    session, columns, rows, filename=f"alerts_{len(rows)}",
                    description="IDS alerts",
                )
            ),
            lambda path: show_message(
                self, "Export complete",
                f"{len(rows)} alert(s) exported" if rows
                else "No records available for export.",
                detail=f"Written to:\n{path}", fonts=self.fonts,
            ),
            name="alert-export",
        )

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """Refresh when a new alert arrives or the transport changes state."""
        if event.type == EventType.SNORT_ALERT_RECEIVED:
            self.refresh()
        elif event.type == EventType.SNORT_STATUS_CHANGED:
            self._update_snort_status()
