"""System health and diagnostics screen (§39, §71).

Every row on this page is a live probe result. A subsystem is shown as healthy
only when it answered; nothing is assumed and nothing is optimistic (§120).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.enums import CheckResult
from aethra_sec.models.system import DiagnosticsReport, ServiceStatus
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget, state_colour
from aethra_sec.ui.widgets import (
    Card,
    Column,
    DataTable,
    ScrollableFrame,
    StatusIndicator,
    Toolbar,
    show_message,
)
from aethra_sec.utils.formatting import format_bytes, format_count
from aethra_sec.utils.timeutil import format_local

CHECK_COLUMNS = (
    Column("result", "Result", width=90, colour_by="state"),
    Column("name", "Check", width=230),
    Column("category", "Category", width=120),
    Column("summary", "Outcome", width=420, stretch=True),
    Column("remedy", "What to do", width=380),
)


class HealthScreen(Screen):
    """Live subsystem status, diagnostics and runtime detail."""

    title = "System Health"
    subtitle = "Live subsystem probes, diagnostics and runtime statistics"
    required_permission = "health.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._indicators: dict[str, StatusIndicator] = {}

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the health screen.

        Wrapped in a :class:`ScrollableFrame`, matching the Alerts screen: a
        fixed-height page must never leave content unreachable whenever it is
        taller than the window (§ layout).
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        status_card = Card(
            root, "Subsystem status", subtitle="probed live", fonts=self.fonts,
            padding=18,
        )
        status_card.pack(fill="x")

        grid = ttk.Frame(status_card, style="Card.TFrame")
        grid.pack(fill="x")
        names = (
            ("application", "AETHRA-SEC"), ("database", "Database (MySQL)"),
            ("nmap", "Nmap"), ("tshark", "PyShark / TShark"),
            ("capture", "Packet capture"), ("snort", "Snort IDS"),
        )
        for index, (key, label) in enumerate(names):
            indicator = StatusIndicator(grid, label)
            indicator.grid(
                row=index // 3, column=index % 3, sticky="nsew", padx=(0, 18), pady=4
            )
            self._indicators[key] = indicator
        for column in range(3):
            grid.columnconfigure(column, weight=1)

        toolbar = Toolbar(status_card)
        toolbar.pack(fill="x", pady=(16, 0))
        toolbar.add_button("Re-probe now", self._probe, style="Accent.TButton")
        toolbar.add_button("Run diagnostics", self._run_diagnostics)
        if self.can("health.detail"):
            toolbar.add_button("Runtime detail", self._show_runtime)
        self._probe_label = toolbar.add_label("", side="right")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, pady=(16, 0))

        diagnostics = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(diagnostics, text="Diagnostics")
        self._build_diagnostics(diagnostics)

        runtime = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(runtime, text="Runtime")
        self._build_runtime(runtime)

    def _build_diagnostics(self, parent: tk.Misc) -> None:
        """Diagnostics results table (§71)."""
        card = Card(parent, "Diagnostic checks", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)
        self._diagnostics_summary = ttk.Label(
            card, text="Select 'Run diagnostics' to check every dependency.",
            style="CardMuted.TLabel", wraplength=1000, justify="left",
        )
        self._diagnostics_summary.pack(anchor="w", pady=(0, 8))
        self._checks_table = DataTable(card, CHECK_COLUMNS, height=16)
        self._checks_table.pack(fill="both", expand=True)

    def _build_runtime(self, parent: tk.Misc) -> None:
        """Runtime statistics pane."""
        card = Card(parent, "Runtime statistics", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)
        self._runtime_text = tk.Text(card, wrap="word")
        configure_text_widget(self._runtime_text, self.fonts, mono=True)
        scrollbar = ttk.Scrollbar(
            card, orient="vertical", command=self._runtime_text.yview
        )
        self._runtime_text.configure(yscrollcommand=scrollbar.set, state="disabled")
        self._runtime_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def on_show(self) -> None:
        """Probe on entry."""
        self._probe()
        self._refresh_runtime()

    def _probe(self) -> None:
        """Re-probe every subsystem."""
        health = self.context.health
        if health is None:
            return
        self.status("Probing subsystems...")
        self.run_async(health.probe_all, self._apply_statuses, name="health-probe")

    def _apply_statuses(self, statuses: dict[str, ServiceStatus]) -> None:
        """Render the probe results."""
        for key, indicator in self._indicators.items():
            status = statuses.get(key)
            if status is not None:
                indicator.update_state(str(status.state), status.detail)
        unhealthy = [s.name for s in statuses.values() if not s.is_healthy]
        self._probe_label.configure(
            text=(
                "All probed subsystems responded."
                if not unhealthy
                else f"Not healthy: {', '.join(unhealthy)}"
            )
        )
        self.status(
            "Subsystem probe complete."
            if not unhealthy
            else f"Subsystem probe complete - {len(unhealthy)} not healthy."
        )
        self._refresh_runtime()

    def _run_diagnostics(self) -> None:
        """Run the full diagnostics suite."""
        health = self.context.health
        if health is None:
            return
        self.status("Running diagnostics...")
        self.run_async(
            health.run_diagnostics, self._apply_diagnostics, name="diagnostics"
        )

    def _apply_diagnostics(self, report: DiagnosticsReport) -> None:
        """Render the diagnostics table."""
        self._checks_table.set_rows(
            [
                {
                    "result": str(check.result),
                    "name": check.name,
                    "category": check.category,
                    "summary": check.summary,
                    "remedy": check.remedy or "-",
                }
                for check in report.checks
            ]
        )
        colour = PALETTE.ok if report.is_ready else PALETTE.critical
        self._diagnostics_summary.configure(
            text=(
                f"{report.passed} passed · {report.warnings} warning(s) · "
                f"{report.failures} failure(s) · system "
                f"{'ready' if report.is_ready else 'NOT ready'} · checked "
                f"{format_local(report.generated_at)}"
            ),
            foreground=colour,
        )
        self.status(
            f"Diagnostics: {report.passed} pass, {report.warnings} warning, "
            f"{report.failures} fail."
        )

    def _refresh_runtime(self) -> None:
        """Render the runtime statistics pane."""
        health = self.context.health
        if health is None:
            return
        details = health.runtime_details()
        lines = ["RUNTIME", ""]
        for key in (
            "application_version", "python_version", "platform", "uptime",
            "started_at", "last_probe", "env_file", "log_directory",
            "report_directory", "active_sessions",
        ):
            if key in details:
                lines.append(f"  {key:<22}: {details[key]}")

        pool = details.get("database_pool", {})
        if pool:
            lines.extend(["", "DATABASE POOL", ""])
            for key, value in pool.items():
                lines.append(f"  {key:<22}: {value}")

        capture = details.get("capture", {})
        if capture:
            lines.extend(["", "PACKET CAPTURE", ""])
            for key, value in capture.items():
                lines.append(f"  {key:<22}: {value}")

        snort = details.get("snort", {})
        if snort:
            lines.extend(["", "SNORT INGEST", ""])
            for key, value in snort.items():
                lines.append(f"  {key:<22}: {value}")

        correlation = details.get("correlation")
        if correlation is not None:
            lines.extend(["", "CORRELATION ENGINE", ""])
            for key in (
                "runs", "events_processed", "incidents_created",
                "incidents_updated", "alerts_attached", "anomalies_attached",
                "findings_linked", "errors",
                "last_run_at",
            ):
                lines.append(f"  {key:<22}: {getattr(correlation, key, '-')}")

        bus = details.get("event_bus", {})
        if bus:
            lines.extend(["", "EVENT BUS", ""])
            for key, value in bus.items():
                lines.append(f"  {key:<22}: {value}")

        jobs = details.get("scheduler", [])
        if jobs:
            lines.extend(["", "BACKGROUND JOBS", ""])
            for job in jobs:
                lines.append(
                    f"  {str(job['name']):<20} every {job['interval_seconds']:>7.1f}s  "
                    f"runs {job['runs']:>5}  errors {job['errors']:>3}  "
                    f"last {format_local(job['last_run'])}"
                    + (f"  ERROR: {job['last_error']}" if job["last_error"] else "")
                )

        capture_service = self.context.capture
        if capture_service is not None:
            lines.extend(["", "DETECTION RULES", ""])
            for key, value in capture_service.rules.statistics.items():
                lines.append(f"  {key:<22}: {format_count(int(value))}")
            lines.extend(["", "CAPTURE PIPELINE", ""])
            for key, value in capture_service.counters.snapshot().items():
                lines.append(f"  {key:<22}: {value}")

        self._runtime_text.configure(state="normal")
        self._runtime_text.delete("1.0", "end")
        self._runtime_text.insert("1.0", "\n".join(lines))
        self._runtime_text.configure(state="disabled")

    def _show_runtime(self) -> None:
        """Show the runtime detail in a dialog."""
        health = self.context.health
        if health is None:
            return
        details = health.runtime_details()
        show_message(
            self, "Runtime detail", "Live runtime statistics",
            detail="\n".join(f"{key}: {value}" for key, value in details.items()),
            fonts=self.fonts, mono=True,
        )

    def handle_event(self, event: Event) -> None:
        """Repaint when a subsystem changes state."""
        if event.type in (
            EventType.SERVICE_STATUS_CHANGED, EventType.DATABASE_STATUS_CHANGED,
            EventType.SNORT_STATUS_CHANGED,
            EventType.CAPTURE_STARTED, EventType.CAPTURE_STOPPED,
            EventType.CAPTURE_ERROR,
        ):
            health = self.context.health
            if health is not None:
                self._apply_statuses(health.statuses())

    def on_tick(self) -> None:
        """Keep the runtime pane current."""
        self._refresh_runtime()
