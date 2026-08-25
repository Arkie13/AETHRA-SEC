"""Logs and audit screen (§69, §56).

Shows the hash-chained audit trail, recorded subsystem errors and the rotating
diagnostic log, with search, filtering, export and integrity verification. A
failed verification is reported as ``LOG INTEGRITY WARNING`` and never silently
corrected.
"""

from __future__ import annotations

import tkinter as tk
from datetime import timedelta
from tkinter import ttk
from typing import Any

from aethra_sec.models.user import AuditRecord
from aethra_sec.security.integrity import IntegrityReport
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    Card, Column, DataTable, DetailDialog, FilterBar, ScrollableFrame, Toolbar,
    show_message,
)
from aethra_sec.utils.formatting import format_count, truncate
from aethra_sec.utils.timeutil import format_local, utcnow

AUDIT_COLUMNS = (
    Column("time", "Time", width=155),
    Column("user", "User", width=110),
    Column("action", "Action", width=185),
    Column("category", "Category", width=110),
    Column("target", "Target", width=170),
    Column("result", "Result", width=85, colour_by="state"),
    Column("detail", "Detail", width=430, stretch=True),
)

ERROR_COLUMNS = (
    Column("time", "Time", width=155),
    Column("component", "Component", width=140),
    Column("severity", "Severity", width=95, colour_by="severity", glyph=True),
    Column("message", "Message", width=420, stretch=True),
    Column("acknowledged", "Ack", width=60),
)


class LogsScreen(Screen):
    """Audit trail, error log and diagnostic log."""

    title = "Logs & Audit"
    subtitle = "Append-only audit trail with SHA-256 chained integrity hashes"
    required_permission = "log.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._records: dict[int, AuditRecord] = {}

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the logs screen.

        Wrapped in a :class:`ScrollableFrame`, matching the Alerts screen: a
        fixed-height page must never leave content unreachable whenever it is
        taller than the window (§ layout).
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        self._build_filters(root)

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, pady=(16, 0))

        audit_tab = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(audit_tab, text="Audit trail")
        self._build_audit(audit_tab)

        errors_tab = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(errors_tab, text="System errors")
        self._build_errors(errors_tab)

        app_tab = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(app_tab, text="Application log")
        self._build_application_log(app_tab)

    def _build_filters(self, parent: tk.Misc) -> None:
        """Audit search and filter controls."""
        card = Card(parent, "Search and filter", fonts=self.fonts, padding=18)
        card.pack(fill="x")
        row = FilterBar(card)
        row.pack(fill="x")

        ttk.Label(row, text="Search", style="CardMuted.TLabel").pack(side="left")
        self._search_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self._search_var, width=26)
        entry.pack(side="left", padx=(8, 14))
        entry.bind("<Return>", lambda _e: self.refresh())

        self._action_var = tk.StringVar(value="All")
        self._category_var = tk.StringVar(value="All")
        self._result_var = tk.StringVar(value="All")
        self._period_var = tk.StringVar(value="Last 7 days")

        for label, variable, width in (
            ("Action", self._action_var, 24),
            ("Category", self._category_var, 16),
            ("Result", self._result_var, 12),
            ("Period", self._period_var, 15),
        ):
            ttk.Label(row, text=label, style="CardMuted.TLabel").pack(side="left")
            combo = ttk.Combobox(
                row, textvariable=variable, state="readonly", width=width
            )
            combo.pack(side="left", padx=(8, 14))
            if variable is self._result_var:
                combo.configure(values=["All", "SUCCESS", "FAILURE", "DENIED", "WARNING"])
            elif variable is self._period_var:
                combo.configure(
                    values=[
                        "Last hour", "Last 24 hours", "Last 7 days",
                        "Last 30 days", "All time",
                    ]
                )
            else:
                setattr(self, f"_{label.lower()}_combo", combo)
                combo.configure(values=["All"])

        ttk.Button(row, text="Apply", style="Accent.TButton", command=self.refresh).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(row, text="Reset", style="Ghost.TButton", command=self._reset).pack(
            side="left"
        )

    def _reset(self) -> None:
        """Clear every filter."""
        self._search_var.set("")
        self._action_var.set("All")
        self._category_var.set("All")
        self._result_var.set("All")
        self._period_var.set("Last 7 days")
        self.refresh()

    def _build_audit(self, parent: tk.Misc) -> None:
        """Audit trail table with integrity controls."""
        card = Card(parent, "Audit records", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Record detail", self._show_record)
        toolbar.add_button(
            "Verify integrity", self._verify_integrity, enabled=self.can("log.verify")
        )
        toolbar.add_button("Export", self._export, enabled=self.can("log.export"))
        self._count_label = toolbar.add_label("", side="right")

        self._integrity_label = ttk.Label(
            card, text="", style="CardMuted.TLabel", wraplength=1000, justify="left"
        )
        self._integrity_label.pack(anchor="w", pady=(0, 6))

        self._table = DataTable(
            card, AUDIT_COLUMNS, height=16,
            on_activate=lambda _row: self._show_record(),
        )
        self._table.pack(fill="both", expand=True)

    def _build_errors(self, parent: tk.Misc) -> None:
        """Recorded subsystem errors (§57, §58)."""
        card = Card(parent, "Recorded subsystem failures", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)
        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Refresh", self._load_errors)
        toolbar.add_button("Acknowledge", self._acknowledge_error)
        self._error_table = DataTable(card, ERROR_COLUMNS, height=14)
        self._error_table.pack(fill="both", expand=True)

    def _build_application_log(self, parent: tk.Misc) -> None:
        """Tail of the rotating diagnostic log."""
        card = Card(parent, "Application log", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)
        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Reload", self._load_application_log)
        self._log_path_label = toolbar.add_label("", side="right")

        self._log_text = tk.Text(card, wrap="none")
        configure_text_widget(self._log_text, self.fonts, mono=True)
        scrollbar = ttk.Scrollbar(card, orient="vertical", command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=scrollbar.set, state="disabled")
        self._log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def on_show(self) -> None:
        """Load filter options and every tab's data."""
        self._load_filter_options()
        self.refresh()
        self._load_errors()
        self._load_application_log()

    def _load_filter_options(self) -> None:
        """Populate the action and category drop-downs from real values."""
        logs = self.context.logs
        session = self.session
        if logs is None or session is None:
            return

        def apply(options: dict[str, list[str]]) -> None:
            action_combo = getattr(self, "_action_combo", None)
            category_combo = getattr(self, "_category_combo", None)
            if action_combo is not None:
                action_combo.configure(values=["All", *options.get("actions", [])])
            if category_combo is not None:
                category_combo.configure(values=["All", *options.get("categories", [])])

        self.run_async(
            lambda: logs.filter_options(session), apply, name="log-filters"
        )

    def refresh(self) -> None:
        """Reload the audit trail using the current filters."""
        logs = self.context.logs
        session = self.session
        if logs is None or session is None:
            return
        filters: dict[str, Any] = {"limit": 2000}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._action_var.get() != "All":
            filters["action"] = self._action_var.get()
        if self._category_var.get() != "All":
            filters["category"] = self._category_var.get()
        if self._result_var.get() != "All":
            filters["result"] = self._result_var.get()
        window = {
            "Last hour": timedelta(hours=1),
            "Last 24 hours": timedelta(hours=24),
            "Last 7 days": timedelta(days=7),
            "Last 30 days": timedelta(days=30),
        }.get(self._period_var.get())
        if window is not None:
            filters["start"] = utcnow() - window

        self.status("Loading audit records...")
        self.run_async(
            lambda: (logs.search(session, **filters), logs.total(session)),
            self._apply,
            name="audit-load",
        )

    def _apply(self, payload: tuple[list[AuditRecord], int]) -> None:
        """Render the audit table."""
        records, total = payload
        self._records = {r.id: r for r in records if r.id is not None}
        self._table.set_rows(
            [
                {
                    "_id": record.id,
                    "time": format_local(record.occurred_at, "%d %b %Y %H:%M:%S"),
                    "user": record.username or "system",
                    "action": record.action,
                    "category": record.category,
                    "target": (
                        f"{record.target_type}:{record.target_id}".strip(":") or "-"
                    ),
                    "result": record.result,
                    "detail": truncate(record.detail, 220),
                }
                for record in records
            ]
        )
        self._count_label.configure(
            text=f"{len(records):,} shown of {total:,} total"
        )
        self.status(f"{len(records):,} audit record(s) loaded.")

    def _show_record(self) -> None:
        """Open one audit record in full, including its integrity hashes."""
        row = self._table.selected_row()
        if row is None:
            self.status("Select an audit record first.")
            return
        record = self._records.get(int(row.get("_id") or 0))
        if record is None:
            return
        DetailDialog(
            self, f"Audit record {record.id}",
            rows=[
                ("Occurred at", format_local(record.occurred_at)),
                ("User", record.username or "system"),
                ("User id", str(record.user_id) if record.user_id else "-"),
                ("Action", record.action),
                ("Category", record.category),
                ("Target", f"{record.target_type}:{record.target_id}".strip(":") or "-"),
                ("Result", record.result),
                ("Host context", record.host_context or "-"),
                ("Source", record.source),
                ("Previous hash", record.previous_hash or "(none)"),
                ("Record hash", record.record_hash or "(not hashed)"),
            ],
            sections=[
                ("DETAIL", record.detail or "-"),
                (
                    "INTEGRITY",
                    "Each record's hash covers its own fields plus the previous "
                    "record's hash. Changing, removing or re-ordering a record "
                    "breaks the chain from that point onward, which the "
                    "'Verify integrity' action reports.",
                ),
            ],
            fonts=self.fonts,
        ).show()

    def _verify_integrity(self) -> None:
        """Run the audit chain verification (§56)."""
        logs = self.context.logs
        session = self.session
        if logs is None or session is None:
            return
        self.status("Verifying audit log integrity...")
        self.run_async(
            lambda: logs.verify_integrity(session), self._show_integrity,
            name="log-verify",
        )

    def _show_integrity(self, report: IntegrityReport) -> None:
        """Display the verification result."""
        colour = PALETTE.ok if report.is_valid else PALETTE.critical
        self._integrity_label.configure(text=report.summary, foreground=colour)
        detail_lines = [report.summary, ""]
        if report.issues:
            detail_lines.append("ISSUES")
            for issue in report.issues[:50]:
                detail_lines.append(
                    f"  record {issue.record_id}  [{issue.kind}]  {issue.detail}"
                )
            detail_lines.extend(
                [
                    "",
                    "AETHRA-SEC does not repair these records. Investigate who "
                    "had direct database access, and treat affected records as "
                    "untrustworthy.",
                    "",
                    "Note: an administrator pruning old audit records also "
                    "truncates the chain's prefix, which is reported here as a "
                    "chain-link mismatch on the oldest surviving record.",
                ]
            )
        else:
            detail_lines.append(
                f"Records checked: {report.checked:,}\n"
                f"First record id: {report.first_record_id}\n"
                f"Last record id: {report.last_record_id}\n"
                f"Records without a hash: {report.unhashed}"
            )
        show_message(
            self,
            "Log integrity verification",
            report.summary,
            detail="\n".join(detail_lines),
            fonts=self.fonts,
        )
        self.status(report.summary)

    def _export(self) -> None:
        """Export the matching audit records to CSV."""
        logs = self.context.logs
        reports = self.context.reports
        session = self.session
        if logs is None or reports is None or session is None:
            return
        filters: dict[str, Any] = {"limit": 20000}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._action_var.get() != "All":
            filters["action"] = self._action_var.get()
        self.run_async(
            lambda: str(logs.export(session, reports.output_dir, **filters)),
            lambda path: show_message(
                self, "Export complete", "Audit records exported",
                detail=(
                    f"Written to:\n{path}\n\nThe export includes each record's "
                    "integrity hash so an exported copy can be checked against "
                    "the live chain."
                ),
                fonts=self.fonts,
            ),
            name="audit-export",
        )

    def _load_errors(self) -> None:
        """Reload recorded subsystem errors."""
        logs = self.context.logs
        session = self.session
        if logs is None or session is None:
            return
        self.run_async(
            lambda: logs.errors(session, limit=300), self._apply_errors,
            name="errors-load",
        )

    def _apply_errors(self, errors: list[Any]) -> None:
        """Render the error table."""
        self._error_table.set_rows(
            [
                {
                    "_id": error.id,
                    "time": format_local(error.occurred_at),
                    "component": error.component,
                    "severity": error.severity,
                    "message": error.message,
                    "acknowledged": "yes" if error.acknowledged else "-",
                }
                for error in errors
            ]
        )

    def _acknowledge_error(self) -> None:
        """Acknowledge the selected error."""
        row = self._error_table.selected_row()
        logs = self.context.logs
        session = self.session
        if row is None or logs is None or session is None:
            self.status("Select an error first.")
            return
        error_id = int(row.get("_id") or 0)
        self.run_async(
            lambda: logs.acknowledge_error(session, error_id),
            lambda _r: (self.status("Error acknowledged."), self._load_errors()),
            name="error-ack",
        )

    def _load_application_log(self) -> None:
        """Load the tail of the rotating diagnostic log."""
        logs = self.context.logs
        session = self.session
        if logs is None or session is None:
            return
        path = logs.application_log_path()
        self._log_path_label.configure(text=str(path) if path else "No log file")
        self.run_async(
            lambda: logs.tail_application_log(session, 800),
            self._apply_application_log,
            name="applog-load",
        )

    def _apply_application_log(self, lines: list[str]) -> None:
        """Render the diagnostic log tail."""
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.insert(
            "1.0",
            "".join(lines)
            if lines
            else (
                "The application log is empty or not yet created. File logging "
                "starts when AETHRA-SEC boots; check the configured log "
                "directory on the System Health screen."
            ),
        )
        self._log_text.see("end")
        self._log_text.configure(state="disabled")
