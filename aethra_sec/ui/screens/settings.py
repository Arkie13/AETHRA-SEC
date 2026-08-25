"""Settings screen (§40, §91, §116).

Administrator-only. Two kinds of configuration are shown, and the distinction
matters:

* **Tunable settings** live in the database and can be changed here - detection
  thresholds, retention, refresh rates, security policy.
* **Deployment configuration** (credentials, tool paths, the Snort transport,
  the authorisation boundary) lives in ``.env`` and is shown read-only, because
  changing it needs a restart and, for credentials, must never round-trip
  through the interface.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import ttk
from typing import Any

from aethra_sec.config.environment import describe_environment, loaded_env_file
from aethra_sec.models.system import SystemSetting
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    Card,
    Column,
    DataTable,
    FilterBar,
    FormDialog,
    FormField,
    RowAction,
    Toolbar,
    confirm,
    show_message,
)
from aethra_sec.utils.formatting import format_bytes, format_count
from aethra_sec.utils.timeutil import format_local, utcnow

SETTING_COLUMNS = (
    Column("key", "Setting", width=290),
    Column("value", "Value", width=110),
    Column("type", "Type", width=60),
    Column("category", "Category", width=110),
    Column("description", "Description", width=560, stretch=True),
    Column("updated", "Updated", width=140),
)

BACKUP_COLUMNS = (
    Column("name", "Backup file", width=360, stretch=True),
    Column("created", "Created", width=170),
    Column("age", "Age", width=130),
    Column("size", "Size", width=110, anchor="e"),
)


class SettingsScreen(Screen):
    """Edit tunable settings and inspect deployment configuration."""

    title = "System Settings"
    subtitle = "Detection thresholds, retention and application configuration"
    required_permission = "settings.manage"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._settings: dict[str, SystemSetting] = {}

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the settings screen."""
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        tunable = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(tunable, text="Tunable settings")
        self._build_tunable(tunable)

        deployment = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(deployment, text="Deployment configuration")
        self._build_deployment(deployment)

        maintenance = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(maintenance, text="Data maintenance")
        self._build_maintenance(maintenance)

        backup = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(backup, text="Database backup")
        self._build_backup(backup)

    def _build_tunable(self, parent: tk.Misc) -> None:
        """Editable settings table."""
        card = Card(parent, "Settings", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)

        controls = ttk.Frame(card, style="Card.TFrame")
        controls.pack(fill="x", pady=(0, 8))
        ttk.Label(controls, text="Category", style="CardMuted.TLabel").pack(side="left")
        self._category_var = tk.StringVar(value="All")
        self._category_combo = ttk.Combobox(
            controls, textvariable=self._category_var, state="readonly", width=20
        )
        self._category_combo.pack(side="left", padx=(8, 14))
        self._category_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        toolbar = Toolbar(controls)
        toolbar.pack(side="left")
        toolbar.add_button("Edit selected", self._edit_setting, style="Accent.TButton")
        toolbar.add_button("Refresh", self.refresh)

        ttk.Label(
            card,
            text=(
                "Threshold changes take effect immediately - the detection "
                "engine reloads them without a restart."
            ),
            style="CardDim.TLabel",
        ).pack(anchor="w", pady=(0, 6))

        self._table = DataTable(
            card, SETTING_COLUMNS, height=16,
            on_activate=lambda _row: self._edit_setting(),
        )
        self._table.pack(fill="both", expand=True)

    def _build_deployment(self, parent: tk.Misc) -> None:
        """Read-only deployment configuration."""
        card = Card(
            parent, "Deployment configuration", subtitle="read-only - edit .env and restart",
            fonts=self.fonts, padding=18,
        )
        card.pack(fill="both", expand=True)
        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Reload view", self._render_deployment)
        toolbar.add_button("Restart Snort ingest", self._restart_snort)

        self._deployment_text = tk.Text(card, wrap="word")
        configure_text_widget(self._deployment_text, self.fonts, mono=True)
        scrollbar = ttk.Scrollbar(
            card, orient="vertical", command=self._deployment_text.yview
        )
        self._deployment_text.configure(yscrollcommand=scrollbar.set, state="disabled")
        self._deployment_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_maintenance(self, parent: tk.Misc) -> None:
        """Retention, backup and database maintenance (§110, §111)."""
        card = Card(parent, "Data maintenance", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 8))
        can_maintain = self.can("data.maintain")
        toolbar.add_button("Run retention now", self._run_retention, enabled=can_maintain)
        toolbar.add_button("Prune audit log", self._prune_audit, enabled=can_maintain)
        toolbar.add_button("Refresh sizes", self._load_maintenance, enabled=can_maintain)
        if not can_maintain:
            toolbar.add_label("Administrator access is required for maintenance.")

        self._maintenance_text = tk.Text(card, wrap="word")
        configure_text_widget(self._maintenance_text, self.fonts, mono=True)
        scrollbar = ttk.Scrollbar(
            card, orient="vertical", command=self._maintenance_text.yview
        )
        self._maintenance_text.configure(yscrollcommand=scrollbar.set, state="disabled")
        self._maintenance_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_backup(self, parent: tk.Misc) -> None:
        """Backups: take one, schedule them, and save one where you want it."""
        can_maintain = self.can("data.maintain")

        status_card = Card(
            parent, "Backup status", fonts=self.fonts, padding=18,
            subtitle="read from the files that exist on disk",
        )
        status_card.pack(fill="x")
        self._backup_status_label = ttk.Label(
            status_card, text="Loading...", style="CardMuted.TLabel", justify="left",
        )
        self._backup_status_label.pack(anchor="w")

        schedule_card = Card(parent, "Automatic backup", fonts=self.fonts, padding=18)
        schedule_card.pack(fill="x", pady=(16, 0))
        ttk.Label(
            schedule_card,
            text=(
                "The countdown runs from the newest backup already on disk, so "
                "restarting AETHRA-SEC does not push the next one back."
            ),
            style="CardDim.TLabel", wraplength=900, justify="left",
        ).pack(anchor="w", pady=(0, 8))

        row = FilterBar(schedule_card)
        row.pack(fill="x")
        self._auto_backup_var = tk.BooleanVar(value=False)
        auto = ttk.Checkbutton(
            row, text="Back up automatically", variable=self._auto_backup_var,
        )
        auto.pack(side="left", padx=(0, 16))
        ttk.Label(row, text="Every", style="CardMuted.TLabel").pack(side="left")
        self._interval_var = tk.StringVar(value="24")
        ttk.Spinbox(
            row, textvariable=self._interval_var, from_=1, to=8760, width=7,
        ).pack(side="left", padx=(8, 4))
        ttk.Label(row, text="hour(s)", style="CardMuted.TLabel").pack(
            side="left", padx=(0, 16)
        )
        ttk.Label(row, text="Keep", style="CardMuted.TLabel").pack(side="left")
        self._keep_var = tk.StringVar(value="7")
        ttk.Spinbox(
            row, textvariable=self._keep_var, from_=0, to=1000, width=7,
        ).pack(side="left", padx=(8, 4))
        ttk.Label(
            row, text="file(s)  (0 keeps every backup)", style="CardMuted.TLabel"
        ).pack(side="left", padx=(0, 16))
        apply_button = ttk.Button(
            row, text="Apply schedule", style="Accent.TButton",
            command=self._apply_backup_schedule,
        )
        apply_button.pack(side="left")
        if not can_maintain:
            for widget in (auto, apply_button):
                widget.state(["disabled"])

        folder_row = FilterBar(schedule_card)
        folder_row.pack(fill="x", pady=(8, 0))
        ttk.Label(folder_row, text="Folder", style="CardMuted.TLabel").pack(side="left")
        self._backup_dir_var = tk.StringVar()
        ttk.Entry(
            folder_row, textvariable=self._backup_dir_var, width=64,
        ).pack(side="left", padx=(8, 6))
        choose = ttk.Button(
            folder_row, text="Choose...", command=self._choose_backup_directory
        )
        choose.pack(side="left")
        if not can_maintain:
            choose.state(["disabled"])

        files_card = Card(parent, "Backups on disk", fonts=self.fonts, padding=18)
        files_card.pack(fill="both", expand=True, pady=(16, 0))

        toolbar = Toolbar(files_card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button(
            "Back up now", self._backup_now, style="Accent.TButton",
            enabled=can_maintain,
        )
        toolbar.add_button(
            "Back up and save as...", self._backup_to_file, enabled=can_maintain
        )
        toolbar.add_separator()
        toolbar.add_button(
            "Save a copy...", self._save_backup_copy, enabled=can_maintain
        )
        toolbar.add_button("Delete", self._delete_backup, enabled=can_maintain)
        toolbar.add_button("Refresh", self._load_backups)
        self._backup_count_label = toolbar.add_label("", side="right")
        if not can_maintain:
            toolbar.add_label("Administrator access is required for backups.")

        self._backup_table = DataTable(
            files_card, BACKUP_COLUMNS, height=10,
            empty_text="No backups have been taken yet",
            on_activate=lambda _row: self._save_backup_copy(),
            actions=[
                RowAction("Save a copy...", lambda _row: self._save_backup_copy()),
                RowAction("Delete backup", lambda _row: self._delete_backup()),
            ],
        )
        self._backup_table.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def on_show(self) -> None:
        """Load every tab."""
        self.refresh()
        self._render_deployment()
        self._load_maintenance()
        self._load_backups()

    def refresh(self) -> None:
        """Reload the tunable settings table."""
        settings = self.context.settings_service
        session = self.session
        if settings is None or session is None:
            return
        category = self._category_var.get()
        self.run_async(
            lambda: (
                settings.list_for_ui("" if category == "All" else category),
                settings.categories(),
            ),
            self._apply,
            name="settings-load",
        )

    def _apply(self, payload: tuple[list[SystemSetting], list[str]]) -> None:
        """Render the settings table."""
        rows, categories = payload
        self._settings = {setting.key: setting for setting in rows}
        self._category_combo.configure(values=["All", *categories])
        self._table.set_rows(
            [
                {
                    "_key": setting.key,
                    "key": setting.key,
                    "value": setting.value,
                    "type": setting.value_type,
                    "category": setting.category,
                    "description": setting.description,
                    "updated": format_local(setting.updated_at, "%d %b %Y %H:%M"),
                }
                for setting in rows
            ]
        )
        self.status(f"{len(rows)} setting(s) loaded.")

    def _edit_setting(self) -> None:
        """Edit the selected setting."""
        row = self._table.selected_row()
        settings = self.context.settings_service
        session = self.session
        if row is None or settings is None or session is None:
            self.status("Select a setting first.")
            return
        key = str(row.get("_key") or "")
        setting = self._settings.get(key)
        if setting is None:
            return
        spec = settings.spec_for(key)

        bounds = ""
        if spec is not None and spec.minimum is not None:
            bounds = f"Permitted range: {spec.minimum:g} to {spec.maximum:g}."

        field = (
            FormField("value", "Value", kind="bool", value=setting.typed_value())
            if setting.value_type == "bool"
            else FormField(
                "value", "Value", value=setting.value, required=True,
                help_text=bounds,
            )
        )
        values = FormDialog(
            self, f"Edit {key}", [field], fonts=self.fonts, submit_label="Save",
            intro=f"{setting.description}\n\nCurrent value: {setting.value}",
        ).show()
        if not values:
            return
        self.run_async(
            lambda: settings.set(session, key, values["value"]),
            lambda stored: (
                self.status(f"'{key}' set to {stored}."),
                self.refresh(),
            ),
            name="setting-save",
        )

    def _render_deployment(self) -> None:
        """Show the read-only deployment configuration."""
        settings = self.context.settings
        lines = [
            "DEPLOYMENT CONFIGURATION (read-only)",
            "Edit .env and restart AETHRA-SEC to change these values.",
            f"Loaded .env file: {loaded_env_file() or '(none - defaults in use)'}",
            "",
            "DATABASE",
        ]
        for key, value in settings.database.redacted().items():
            lines.append(f"  {key:<22}: {value}")

        lines.extend(["", "EXTERNAL TOOLS"])
        for label, path in (
            ("Nmap path", settings.tools.nmap_path),
            ("TShark path", settings.tools.tshark_path),
            ("Snort path", settings.tools.snort_path),
            ("Snort config", settings.tools.snort_config),
        ):
            lines.append(f"  {label:<22}: {path or '(auto-discover on PATH)'}")

        nmap = self.context.nmap
        capture = self.context.capture
        if nmap is not None:
            lines.append(f"  {'Nmap resolved':<22}: {nmap.availability().detail}")
        if capture is not None:
            lines.append(f"  {'TShark resolved':<22}: {capture.availability().detail}")

        lines.extend(["", "SNORT ALERT INGEST"])
        lines.append(f"  {'Transport':<22}: {settings.snort.transport}")
        lines.append(f"  {'Endpoint':<22}: {settings.snort.describe()}")
        snort = self.context.snort
        if snort is not None:
            status = snort.status()
            lines.append(f"  {'Observed state':<22}: {status.status_text}")
            lines.append(f"  {'Detail':<22}: {status.detail}")
            found, detail = snort.executable_status()
            lines.append(f"  {'Snort executable':<22}: {detail}")

        lines.extend(["", "CAPTURE"])
        lines.append(f"  {'Configured interface':<22}: {settings.capture.interface or '(choose in the UI)'}")
        lines.append(f"  {'Capture filter':<22}: {settings.capture.bpf_filter or '(none)'}")

        lines.extend(["", "AUTHORISATION BOUNDARY"])
        lines.append(
            f"  {'Authorised networks':<22}: "
            + ", ".join(str(n) for n in settings.authorization.parsed_networks)
        )
        lines.append(
            f"  {'Public targets':<22}: "
            + ("ENABLED" if settings.authorization.allow_public else "refused")
        )
        if settings.authorization.invalid_networks:
            lines.append(
                f"  {'Unparsable entries':<22}: "
                + ", ".join(settings.authorization.invalid_networks)
            )

        lines.extend(["", "SECURITY"])
        lines.append(
            f"  {'Password hashing':<22}: {self.context.passwords.algorithm_description}"
        )
        lines.append(f"  {'Two-factor':<22}: {self.context.otp.status().display}")

        lines.extend(["", "PATHS"])
        lines.append(f"  {'Log directory':<22}: {settings.log_dir}")
        lines.append(f"  {'Report directory':<22}: {settings.report_dir}")
        lines.append(f"  {'Log level':<22}: {settings.log_level}")

        lines.extend(["", "ENVIRONMENT VARIABLES (secrets redacted)"])
        for key, value in describe_environment().items():
            lines.append(f"  {key:<34}: {value}")

        self._deployment_text.configure(state="normal")
        self._deployment_text.delete("1.0", "end")
        self._deployment_text.insert("1.0", "\n".join(lines))
        self._deployment_text.configure(state="disabled")

    def _restart_snort(self) -> None:
        """Restart the Snort alert transport with the current configuration."""
        snort = self.context.snort
        session = self.session
        if snort is None or session is None:
            return
        self.run_async(
            lambda: snort.restart(session),
            lambda started: (
                self.status(
                    "Snort ingest restarted."
                    if started
                    else f"Snort ingest not running: {snort.status().detail}"
                ),
                self._render_deployment(),
            ),
            name="snort-restart",
        )

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def _load_maintenance(self) -> None:
        """Show table sizes and the last retention result."""
        retention = self.context.retention
        session = self.session
        if retention is None or session is None or not self.can("data.maintain"):
            return
        self.run_async(
            lambda: (
                retention.table_sizes(session),
                retention.database_size_bytes(session),
            ),
            self._apply_maintenance,
            name="maintenance-load",
        )

    def _apply_maintenance(self, payload: tuple[dict[str, int], int]) -> None:
        """Render the maintenance pane."""
        sizes, total_bytes = payload
        retention = self.context.retention
        lines = [
            "DATABASE",
            f"  Approximate on-disk size: {format_bytes(total_bytes)}",
            "",
            "TABLE ROW ESTIMATES",
        ]
        for name, rows in sorted(sizes.items(), key=lambda item: -item[1]):
            lines.append(f"  {name:<30}: {format_count(rows)}")

        lines.extend(["", "LAST RETENTION RUN"])
        if retention is not None and retention.last_result is not None:
            result = retention.last_result
            lines.append(f"  {format_local(result.ran_at)}: {result.summary()}")
        else:
            lines.append("  Retention has not run in this session yet.")

        lines.extend(
            [
                "",
                "NOTES",
                "  - Evidence attached to an incident is never pruned "
                "automatically.",
                "  - Audit records are pruned only on explicit request, and "
                "pruning is itself audited.",
                "  - Retention periods are configured on the Tunable settings "
                "tab under the 'retention' category.",
            ]
        )
        self._maintenance_text.configure(state="normal")
        self._maintenance_text.delete("1.0", "end")
        self._maintenance_text.insert("1.0", "\n".join(lines))
        self._maintenance_text.configure(state="disabled")

    def _run_retention(self) -> None:
        """Run a retention pass now."""
        retention = self.context.retention
        session = self.session
        if retention is None or session is None:
            return
        if not confirm(
            self, "Run retention", "Run data retention pruning now?",
            detail=(
                "Records older than the configured retention are deleted. "
                "Evidence linked to an incident is retained regardless."
            ),
            confirm_label="Run retention", danger=True,
        ):
            return
        self.run_async(
            lambda: retention.run_now(session),
            lambda result: (
                show_message(
                    self, "Retention complete", result.summary(), fonts=self.fonts
                ),
                self._load_maintenance(),
            ),
            name="retention-run",
        )

    # ------------------------------------------------------------------
    # Database backup (§111)
    # ------------------------------------------------------------------
    def _load_backups(self) -> None:
        """Read the real backup files and the current schedule."""
        backup = self.context.backup
        session = self.session
        if backup is None or session is None:
            return
        self.run_async(backup.status, self._apply_backups, name="backup-status")

    def _apply_backups(self, status: Any) -> None:
        """Render the schedule, the summary line and the file list."""
        self._auto_backup_var.set(status.automatic_enabled)
        self._interval_var.set(str(status.interval_hours))
        self._keep_var.set(str(status.keep_files))
        if not self._backup_dir_var.get().strip():
            self._backup_dir_var.set(str(status.directory))

        now = utcnow()
        self._backup_table.set_rows(
            [
                {
                    "_name": item.name,
                    "name": item.name,
                    "created": format_local(item.created_at, "%d %b %Y %H:%M:%S"),
                    "age": _describe_age(now - item.created_at),
                    "size": format_bytes(item.size_bytes),
                }
                for item in status.backups
            ]
        )
        self._backup_count_label.configure(
            text=f"{len(status.backups)} backup(s) · {format_bytes(status.total_bytes)}"
        )
        self._backup_status_label.configure(text=_describe_backup_status(status, now))

    def _apply_backup_schedule(self) -> None:
        """Save the schedule the administrator typed."""
        settings = self.context.settings_service
        session = self.session
        if settings is None or session is None:
            return
        try:
            interval = int(self._interval_var.get())
            keep = int(self._keep_var.get())
        except ValueError:
            self.show_error_message(
                "The interval and the keep count must both be whole numbers.",
                "Schedule not saved",
            )
            return

        enabled = bool(self._auto_backup_var.get())
        directory = self._backup_dir_var.get().strip()
        self.run_async(
            lambda: [
                settings.set(session, "backup.automatic_enabled", enabled),
                settings.set(session, "backup.interval_hours", interval),
                settings.set(session, "backup.keep_files", keep),
                settings.set(session, "backup.directory", directory),
            ],
            lambda _saved: (self._load_backups(), self.refresh()),
            name="backup-schedule",
        )

    def _choose_backup_directory(self) -> None:
        """Pick the folder automatic backups are written to."""
        from tkinter import filedialog

        chosen = filedialog.askdirectory(
            parent=self, title="Choose the backup folder",
            initialdir=self._backup_dir_var.get() or str(Path.home()),
        )
        if chosen:
            self._backup_dir_var.set(chosen)

    def _backup_now(self) -> None:
        """Back up into the configured folder."""
        backup = self.context.backup
        session = self.session
        if backup is None or session is None:
            return
        directory = backup.directory
        if not confirm(
            self, "Back up database", "Create a database backup now?",
            detail=(
                f"A timestamped SQL dump is written to:\n{directory}\n\n"
                "Existing backups are never overwritten."
            ),
            confirm_label="Back up",
        ):
            return
        self.run_async(
            lambda: str(backup.create(session)),
            lambda path: (
                show_message(
                    self, "Backup complete", "Database backup written",
                    detail=f"{path}", fonts=self.fonts,
                ),
                self._load_backups(),
            ),
            name="db-backup",
        )

    def _backup_to_file(self) -> None:
        """Back up straight to a file the operator chooses - the download."""
        backup = self.context.backup
        session = self.session
        if backup is None or session is None:
            return
        from tkinter import filedialog

        stamp = utcnow().strftime("%Y%m%d_%H%M%S")
        chosen = filedialog.asksaveasfilename(
            parent=self, title="Save database backup as",
            defaultextension=".sql",
            initialfile=f"aethra_backup_{stamp}.sql",
            filetypes=[("SQL dump", "*.sql"), ("All files", "*.*")],
        )
        if not chosen:
            return
        target = Path(chosen)
        self.run_async(
            lambda: str(backup.create(session, target)),
            lambda path: (
                show_message(
                    self, "Backup saved", "Database backup written",
                    detail=f"{path}", fonts=self.fonts,
                ),
                self._load_backups(),
            ),
            name="db-backup-as",
        )

    def _selected_backup(self) -> str:
        """Name of the highlighted backup, or an empty string."""
        row = self._backup_table.selected_row()
        return str(row.get("_name", "")) if row else ""

    def _save_backup_copy(self) -> None:
        """Copy an existing backup somewhere the operator chooses."""
        backup = self.context.backup
        session = self.session
        name = self._selected_backup()
        if backup is None or session is None:
            return
        if not name:
            show_message(
                self, "No backup selected",
                "Select a backup in the list first.", fonts=self.fonts,
            )
            return

        from tkinter import filedialog

        chosen = filedialog.asksaveasfilename(
            parent=self, title=f"Save a copy of {name}",
            defaultextension=".sql", initialfile=name,
            filetypes=[("SQL dump", "*.sql"), ("All files", "*.*")],
        )
        if not chosen:
            return
        target = Path(chosen)
        self.run_async(
            lambda: str(backup.save_copy(session, name, target)),
            lambda path: show_message(
                self, "Copy saved", f"{name} was copied.",
                detail=f"{path}", fonts=self.fonts,
            ),
            name="backup-copy",
        )

    def _delete_backup(self) -> None:
        """Delete one backup file."""
        backup = self.context.backup
        session = self.session
        name = self._selected_backup()
        if backup is None or session is None or not name:
            return
        if not confirm(
            self, "Delete backup", f"Delete {name}?",
            detail=(
                "The file is removed from disk. This cannot be undone, and the "
                "deletion is recorded in the audit trail."
            ),
            confirm_label="Delete", danger=True,
        ):
            return
        self.run_async(
            lambda: backup.delete(session, name),
            lambda _done: self._load_backups(),
            name="backup-delete",
        )

    def _prune_audit(self) -> None:
        """Prune old audit records (administrator only)."""
        retention = self.context.retention
        session = self.session
        if retention is None or session is None:
            return
        values = FormDialog(
            self, "Prune audit log",
            [FormField("days", "Delete records older than (days)", value="365", required=True)],
            fonts=self.fonts, submit_label="Prune",
            intro=(
                "Pruning removes the oldest audit records. The integrity chain "
                "prefix is truncated as a result, and verification will report "
                "that on the oldest surviving record. The pruning itself is "
                "recorded in the audit trail. A minimum of 30 days is enforced."
            ),
        ).show()
        if not values:
            return
        try:
            days = int(values["days"])
        except ValueError:
            self.show_error_message("Enter a whole number of days.", "Invalid input")
            return
        self.run_async(
            lambda: retention.prune_audit_logs(session, days),
            lambda removed: show_message(
                self, "Audit pruning complete",
                f"{removed:,} audit record(s) removed",
                detail=(
                    "Run Logs > Verify integrity to see the reported chain "
                    "truncation on the oldest surviving record."
                ),
                fonts=self.fonts,
            ),
            name="audit-prune",
        )


# ---------------------------------------------------------------------------
# Backup status text
# ---------------------------------------------------------------------------
def _describe_age(span: timedelta) -> str:
    """A rough, readable age for a backup file."""
    seconds = int(span.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 90:
        return f"{seconds} second(s) ago"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes} minute(s) ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} hour(s) ago"
    return f"{hours // 24} day(s) ago"


def _describe_due(due: datetime | None, now: datetime) -> str:
    """When the next automatic backup falls, in words."""
    if due is None:
        return "Automatic backup is off - backups happen only when you ask."
    if due <= now:
        return "Next automatic backup: due now, it runs within the minute."
    remaining = int((due - now).total_seconds())
    hours, minutes = divmod(remaining // 60, 60)
    ahead = f"{hours}h {minutes:02d}m" if hours else f"{minutes} minute(s)"
    return (
        f"Next automatic backup: {format_local(due, '%d %b %Y %H:%M')} "
        f"(in {ahead})."
    )


def _describe_backup_status(status: Any, now: datetime) -> str:
    """The status paragraph above the schedule controls.

    Every line is a fact about this machine: whether the tool is installed,
    what is on disk, and when the next run falls. Nothing is asserted about a
    backup that has not happened.
    """
    lines: list[str] = []
    if not status.tool_available:
        lines.append(
            "mysqldump was not found on PATH - backups cannot run until the "
            "MySQL client tools are installed."
        )
    else:
        lines.append(f"Backup folder: {status.directory}")

    latest = status.latest
    if latest is None:
        lines.append("No backup has been taken yet.")
    else:
        lines.append(
            f"Most recent: {latest.name} - {format_bytes(latest.size_bytes)}, "
            f"{_describe_age(now - latest.created_at)}."
        )
        lines.append(
            f"{format_count(len(status.backups))} backup(s) retained, "
            f"{format_bytes(status.total_bytes)} in total."
        )
    lines.append(_describe_due(status.due_at, now))
    if status.last_error:
        lines.append(f"Last scheduled run failed: {status.last_error}")
    return "\n".join(lines)
