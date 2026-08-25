"""Vulnerability assessment screen (§17, §18, §65).

Target entry, scan profile selection, live status, host/port/finding results,
scan history and scan comparison. The authorisation boundary is shown on the
page so the operator can see which networks this installation may assess before
they start (§2).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.core.events import Event, EventType
from aethra_sec.integrations.nmap import (
    DEFAULT_PROFILE,
    TIMING_TEMPLATES,
    ScanProfile,
    available_profiles,
    has_raw_socket_privilege,
)
from aethra_sec.integrations.nmap.profiles import TIMING_DESCRIPTIONS
from aethra_sec.models.scan import Scan, ScanHostResult
from aethra_sec.ui.base import Screen
from aethra_sec.ui.detail_panels import scan_host_chips, scan_host_sections
from aethra_sec.ui.theme import PALETTE, configure_text_widget, severity_colour
from aethra_sec.ui.widgets import (
    Card, Column, DataTable, DetailDialog, DetailDrawer, FilterBar, RowAction,
    ScrollableFrame, Toolbar, confirm, show_message,
)
from aethra_sec.utils.formatting import format_count, truncate
from aethra_sec.utils.timeutil import format_duration, format_local

HOST_COLUMNS = (
    Column("ip", "IP address", width=130),
    Column("hostname", "Hostname", width=170),
    Column("mac", "MAC", width=140),
    Column("status", "Status", width=70, colour_by="state"),
    Column("os", "Operating system", width=210),
    Column("open_ports", "Open ports", width=90, anchor="e"),
    Column("risk", "Risk", width=115, colour_by="severity", glyph=True),
)

PORT_COLUMNS = (
    Column("port", "Port", width=70, anchor="e"),
    Column("protocol", "Protocol", width=70),
    Column("state", "State", width=80),
    Column("service", "Service", width=110),
    Column("product", "Product", width=170),
    Column("version", "Version", width=140),
    Column("extra", "Extra information", width=220, stretch=True),
)

FINDING_COLUMNS = (
    Column("risk", "Risk", width=125, colour_by="severity", glyph=True),
    Column("host", "Host", width=130),
    Column("port", "Port", width=80),
    Column("service", "Service", width=100),
    Column("title", "Finding", width=300, stretch=True),
    Column("reference", "Reference", width=220),
    Column("status", "Status", width=80, colour_by="status"),
)

HISTORY_COLUMNS = (
    Column("id", "Scan", width=60, anchor="e"),
    Column("target", "Target", width=150),
    Column("profile", "Profile", width=190),
    Column("status", "Status", width=100, colour_by="state"),
    Column("started", "Started", width=140),
    Column("duration", "Duration", width=90),
    Column("result", "Result", width=280, stretch=True),
)


class VulnerabilitiesScreen(Screen):
    """Run authorised Nmap assessments and review their real results."""

    title = "Vulnerability Assessment"
    subtitle = "Authorised Nmap assessment - discovery, port state, service and OS detection"
    required_permission = "scan.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._profiles: tuple[ScanProfile, ...] = ()
        self._active_scan_id: int | None = None
        self._current_scan: Scan | None = None
        self._history: list[Scan] = []
        self._drawer: DetailDrawer | None = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the assessment screen.

        Wrapped in a :class:`ScrollableFrame`, matching the Alerts screen: a
        fixed-height page must never leave content unreachable whenever it is
        taller than the window (§ layout).
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        self._build_controls(root)
        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, pady=(16, 0))

        results = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(results, text="Results")
        self._build_results(results)

        history = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(history, text="History & comparison")
        self._build_history(history)

    def _build_controls(self, parent: tk.Misc) -> None:
        """Target, profile, ports, timing and the run controls."""
        card = Card(parent, "New assessment", fonts=self.fonts, padding=18)
        card.pack(fill="x")

        row = FilterBar(card)
        row.pack(fill="x")

        ttk.Label(row, text="Target", style="CardMuted.TLabel").pack(side="left")
        self._target_var = tk.StringVar()
        target_entry = ttk.Entry(row, textvariable=self._target_var, width=26)
        target_entry.pack(side="left", padx=(8, 14))
        target_entry.bind("<Return>", lambda _e: self._start_scan())

        ttk.Label(row, text="Profile", style="CardMuted.TLabel").pack(side="left")
        self._profile_var = tk.StringVar()
        self._profile_combo = ttk.Combobox(
            row, textvariable=self._profile_var, state="readonly", width=34
        )
        self._profile_combo.pack(side="left", padx=(8, 14))
        self._profile_combo.bind("<<ComboboxSelected>>", lambda _e: self._describe_profile())

        ttk.Label(row, text="Ports", style="CardMuted.TLabel").pack(side="left")
        self._ports_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._ports_var, width=16).pack(
            side="left", padx=(8, 14)
        )

        ttk.Label(row, text="Timing", style="CardMuted.TLabel").pack(side="left")
        self._timing_var = tk.StringVar(value="T3")
        ttk.Combobox(
            row, textvariable=self._timing_var, state="readonly", width=5,
            values=list(TIMING_TEMPLATES),
        ).pack(side="left", padx=(8, 14))

        self._start_button = ttk.Button(
            row, text="Start scan", style="Accent.TButton", command=self._start_scan
        )
        self._start_button.pack(side="left", padx=(0, 6))
        self._stop_button = ttk.Button(
            row, text="Stop scan", style="Danger.TButton", command=self._stop_scan
        )
        self._stop_button.pack(side="left")
        self._stop_button.state(["disabled"])
        if not self.can("scan.run"):
            self._start_button.state(["disabled"])

        self._profile_note = ttk.Label(
            card, text="", style="CardDim.TLabel", wraplength=1000, justify="left"
        )
        self._profile_note.pack(anchor="w", pady=(8, 0))

        self._authorization_note = ttk.Label(
            card, text="", style="CardMuted.TLabel", wraplength=1000, justify="left"
        )
        self._authorization_note.pack(anchor="w", pady=(4, 0))

        self._scan_status = ttk.Label(card, text="", style="CardMuted.TLabel")
        self._scan_status.pack(anchor="w", pady=(6, 0))

    def _build_results(self, parent: tk.Misc) -> None:
        """Host, port and finding tables for the selected scan."""
        summary = Card(parent, "Scan summary", fonts=self.fonts, padding=18)
        summary.pack(fill="x")
        self._summary_label = ttk.Label(
            summary, text="No scan selected.", style="CardMuted.TLabel",
            wraplength=1000, justify="left",
        )
        self._summary_label.pack(anchor="w")

        hosts_card = Card(parent, "Discovered hosts", fonts=self.fonts, padding=18)
        hosts_card.pack(fill="both", expand=True, pady=(16, 0))
        self._hosts_table = DataTable(
            hosts_card, HOST_COLUMNS, height=6, on_select=self._show_host_ports,
            # Selecting a host fills the panels below; opening it inspects the
            # host in place, so the scan stays on screen behind the drawer.
            on_activate=self._inspect_scan_host,
            empty_text="No hosts in this assessment",
            actions=[
                RowAction("Inspect host", self._inspect_scan_host),
                RowAction("Open in host inventory", self._open_inventory),
            ],
        )
        self._hosts_table.pack(fill="both", expand=True)

        lower = ttk.Frame(parent, style="TFrame")
        lower.pack(fill="both", expand=True, pady=(16, 0))

        ports_card = Card(lower, "Ports and services", fonts=self.fonts, padding=18)
        ports_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._ports_table = DataTable(ports_card, PORT_COLUMNS, height=8)
        self._ports_table.pack(fill="both", expand=True)

        findings_card = Card(
            lower, "Security findings", subtitle="derived from observations",
            fonts=self.fonts, padding=18,
        )
        findings_card.grid(row=0, column=1, sticky="nsew")
        toolbar = Toolbar(findings_card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Finding detail", self._show_finding_detail)
        toolbar.add_button("Mitigation", self._show_finding_mitigation)
        toolbar.add_button("Export findings", self._export_findings)
        self._findings_table = DataTable(
            findings_card, FINDING_COLUMNS, height=8,
            on_activate=lambda _row: self._show_finding_detail(),
        )
        self._findings_table.pack(fill="both", expand=True)

        lower.columnconfigure(0, weight=1)
        lower.columnconfigure(1, weight=1)
        lower.rowconfigure(0, weight=1)

    def _build_history(self, parent: tk.Misc) -> None:
        """Scan history and the comparison pane (§45)."""
        card = Card(parent, "Scan history", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True)

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Open results", self._open_history_scan)
        toolbar.add_button("Compare selected with previous", self._compare_scans)
        toolbar.add_button("Refresh", self._load_history)

        self._history_table = DataTable(
            card, HISTORY_COLUMNS, height=10,
            on_activate=lambda _row: self._open_history_scan(),
        )
        self._history_table.pack(fill="both", expand=True)

        comparison = Card(parent, "Comparison", fonts=self.fonts, padding=18)
        comparison.pack(fill="both", expand=True, pady=(16, 0))
        self._comparison_text = tk.Text(comparison, height=10, wrap="word")
        configure_text_widget(self._comparison_text, self.fonts)
        self._comparison_text.insert(
            "1.0",
            "Select a completed scan and choose 'Compare selected with previous' "
            "to see newly opened ports, closed ports, changed services and "
            "host changes between two real scans of the same target.",
        )
        self._comparison_text.configure(state="disabled")
        self._comparison_text.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def on_show(self) -> None:
        """Populate profiles, boundary text and history."""
        self._load_profiles()
        self._load_history()
        self._update_scan_controls()

    def _load_profiles(self) -> None:
        """List the profiles this machine can actually run (§17)."""
        privileged = has_raw_socket_privilege()
        self._profiles = available_profiles(privileged=privileged)
        labels = [profile.label for profile in self._profiles]
        self._profile_combo.configure(values=labels)
        if not self._profile_var.get() and labels:
            default = next(
                (p.label for p in self._profiles if p.key == DEFAULT_PROFILE), labels[0]
            )
            self._profile_var.set(default)
        self._describe_profile()

        nmap = self.context.nmap
        if nmap is not None:
            availability = nmap.availability()
            if not availability.available:
                self._authorization_note.configure(
                    text=availability.detail, foreground=PALETTE.critical
                )
                self._start_button.state(["disabled"])
            else:
                boundary = nmap.authorization_summary()
                extra = (
                    ""
                    if privileged
                    else (
                        "  Raw-socket profiles (SYN, OS detection, UDP) are "
                        "hidden because this process is not elevated."
                    )
                )
                self._authorization_note.configure(
                    text=f"{boundary}{extra}", foreground=PALETTE.text_muted
                )

    def _describe_profile(self) -> None:
        """Explain the selected profile and prefill its port default."""
        profile = self._selected_profile()
        if profile is None:
            return
        timing = self._timing_var.get()
        self._profile_note.configure(
            text=(
                f"{profile.description}  Estimated duration: "
                f"{profile.estimated_duration or 'varies'}. "
                f"Timing {timing}: {TIMING_DESCRIPTIONS.get(timing, '')}"
            )
        )
        if profile.requires_ports and not self._ports_var.get():
            self._ports_var.set(profile.default_ports)

    def _selected_profile(self) -> ScanProfile | None:
        """The profile matching the current selection."""
        label = self._profile_var.get()
        return next((p for p in self._profiles if p.label == label), None)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _start_scan(self) -> None:
        """Validate, authorise and start an assessment."""
        nmap = self.context.nmap
        session = self.session
        profile = self._selected_profile()
        if nmap is None or session is None or profile is None:
            return

        target = self._target_var.get().strip()
        if not target:
            self.show_error_message("Enter a target to assess.", "No target")
            return
        if not confirm(
            self, "Start assessment",
            f"Run '{profile.label}' against {target}?",
            detail=(
                "Only scan systems you are authorised to assess. AETHRA-SEC "
                "performs discovery and service detection only - it never "
                "attempts exploitation."
            ),
            confirm_label="Start scan",
        ):
            return

        self._start_button.state(["disabled"])
        self._scan_status.configure(
            text=f"Starting assessment of {target}...", foreground=PALETTE.text_muted
        )
        # Capture the Tk variables here; the worker must not touch Tk state.
        port_spec = self._ports_var.get().strip()
        timing = self._timing_var.get()

        def work() -> int:
            return nmap.start_scan(
                session, target,
                profile_key=profile.key,
                port_spec=port_spec,
                timing=timing,
            )

        def started(scan_id: int) -> None:
            self._active_scan_id = scan_id
            self._update_scan_controls()
            self.status(f"Assessment {scan_id} running against {target}.")

        def failed(message: str) -> None:
            self._start_button.state(["!disabled"])
            self._scan_status.configure(text=message, foreground=PALETTE.critical)
            self.show_error_message(message, "Assessment refused")

        self.run_async(work, started, failed, name="scan-start")

    def _stop_scan(self) -> None:
        """Stop the running assessment."""
        nmap = self.context.nmap
        session = self.session
        if nmap is None or session is None or self._active_scan_id is None:
            return
        self.run_async(
            lambda: nmap.stop_scan(session, self._active_scan_id or 0),
            lambda _r: self.status("Stop requested; the scan ends after the current step."),
            name="scan-stop",
        )

    def _update_scan_controls(self) -> None:
        """Enable or disable the run controls from the real scan state."""
        nmap = self.context.nmap
        running = bool(
            nmap
            and self._active_scan_id is not None
            and nmap.is_running(self._active_scan_id)
        )
        if self.can("scan.run"):
            self._start_button.state(["disabled"] if running else ["!disabled"])
        if self.can("scan.stop"):
            self._stop_button.state(["!disabled"] if running else ["disabled"])

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def _load_scan(self, scan_id: int) -> None:
        """Load a scan's real results."""
        nmap = self.context.nmap
        session = self.session
        if nmap is None or session is None:
            return
        self.status(f"Loading assessment {scan_id}...")
        self.run_async(
            lambda: nmap.get_scan(session, scan_id), self._apply_scan, name="scan-load"
        )

    def _apply_scan(self, scan: Scan | None) -> None:
        """Render a loaded scan."""
        self._current_scan = scan
        if scan is None:
            self._summary_label.configure(text="Scan not found.")
            return

        self._summary_label.configure(
            text=(
                f"Scan {scan.id} · {scan.target} · {scan.profile_label or scan.profile} · "
                f"{scan.status} · {scan.summary_line}\n"
                f"Arguments: {scan.arguments or '-'}   |   "
                f"Command: {scan.command_line or '-'}\n"
                f"Started {format_local(scan.started_at)}   Finished "
                f"{format_local(scan.finished_at)}   Duration "
                f"{format_duration(scan.duration_seconds)}   "
                f"Run by {scan.initiated_by_username or 'unknown'}   "
                f"({scan.nmap_version or 'Nmap version not recorded'})"
            )
        )

        self._hosts_table.set_rows(
            [
                {
                    "_scan_host_id": host.id,
                    "ip": host.ip_address,
                    "hostname": host.hostname or "-",
                    "mac": host.mac_address or "-",
                    "status": str(host.status),
                    "os": self._os_text(host),
                    "open_ports": len(host.open_ports),
                    "risk": str(host.highest_risk),
                }
                for host in scan.hosts
            ]
        )
        self._findings_table.set_rows(
            [
                {
                    "_finding": finding,
                    "risk": str(finding.risk_level),
                    "host": finding.ip_address,
                    "port": f"{finding.port}/{finding.protocol}" if finding.port else "-",
                    "service": finding.service or "-",
                    "title": finding.title,
                    "reference": truncate(finding.reference_text, 60),
                    "status": finding.status_text,
                }
                for host in scan.hosts
                for finding in host.findings
            ]
        )
        self._ports_table.clear()
        if scan.hosts:
            self._hosts_table.select_first()
        self.status(f"Assessment {scan.id} loaded: {scan.summary_line}")

    @staticmethod
    def _os_text(host: ScanHostResult) -> str:
        """OS description with its detection accuracy, or a dash when unknown.

        The accuracy is part of the answer: Nmap fingerprints a host, it does
        not read the operating system off it, so how sure it was belongs next
        to what it said. An OS is shown only where Nmap actually reported one.
        """
        if not host.os_name:
            return f"{host.os_family} (family)" if host.os_family else "-"
        if host.os_accuracy:
            return f"{host.os_name} ({host.os_accuracy}%)"
        return host.os_name

    def _scan_host_for(self, row: dict[str, Any]) -> ScanHostResult | None:
        """The scanned host a result row stands for."""
        if self._current_scan is None:
            return None
        return next(
            (
                host for host in self._current_scan.hosts
                if host.id == row.get("_scan_host_id")
            ),
            None,
        )

    def _inspect_scan_host(self, row: dict[str, Any]) -> None:
        """Inspect a scanned host in the drawer, keeping the scan on screen."""
        host = self._scan_host_for(row)
        if host is None:
            return
        if self._drawer is None:
            self._drawer = DetailDrawer(self, self.fonts)
        scan = self._current_scan
        self._drawer.show(
            host.hostname or host.ip_address,
            subtitle=(
                f"{host.ip_address} · assessment {scan.id if scan else '-'} "
                f"({scan.profile_label or scan.profile if scan else '-'})"
            ),
            chips=scan_host_chips(host),
            sections=scan_host_sections(host, self._os_text(host)),
            primary=(
                "Open in Host Inventory",
                lambda address=host.ip_address: self.app.navigate(
                    "hosts", search=address
                ),
            ),
        )
        self.status(f"{host.ip_address} detail open.")

    def _open_inventory(self, row: dict[str, Any]) -> None:
        """Open the host inventory for a scanned host."""
        host = self._scan_host_for(row)
        if host is not None:
            self.app.navigate("hosts", search=host.ip_address)

    def on_hide(self) -> None:
        """Close the drawer when the operator leaves the screen."""
        if self._drawer is not None:
            self._drawer.close()

    def _show_host_ports(self, row: dict[str, Any]) -> None:
        """Show the selected host's ports."""
        if self._current_scan is None:
            return
        host = next(
            (h for h in self._current_scan.hosts if h.id == row.get("_scan_host_id")),
            None,
        )
        if host is None:
            return
        self._ports_table.set_rows(
            [
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service or "-",
                    "product": port.product or "-",
                    "version": port.version or "-",
                    "extra": port.extra_info or port.cpe or "-",
                }
                for port in host.ports
            ]
        )

    def _show_finding_detail(self) -> None:
        """Open the full explanation for the selected finding (§19, §53)."""
        row = self._findings_table.selected_row()
        if row is None:
            self.status("Select a finding first.")
            return
        finding = row.get("_finding")
        if finding is None:
            return
        DetailDialog(
            self,
            f"Finding: {finding.title}",
            rows=[
                ("Risk level", str(finding.risk_level)),
                ("Host", finding.ip_address),
                ("Port", f"{finding.port}/{finding.protocol}" if finding.port else "-"),
                ("Service", finding.service or "-"),
                ("Source", finding.source.label),
                ("Status", finding.status_text),
                ("Recorded", format_local(finding.created_at)),
            ],
            sections=[
                ("WHAT WAS OBSERVED", finding.observation or "-"),
                ("WHY IT MATTERS", finding.concern or "-"),
                ("HOW THE RISK LEVEL WAS ASSIGNED", finding.risk_rationale or "-"),
                ("EVIDENCE", finding.evidence or "-"),
                ("VULNERABILITY REFERENCE", finding.reference_text),
            ],
            fonts=self.fonts,
        ).show()

    def _show_finding_mitigation(self) -> None:
        """Show mitigation guidance for the selected finding (§29)."""
        row = self._findings_table.selected_row()
        mitigation = self.context.mitigation
        if row is None or mitigation is None:
            self.status("Select a finding first.")
            return
        finding = row.get("_finding")
        if finding is None:
            return

        from aethra_sec.models.enums import EvidenceSource, ThreatCategory

        recommendation = mitigation.recommendation_for(
            ThreatCategory.SERVICE_EXPOSURE,
            severity=finding.risk_level.severity,
            service=finding.service,
            source=EvidenceSource.NMAP,
        )
        if recommendation is None:
            from aethra_sec.services.mitigation_service import NO_RECOMMENDATION_TEXT

            show_message(
                self, "Mitigation", "No recommendation configured",
                detail=NO_RECOMMENDATION_TEXT, fonts=self.fonts,
            )
            return
        DetailDialog(
            self,
            f"Mitigation: {recommendation.threat_name}",
            rows=[
                ("Applies to", finding.ip_address + (f":{finding.port}" if finding.port else "")),
                ("Service", finding.service or "-"),
                ("Severity", str(finding.risk_level)),
                ("Knowledge base entry", recommendation.code),
            ],
            sections=[
                ("EXPLANATION", recommendation.explanation),
                ("WHY IT MATTERS", recommendation.why_it_matters),
                ("EVIDENCE", finding.observation or "-"),
                ("IMMEDIATE RECOMMENDED ACTION", recommendation.immediate_action),
                ("LONG-TERM RECOMMENDED ACTION", recommendation.long_term_action),
                ("VERIFICATION STEPS", recommendation.verification_steps),
                (
                    "NOTE",
                    "AETHRA-SEC does not apply mitigations automatically. "
                    "Review the guidance and act through your change process.",
                ),
            ],
            fonts=self.fonts,
        ).show()

    def _export_findings(self) -> None:
        """Export the visible findings to CSV."""
        reports = self.context.reports
        session = self.session
        if reports is None or session is None:
            return
        rows = self._findings_table.export_rows(visible_only=True)
        columns = self._findings_table.export_columns()
        self.run_async(
            lambda: str(
                reports.export_records(
                    session, columns, rows,
                    filename=f"findings_{self._current_scan.id if self._current_scan else 'all'}",
                    description="scan findings",
                )
            ),
            lambda path: show_message(
                self, "Export complete",
                f"{len(rows)} finding(s) exported" if rows
                else "No records available for export.",
                detail=f"Written to:\n{path}", fonts=self.fonts,
            ),
            name="findings-export",
        )

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------
    def _load_history(self) -> None:
        """Reload the scan history."""
        nmap = self.context.nmap
        session = self.session
        if nmap is None or session is None:
            return
        self.run_async(
            lambda: nmap.scan_history(session, limit=200),
            self._apply_history,
            name="history-load",
        )

    def _apply_history(self, scans: list[Scan]) -> None:
        """Render the scan history table."""
        self._history = scans
        self._history_table.set_rows(
            [
                {
                    "_scan_id": scan.id,
                    "_target": scan.target,
                    "id": scan.id,
                    "target": scan.target,
                    "profile": scan.profile_label or scan.profile,
                    "status": str(scan.status),
                    "started": format_local(scan.started_at or scan.created_at),
                    "duration": format_duration(scan.duration_seconds),
                    "result": scan.summary_line,
                }
                for scan in scans
            ]
        )
        if scans and self._current_scan is None:
            first_completed = next(
                (s for s in scans if str(s.status) == "COMPLETED"), None
            )
            if first_completed and first_completed.id:
                self._load_scan(first_completed.id)

    def _open_history_scan(self) -> None:
        """Load the selected historical scan."""
        row = self._history_table.selected_row()
        if row is None:
            self.status("Select a scan first.")
            return
        scan_id = row.get("_scan_id")
        if scan_id:
            self._load_scan(int(scan_id))

    def _compare_scans(self) -> None:
        """Compare the selected scan with the previous one of the same target."""
        row = self._history_table.selected_row()
        nmap = self.context.nmap
        session = self.session
        if row is None or nmap is None or session is None:
            self.status("Select a completed scan first.")
            return

        current_id = int(row.get("_scan_id") or 0)
        target = str(row.get("_target") or "")
        candidates = [
            s for s in self._history
            if s.target == target and str(s.status) == "COMPLETED" and s.id
        ]
        candidates.sort(key=lambda s: s.id or 0)
        previous = [s for s in candidates if (s.id or 0) < current_id]
        if not previous:
            show_message(
                self, "Comparison",
                "No earlier completed scan of this target",
                detail=(
                    f"There is only one completed assessment of '{target}'. "
                    "Run it again later to compare results."
                ),
                fonts=self.fonts,
            )
            return
        baseline_id = previous[-1].id or 0
        self.run_async(
            lambda: nmap.compare(session, baseline_id, current_id),
            lambda comparison: self._render_comparison(comparison, baseline_id, current_id),
            name="scan-compare",
        )

    def _render_comparison(self, comparison: Any, baseline: int, current: int) -> None:
        """Write the comparison result into the text pane."""
        lines = [
            f"Comparing scan {baseline} (baseline) with scan {current} (current).",
            "",
        ]
        if not comparison.has_changes:
            lines.append("No differences were detected between these two scans.")
        else:
            for label, entries, formatter in (
                (
                    "NEWLY OPEN PORTS",
                    comparison.newly_open_ports,
                    lambda e: f"{e[0]}  {e[1]}/{e[2]}",
                ),
                (
                    "PORTS NO LONGER OPEN",
                    comparison.closed_ports,
                    lambda e: f"{e[0]}  {e[1]}/{e[2]}",
                ),
                (
                    "CHANGED SERVICES",
                    comparison.changed_services,
                    lambda e: f"{e[0]}  {e[1]}/{e[2]}: '{e[3]}' -> '{e[4]}'",
                ),
                ("NEW HOSTS", comparison.new_hosts, lambda e: str(e)),
                ("HOSTS NO LONGER RESPONDING", comparison.missing_hosts, lambda e: str(e)),
            ):
                lines.append(f"{label} ({len(entries)})")
                if entries:
                    lines.extend(f"  - {formatter(entry)}" for entry in entries)
                else:
                    lines.append("  - none")
                lines.append("")

        if comparison.recurring_findings:
            lines.append(
                f"RECURRING FINDINGS ({len(comparison.recurring_findings)}) - present "
                "in both scans and therefore still unresolved:"
            )
            lines.extend(f"  - {title}" for title in comparison.recurring_findings)

        self._comparison_text.configure(state="normal")
        self._comparison_text.delete("1.0", "end")
        self._comparison_text.insert("1.0", "\n".join(lines))
        self._comparison_text.configure(state="disabled")
        self.status("Scan comparison complete.")

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """React to scan lifecycle events."""
        if event.type == EventType.NMAP_SCAN_STARTED:
            payload = event.payload
            self._scan_status.configure(
                text=f"Scanning {payload.target}: {payload.detail}",
                foreground=PALETTE.info,
            )
            self._update_scan_controls()
        elif event.type == EventType.NMAP_SCAN_COMPLETED:
            payload = event.payload
            self._scan_status.configure(
                text=(
                    f"Completed {payload.target}: {payload.hosts_up} host(s) up, "
                    f"{payload.open_ports} open port(s), {payload.findings} "
                    f"finding(s) in {payload.duration_seconds:.1f}s"
                ),
                foreground=PALETTE.ok,
            )
            self._active_scan_id = None
            self._update_scan_controls()
            self._load_scan(payload.scan_id)
            self._load_history()
        elif event.type == EventType.NMAP_SCAN_FAILED:
            payload = event.payload
            self._scan_status.configure(
                text=f"Assessment failed: {payload.error}", foreground=PALETTE.critical
            )
            self._active_scan_id = None
            self._update_scan_controls()
            self._load_history()
