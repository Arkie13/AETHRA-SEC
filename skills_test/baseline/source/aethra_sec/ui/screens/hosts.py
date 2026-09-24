"""Host inventory and host detail (§46, §47, §93)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Sequence

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.host import Host
from aethra_sec.ui.base import Screen
from aethra_sec.ui.detail_panels import host_chips, host_sections
from aethra_sec.ui.theme import METRICS, PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    Card, Column, DataTable, DetailDrawer, FilterBar, FormDialog, FormField,
    Kpi, KpiStrip, RowAction, Toolbar, Workspace, confirm, show_message,
)
from aethra_sec.services.host_service import MAX_RESOLVE_BATCH
from aethra_sec.utils.formatting import format_bytes, format_count
from aethra_sec.utils.timeutil import format_local

HOST_COLUMNS = (
    Column("ip", "IP address", width=130),
    Column("hostname", "Hostname", width=170),
    Column("mac", "MAC", width=140),
    Column("os", "Operating system", width=190),
    Column("risk", "Risk", width=118, colour_by="severity", glyph=True),
    Column("ports", "Open ports", width=85, anchor="e"),
    Column("packets", "Packets", width=95, anchor="e"),
    Column("alerts", "Alerts", width=65, anchor="e"),
    Column("findings", "Findings", width=75, anchor="e"),
    Column("trusted", "Trusted", width=70),
    Column("last_seen", "Last seen", width=140),
)


def _host_counts(hosts: Sequence[Host], statistics: dict[str, int]) -> dict[str, int]:
    """Inventory tallies for the summary strip.

    "Online" means a host whose last observation reported it up - not a host
    that merely exists in the inventory - so an asset list that has gone quiet
    is visibly quiet rather than reassuringly large.
    """
    online = sum(1 for host in hosts if str(host.status).upper() == "UP")
    elevated = sum(
        1 for host in hosts
        if str(host.risk_level).upper() in {"CRITICAL", "HIGH"}
    )
    return {
        "total": int(statistics.get("total", len(hosts))),
        "online": online,
        "offline": max(0, len(hosts) - online),
        "active": int(statistics.get("active_24h", 0)),
        "elevated": elevated,
        "trusted": int(statistics.get("trusted", 0)),
    }


class HostsScreen(Screen):
    """Discovered host inventory with a detail pane."""

    title = "Host Inventory"
    subtitle = "Hosts observed in captured traffic or discovered by assessment"
    required_permission = "host.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._hosts: dict[int, Host] = {}
        self._drawer: DetailDrawer | None = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """An asset workspace: the inventory beside the selected host.

        This was a summary strip, a filter panel, and then a *vertical* split
        whose lower half - the host detail - carried more weight than the
        table above it. Several hundred real hosts therefore rendered as about
        five visible rows, with the detail tabs pushed off the bottom of the
        page. The inventory now sits beside the detail and takes the full
        height of the workspace.
        """
        # The same strip the dashboard uses, so a figure means the same thing
        # and looks the same wherever it appears.
        self._kpis = KpiStrip(
            self,
            [
                Kpi("total", "Total hosts", PALETTE.accent,
                    tooltip="Every host in the inventory."),
                Kpi("online", "Online", PALETTE.ok,
                    tooltip="Hosts whose last observation reported them up."),
                Kpi("offline", "Not up", PALETTE.offline,
                    tooltip="Hosts last seen down, or never confirmed up."),
                Kpi("active", "Seen 24h", PALETTE.info,
                    tooltip="Hosts observed in the last 24 hours."),
                Kpi("elevated", "Elevated risk", PALETTE.high,
                    tooltip="Hosts at HIGH or CRITICAL risk, from stored "
                            "assessment findings."),
                Kpi("trusted", "Trusted", PALETTE.low,
                    tooltip="Hosts registered as trusted assets."),
            ],
            fonts=self.fonts,
        )
        self._kpis.pack(fill="x", pady=(0, METRICS.space_md))
        # The screen still addresses figures by key.
        self._summary = self._kpis

        workspace = Workspace(self, share=0.52)
        workspace.pack(fill="both", expand=True)

        # Filters on one line rather than inside a titled panel.
        row = FilterBar(workspace.toolbar)
        row.pack(fill="x")
        ttk.Label(row, text="Search", style="CardMuted.TLabel").pack(side="left")
        self._search_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self._search_var, width=24)
        entry.pack(side="left", padx=(METRICS.space_sm, METRICS.space_md))
        entry.bind("<Return>", lambda _e: self.refresh())

        self._risk_var = tk.StringVar(value="All")
        ttk.Label(row, text="Risk", style="CardMuted.TLabel").pack(side="left")
        ttk.Combobox(
            row, textvariable=self._risk_var, state="readonly", width=13,
            values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        ).pack(side="left", padx=(METRICS.space_sm, METRICS.space_md))

        self._trusted_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row, text="Trusted only", variable=self._trusted_var,
            command=self.refresh, style="Toolbar.TCheckbutton",
        ).pack(side="left", padx=(0, METRICS.space_md))
        ttk.Button(
            row, text="Apply", style="Accent.TButton", command=self.refresh
        ).pack(side="left")

        self._stats_label = ttk.Label(
            workspace.context, text="", style="CardDim.TLabel",
            wraplength=1200, justify="left",
        )
        self._stats_label.pack(anchor="w")

        # --- master: the inventory --------------------------------------
        listing = Card(workspace.master_pane, "Hosts", fonts=self.fonts)
        listing.pack(fill="x")

        toolbar = Toolbar(workspace.master_pane)
        toolbar.pack(fill="x", pady=(0, METRICS.space_sm))
        toolbar.add_button("Resolve hostnames", self._resolve_hostname)
        toolbar.add_button("Mark trusted", self._add_trusted)
        toolbar.add_button("Remove trust", self._remove_trusted)
        toolbar.add_button("Scan this host", self._scan_host)
        toolbar.add_button("Export", self._export)
        self._count_label = toolbar.add_label("", side="right")

        # `height` is a floor: the table fills the pane, so the visible row
        # count follows the window rather than this number.
        self._table = DataTable(
            workspace.master_pane, HOST_COLUMNS, height=16,
            on_select=self._load_detail,
            selectmode="extended",
            on_activate=lambda row: self._open_drawer(row),
            empty_text="No hosts observed yet",
            actions=[
                RowAction("Open details", lambda row: self._open_drawer(row)),
                RowAction("Scan this host", lambda _row: self._scan_host()),
                RowAction("Resolve hostname(s)", lambda _row: self._resolve_hostname()),
                RowAction("Mark trusted", lambda _row: self._add_trusted()),
                RowAction("Remove trust", lambda _row: self._remove_trusted()),
                RowAction("Show alerts for this host", lambda _row: self._open_alerts()),
            ],
        )
        self._table.pack(fill="both", expand=True)

        # --- detail: the selected host ----------------------------------
        self._detail_card = Card(
            workspace.detail_pane, "Host detail",
            subtitle="select a host", fonts=self.fonts,
        )
        self._detail_card.pack(fill="x")

        self._notebook = ttk.Notebook(workspace.detail_pane)
        self._notebook.pack(fill="both", expand=True)
        self._tabs: dict[str, tk.Text] = {}
        for key, label in (
            ("identity", "Identity & activity"),
            ("ports", "Ports & services"),
            ("security", "Alerts"),
            ("timeline", "Timeline"),
        ):
            frame = ttk.Frame(self._notebook, style="TFrame")
            self._notebook.add(frame, text=label)
            # No fixed height: the pane decides, so the text grows with the
            # window instead of leaving dead space beneath it.
            text = tk.Text(frame, wrap="word")
            configure_text_widget(text, self.fonts)
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            text.insert("1.0", "Select a host to see its detail.")
            text.configure(state="disabled")
            self._tabs[key] = text

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload the inventory."""
        hosts = self.context.hosts
        session = self.session
        if hosts is None or session is None:
            return
        filters: dict[str, Any] = {"limit": 1000}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._risk_var.get() != "All":
            filters["risk_level"] = self._risk_var.get()
        if self._trusted_var.get():
            filters["trusted_only"] = True

        self.status("Loading host inventory...")
        self.run_async(
            lambda: (hosts.search(session, **filters), hosts.statistics(session)),
            self._apply,
            name="hosts-load",
        )

    def _apply(self, payload: tuple[list[Host], dict[str, int]]) -> None:
        """Render the inventory table."""
        host_list, statistics = payload
        self._hosts = {h.id: h for h in host_list if h.id is not None}
        self._summary.update_counts(_host_counts(host_list, statistics))
        self._table.set_rows(
            [
                {
                    "_id": host.id,
                    "ip": host.ip_address,
                    "hostname": host.hostname_text,
                    "mac": host.mac_address or "-",
                    "os": host.os_text,
                    "risk": str(host.risk_level),
                    "ports": host.open_port_count,
                    "packets": format_count(host.packet_count),
                    "alerts": host.alert_count,
                    "findings": host.finding_count,
                    "trusted": "yes" if host.is_trusted else "-",
                    "last_seen": format_local(host.last_seen, "%d %b %H:%M:%S"),
                }
                for host in host_list
            ]
        )
        self._count_label.configure(text=f"{len(host_list):,} host(s)")
        self._stats_label.configure(
            text=(
                f"{format_count(statistics.get('total', 0))} host(s) known · "
                f"{format_count(statistics.get('active_24h', 0))} seen in the last "
                f"24 hours · {format_count(statistics.get('trusted', 0))} registered "
                "as trusted assets.\nCapture sees an address and a MAC, not a "
                "name or an operating system: use Resolve hostnames for the "
                "first and an assessment for the second. Neither is invented."
            )
        )
        self.status(
            f"{len(host_list):,} host(s) in inventory."
            if host_list
            else "No hosts observed yet. Start capture or run an assessment."
        )
        if host_list:
            self._table.select_first()
            self._apply_focus()

    def _selected_host(self) -> Host | None:
        """The currently selected host."""
        row = self._table.selected_row()
        if row is None:
            return None
        return self._hosts.get(int(row.get("_id") or 0))

    # ------------------------------------------------------------------
    # Details drawer
    # ------------------------------------------------------------------
    def _open_drawer(self, row: dict[str, Any]) -> None:
        """Inspect a host in the drawer without disturbing the table below."""
        host = self._hosts.get(int(row.get("_id") or 0))
        hosts = self.context.hosts
        session = self.session
        if host is None or host.id is None or hosts is None or session is None:
            return
        host_id = host.id
        self.status(f"Loading {host.display_name}...")
        self.run_async(
            lambda: hosts.detail(session, host_id),
            self._show_drawer,
            name="host-drawer",
        )

    def _show_drawer(self, detail: dict[str, Any]) -> None:
        """Render the loaded host in the drawer."""
        host: Host | None = detail.get("host")
        if host is None or not self.is_alive:
            return
        if self._drawer is None:
            self._drawer = DetailDrawer(self, self.fonts)
        self._drawer.show(
            host.display_name,
            subtitle=(
                f"{host.ip_address} · discovered by {host.discovery_source.label}"
            ),
            chips=host_chips(host),
            sections=host_sections(detail),
            primary=(
                "Show alerts",
                lambda ip=host.ip_address: self.app.navigate("alerts", search=ip),
            ),
        )
        self.status(f"{host.display_name} detail open.")

    def on_hide(self) -> None:
        """Close the drawer when the operator leaves the screen."""
        if self._drawer is not None:
            self._drawer.close()

    # ------------------------------------------------------------------
    # Cross-screen navigation
    # ------------------------------------------------------------------
    def set_search(self, text: str) -> None:
        """Open the inventory filtered to one address (used by other screens)."""
        self._search_var.set(str(text or ""))
        self.refresh()

    def set_focus_host(self, host_id: int) -> None:
        """Select a specific host once the inventory has loaded."""
        self._focus_host_id = int(host_id or 0)
        self.refresh()

    def _apply_focus(self) -> None:
        """Select the host requested by another screen, if it is present."""
        host_id = getattr(self, "_focus_host_id", 0)
        if not host_id:
            return
        self._focus_host_id = 0
        # The tree lists the *visible* rows in display order; pairing them with
        # the unfiltered, unsorted row list selects the wrong host as soon as a
        # filter or a sort is applied.
        for row_id, row in zip(
            self._table.tree.get_children(), self._table.rows(visible_only=True)
        ):
            if int(row.get("_id") or 0) == host_id:
                self._table.tree.selection_set(row_id)
                self._table.tree.focus(row_id)
                self._table.tree.see(row_id)
                return
        self.status(f"Host {host_id} is not in the current inventory view.")

    def _open_alerts(self) -> None:
        """Show the Alerts screen filtered to the selected host."""
        host = self._selected_host()
        if host is not None:
            self.app.navigate("alerts", search=host.ip_address)

    def _load_detail(self, _row: dict[str, Any]) -> None:
        """Load the selected host's full detail."""
        host = self._selected_host()
        hosts = self.context.hosts
        session = self.session
        if host is None or host.id is None or hosts is None or session is None:
            return
        host_id = host.id
        self.run_async(
            lambda: hosts.detail(session, host_id), self._render_detail, name="host-detail"
        )

    def _render_detail(self, detail: dict[str, Any]) -> None:
        """Populate the host detail tabs."""
        host: Host | None = detail.get("host")
        if host is None:
            return
        self._detail_card.set_subtitle(host.display_name)

        observations = detail.get("observations", [])
        total_sent = sum(o.packets_sent for o in observations)
        total_received = sum(o.packets_received for o in observations)
        bytes_sent = sum(o.bytes_sent for o in observations)
        bytes_received = sum(o.bytes_received for o in observations)

        identity = [
            f"IP address       : {host.ip_address}",
            f"Hostname         : {host.hostname or 'not resolved'}",
            f"MAC address      : {host.mac_address or 'not observed'}",
            f"Vendor           : {host.vendor or 'not identified'}",
            f"Operating system : {host.os_text}",
            f"Status           : {host.status}",
            f"Risk level       : {host.risk_level}",
            f"Discovered by    : {host.discovery_source.label}",
            f"Trusted asset    : {'yes - ' + host.trust_note if host.is_trusted else 'no'}",
            f"First seen       : {format_local(host.first_seen)}",
            f"Last seen        : {format_local(host.last_seen)}",
            f"Protocols        : {', '.join(host.protocols_observed) or 'none observed'}",
            "",
            "OBSERVED TRAFFIC",
            f"  packets sent     : {format_count(total_sent)}",
            f"  packets received : {format_count(total_received)}",
            f"  bytes sent       : {format_bytes(bytes_sent)}",
            f"  bytes received   : {format_bytes(bytes_received)}",
            "",
        ]
        if observations:
            identity.append("PER-PROTOCOL ROLLUPS")
            for observation in observations[:25]:
                identity.append(
                    f"  {observation.protocol or 'unspecified':<8} "
                    f"iface {observation.interface or '-':<12} "
                    f"sent {format_count(observation.packets_sent):>10} "
                    f"recv {format_count(observation.packets_received):>10} "
                    f"last {format_local(observation.last_seen)}"
                )
        else:
            identity.append(
                "No traffic rollups recorded for this host yet."
            )
        self._write("identity", "\n".join(identity))

        ports = detail.get("open_ports", [])
        findings = detail.get("findings", [])
        scans = detail.get("scans", [])
        port_lines = [f"OPEN PORTS FROM THE MOST RECENT ASSESSMENT ({len(ports)})", ""]
        if ports:
            for port in ports:
                port_lines.append(
                    f"  {port.endpoint:<12} {port.state:<8} {port.service_text}"
                )
        else:
            port_lines.append(
                "  No assessment has recorded open ports for this host."
            )
        port_lines.extend(["", f"FINDINGS ({len(findings)})", ""])
        for finding in findings[:40]:
            port_lines.extend(
                [
                    f"  [{finding.risk_level}] {finding.title}  ({finding.status_text})",
                    f"      {finding.observation}",
                    f"      {finding.reference_text}",
                ]
            )
        if not findings:
            port_lines.append("  No findings recorded for this host.")
        port_lines.extend(["", f"ASSESSMENT HISTORY ({len(scans)})", ""])
        for scan in scans[:20]:
            port_lines.append(
                f"  scan {scan.id}  {format_local(scan.created_at)}  "
                f"{scan.profile_label or scan.profile}  {scan.status}  "
                f"{scan.summary_line}"
            )
        if not scans:
            port_lines.append("  This host has not been assessed.")
        self._write("ports", "\n".join(port_lines))

        alerts = detail.get("alerts", [])
        security = [f"IDS ALERTS ({len(alerts)})", ""]
        for alert in alerts[:40]:
            security.append(
                f"  {format_local(alert.effective_time)}  [{alert.severity}] "
                f"{alert.signature_text} {alert.message}"
            )
        if not alerts:
            security.append("  No IDS alerts involve this host.")
        self._write("security", "\n".join(security))

        timeline = detail.get("timeline", [])
        lines = ["HOST TIMELINE (most recent first)", ""]
        if timeline:
            for entry in timeline:
                lines.append(
                    f"{format_local(entry['at'])}  [{entry['source']}]  {entry['summary']}"
                )
        else:
            lines.append("No timeline entries recorded for this host.")
        self._write("timeline", "\n".join(lines))

    def _write(self, key: str, content: str) -> None:
        """Replace one tab's contents."""
        widget = self._tabs[key]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _resolve_hostname(self) -> None:
        """Reverse-resolve the selected hosts, or every unresolved one.

        A capture-built inventory has no hostnames at all until something asks
        DNS, and asking one row at a time is not a workable answer to ninety
        hosts. Selecting nothing therefore means "all of the ones nobody has
        looked up yet", after saying how many lookups that is.
        """
        hosts = self.context.hosts
        session = self.session
        if hosts is None or session is None:
            return

        selected = [
            int(row["_id"]) for row in self._table.selected_rows()
            if row.get("_id") is not None
        ]
        if selected:
            self.run_async(
                lambda: hosts.resolve_hostnames(session, selected),
                self._applied_resolution,
                name="host-resolve",
            )
            return

        self.run_async(
            lambda: hosts.unresolved_hostname_count(session),
            self._confirm_resolve_all,
            name="host-resolve-count",
        )

    def _confirm_resolve_all(self, pending: int) -> None:
        """Ask before turning one click into a few hundred DNS queries."""
        hosts = self.context.hosts
        session = self.session
        if hosts is None or session is None:
            return
        if not pending:
            show_message(
                self, "Nothing to resolve",
                "Every host has already been looked up.",
                detail=(
                    "A host showing 'no DNS record' was asked and had no name "
                    "to give. Select a row and use Resolve hostnames to ask "
                    "again."
                ),
                fonts=self.fonts,
            )
            return
        batch = min(pending, MAX_RESOLVE_BATCH)
        if not confirm(
            self, "Resolve hostnames",
            f"Look up hostnames for {batch:,} host(s)?",
            detail=(
                f"{pending:,} host(s) have never been looked up. This sends one "
                f"reverse DNS query per host - {batch:,} in this round.\n\n"
                "Addresses with no name are recorded as asked, so they are not "
                "queried again. Nothing is invented for a lookup that fails."
            ),
            confirm_label="Resolve",
        ):
            return
        self.run_async(
            lambda: hosts.resolve_hostnames(session, None),
            self._applied_resolution,
            name="host-resolve",
        )

    def _applied_resolution(self, result: Any) -> None:
        """Report what the lookups actually produced, and reload."""
        self.status(result.summary())
        if result.attempted and not result.resolved:
            show_message(
                self, "No names returned",
                f"None of the {result.attempted:,} address(es) had a DNS record.",
                detail=(
                    "The addresses are kept as they are - a hostname is never "
                    "invented for a lookup that returned nothing. This is "
                    "normal for addresses outside your own DNS zone."
                ),
                fonts=self.fonts,
            )
        self.refresh()

    def _add_trusted(self) -> None:
        """Register the selected host as a trusted asset (§93)."""
        host = self._selected_host()
        hosts = self.context.hosts
        session = self.session
        if host is None or hosts is None or session is None:
            self.status("Select a host first.")
            return
        values = FormDialog(
            self, f"Register {host.ip_address} as a trusted asset",
            [
                FormField("label", "Label", value=host.display_name, required=True),
                FormField("reason", "Reason", kind="multiline", required=True),
            ],
            fonts=self.fonts, submit_label="Register",
            intro=(
                "Trust is context, not an exemption. Traffic from a trusted "
                "asset is still analysed and still raises anomalies; the trust "
                "flag appears in the evidence so an analyst can weigh it."
            ),
        ).show()
        if not values:
            return
        self.run_async(
            lambda: hosts.add_trusted(
                session, host.ip_address, values["label"], values["reason"]
            ),
            lambda _r: (self.status("Trusted asset registered."), self.refresh()),
            name="host-trust",
        )

    def _remove_trusted(self) -> None:
        """Remove the selected host's trusted-asset registration."""
        host = self._selected_host()
        hosts = self.context.hosts
        session = self.session
        if host is None or hosts is None or session is None:
            self.status("Select a host first.")
            return
        if not confirm(
            self, "Remove trust", f"Remove trusted-asset status from {host.ip_address}?",
            confirm_label="Remove",
        ):
            return
        self.run_async(
            lambda: hosts.remove_trusted(session, host.ip_address),
            lambda _r: (self.status("Trusted asset removed."), self.refresh()),
            name="host-untrust",
        )

    def _scan_host(self) -> None:
        """Open the assessment screen preloaded with this host."""
        host = self._selected_host()
        if host is None:
            self.status("Select a host first.")
            return
        self.app.navigate("vulnerabilities")
        screen = self.app._screens.get("vulnerabilities")  # noqa: SLF001
        if screen is not None and hasattr(screen, "_target_var"):
            screen._target_var.set(host.ip_address)  # noqa: SLF001
            self.status(f"Assessment target set to {host.ip_address}.")

    def _export(self) -> None:
        """Export the visible inventory to CSV."""
        reports = self.context.reports
        session = self.session
        if reports is None or session is None:
            return
        rows = self._table.export_rows(visible_only=True)
        columns = self._table.export_columns()
        self.run_async(
            lambda: str(
                reports.export_records(
                    session, columns, rows, filename=f"hosts_{len(rows)}",
                    description="host inventory",
                )
            ),
            lambda path: show_message(
                self, "Export complete",
                f"{len(rows)} host(s) exported" if rows
                else "No records available for export.",
                detail=f"Written to:\n{path}", fonts=self.fonts,
            ),
            name="host-export",
        )

    def handle_event(self, event: Event) -> None:
        """Refresh after events that change the inventory."""
        if event.type in (
            EventType.NMAP_SCAN_COMPLETED,
        ):
            self.refresh()
