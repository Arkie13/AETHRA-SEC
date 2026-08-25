"""Incident screen and investigation view (§44, §67).

The investigation view is the strongest screen in the application: it shows the
incident summary, the transparent severity calculation, a chronological
evidence timeline drawn from real timestamps, the contributing Snort alerts,
traffic anomalies and Nmap findings, the mitigation guidance, and the analyst's
own notes.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timedelta
from tkinter import ttk
from typing import Any, Sequence

from aethra_sec.analytics.risk_engine import parse_explanation_lines
from aethra_sec.core.events import Event, EventType
from aethra_sec.models.enums import (
    EvaluationLabel,
    IncidentStatus,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.incident import Incident
from aethra_sec.ui.base import Screen
from aethra_sec.ui.detail_panels import (
    host_chips,
    host_sections,
    incident_device_chips,
    unknown_device_sections,
)
from aethra_sec.ui.theme import PALETTE, configure_text_widget, severity_colour
from aethra_sec.ui.widgets import (
    Card, Column, DataTable, DetailDrawer, EmptyState, FilterBar,
    KeyValueList, RiskFactorList, RowAction, ScrollableFrame, SeverityChip,
    SummaryCell, SummaryStrip, Toolbar, confirm, show_message,
)
from aethra_sec.utils.formatting import format_count, truncate
from aethra_sec.utils.timeutil import format_duration, format_local, utcnow

INCIDENT_COLUMNS = (
    Column("reference", "Reference", width=100),
    Column("severity", "Severity", width=100, colour_by="severity", glyph=True),
    Column("confidence", "Conf.", width=55, anchor="e"),
    Column("category", "Category", width=140),
    Column("title", "Incident", width=300, stretch=True),
    Column("sources", "Evidence", width=180),
    Column("status", "Status", width=115, colour_by="status"),
    Column("first_seen", "First seen", width=135),
    Column("last_seen", "Last seen", width=135),
)

#: Devices named by one incident's evidence. Populated from the incident's own
#: alerts, anomalies and findings, and enriched from the host inventory.
DEVICE_COLUMNS = (
    Column("role", "Role", width=110),
    Column("ip", "IP address", width=130),
    Column("hostname", "Hostname", width=170),
    Column("mac", "MAC", width=140),
    Column("os", "Operating system", width=180),
    Column("status", "Status", width=80, colour_by="state"),
    Column("risk", "Risk", width=115, glyph=True),
    Column("trusted", "Trusted", width=70),
)


def _incident_counts(incidents: Sequence[Incident]) -> dict[str, int]:
    """Severity and workflow tallies for the summary strip.

    Counted from the records handed in rather than queried separately, so the
    strip always describes exactly the rows the table is showing.
    """
    counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "open": 0, "resolved": 0,
    }
    settled = {
        IncidentStatus.RESOLVED, IncidentStatus.CLOSED,
        IncidentStatus.FALSE_POSITIVE,
    }
    for incident in incidents:
        severity = str(incident.severity).upper()
        if severity == "CRITICAL":
            counts["critical"] += 1
        elif severity == "HIGH":
            counts["high"] += 1
        elif severity == "MEDIUM":
            counts["medium"] += 1
        else:
            counts["low"] += 1
        if incident.status in settled:
            counts["resolved"] += 1
        else:
            counts["open"] += 1
    return counts


class IncidentsScreen(Screen):
    """Correlated threat incidents and their investigation."""

    title = "Threat Incidents"
    subtitle = "Correlated evidence from Nmap, PyShark and Snort"
    required_permission = "incident.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._incidents: dict[int, Incident] = {}
        self._focus_incident: int | None = None
        self._bundle: dict[str, Any] = {}
        self._devices: list[dict[str, Any]] = []
        self._drawer: DetailDrawer | None = None
        self._cleared_at: datetime | None = None

    def set_focus_incident(self, incident_id: int) -> None:
        """Open a specific incident (used when navigating from Alerts)."""
        self._focus_incident = int(incident_id)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the incidents screen.

        Wrapped in a :class:`ScrollableFrame`, matching the Alerts screen:
        the table and the investigation panel are stacked, each given real
        room, and the page scrolls to reach whichever one does not fit -
        rather than a resizable split, whose divider a `ttk.Panedwindow` (it
        has no `minsize` option at all, unlike the classic `tk` one) cannot
        be stopped from landing, or being dragged, somewhere too cramped to
        show a row.
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        self._build_summary(root)
        self._build_filters(root)
        self._build_table(root)
        self._build_investigation(root)

    def _build_summary(self, parent: tk.Misc) -> None:
        """Severity and workflow counts, above the queue.

        A queue answers "what are the incidents?"; this answers "how bad is
        it?", which is the question an analyst opens the page with. Every
        figure is counted from the incidents the current filters returned, so
        the strip and the table can never disagree.
        """
        self._summary = SummaryStrip(
            parent,
            (
                SummaryCell("critical", "Critical", PALETTE.critical,
                            tooltip="Incidents at CRITICAL severity."),
                SummaryCell("high", "High", PALETTE.high,
                            tooltip="Incidents at HIGH severity."),
                SummaryCell("medium", "Medium", PALETTE.medium,
                            tooltip="Incidents at MEDIUM severity."),
                SummaryCell("low", "Low", PALETTE.low,
                            tooltip="Incidents at LOW or informational severity."),
                SummaryCell("open", "Open", PALETTE.accent,
                            tooltip="Incidents still requiring attention."),
                SummaryCell("resolved", "Resolved", PALETTE.ok,
                            tooltip="Incidents resolved, closed or marked a "
                                    "false positive."),
            ),
            fonts=self.fonts,
        )
        self._summary.pack(fill="x", pady=(0, 10))

    def _build_filters(self, parent: tk.Misc) -> None:
        """Search and filter controls."""
        card = Card(parent, "Search and filter", fonts=self.fonts, padding=18)
        card.pack(fill="x")
        row = FilterBar(card)
        row.pack(fill="x")

        ttk.Label(row, text="Search", style="CardMuted.TLabel").pack(side="left")
        self._search_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self._search_var, width=26)
        entry.pack(side="left", padx=(8, 14))
        entry.bind("<Return>", lambda _e: self.refresh())

        self._severity_var = tk.StringVar(value="All")
        self._status_var = tk.StringVar(value="Open only")
        self._category_var = tk.StringVar(value="All")
        for label, variable, values, width in (
            ("Severity", self._severity_var, ["All", *[str(s) for s in Severity]], 12),
            (
                "Status", self._status_var,
                ["Open only", "All", *[str(s) for s in IncidentStatus]], 15,
            ),
            (
                "Category", self._category_var,
                ["All", *[str(c) for c in ThreatCategory]], 20,
            ),
        ):
            ttk.Label(row, text=label, style="CardMuted.TLabel").pack(side="left")
            ttk.Combobox(
                row, textvariable=variable, values=values, state="readonly", width=width
            ).pack(side="left", padx=(8, 14))

        ttk.Button(row, text="Apply", style="Accent.TButton", command=self.refresh).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(row, text="Reset", style="Ghost.TButton", command=self._reset).pack(
            side="left"
        )
        self._summary_label = ttk.Label(card, text="", style="CardDim.TLabel")
        self._summary_label.pack(anchor="w", pady=(8, 0))

    def _reset(self) -> None:
        """Clear the filters."""
        self._search_var.set("")
        self._severity_var.set("All")
        self._status_var.set("Open only")
        self._category_var.set("All")
        self._cleared_at = None
        self.refresh()

    def _clear_display(self) -> None:
        """Clear the visible list without touching stored incidents.

        Only the view is reset: everything already correlated stays in the
        database exactly as it was. New incidents (and, via the live
        INCIDENT_CREATED/UPDATED events, this screen's own refreshes) still
        appear as they happen - only what had already accumulated is hidden,
        the same "clear display" the Live Packets view already offers.
        """
        self._cleared_at = utcnow()
        self._table.clear()
        self._incidents = {}
        self._count_label.configure(text="0 incident(s)")
        self.status("Display cleared. Stored incidents are unaffected.")

    def set_search(self, text: str) -> None:
        """Open the screen filtered to one address or reference (drill-down)."""
        self._search_var.set(str(text or ""))
        self._status_var.set("All")
        self.refresh()

    def _build_table(self, parent: tk.Misc) -> None:
        """Incident list with workflow controls."""
        card = Card(parent, "Incidents", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True, pady=(16, 0))

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        for label, status in (
            ("Investigating", IncidentStatus.INVESTIGATING),
            ("Acknowledge", IncidentStatus.ACKNOWLEDGED),
            ("Resolve", IncidentStatus.RESOLVED),
            ("False positive", IncidentStatus.FALSE_POSITIVE),
            ("Close", IncidentStatus.CLOSED),
        ):
            toolbar.add_button(label, lambda s=status: self._set_status(s))
        toolbar.add_separator()
        toolbar.add_button("Add note", self._add_note)
        toolbar.add_button("Assign to me", self._assign_self)
        toolbar.add_button("Mark all read", self._mark_all_viewed)
        toolbar.add_button("Export", self._export)
        toolbar.add_separator()
        toolbar.add_button("Clear display", self._clear_display)
        self._count_label = toolbar.add_label("", side="right")

        self._table = DataTable(
            card, INCIDENT_COLUMNS, height=8, on_select=self._load_investigation,
            empty_text="No incidents match the current filters",
            # Each entry acts on the row that was right-clicked, not on
            # whatever was selected beforehand.
            actions=[
                RowAction(
                    "Mark investigating",
                    lambda row: self._set_status(
                        IncidentStatus.INVESTIGATING, self._incident_from_row(row)
                    ),
                ),
                RowAction(
                    "Acknowledge",
                    lambda row: self._set_status(
                        IncidentStatus.ACKNOWLEDGED, self._incident_from_row(row)
                    ),
                ),
                RowAction(
                    "Resolve",
                    lambda row: self._set_status(
                        IncidentStatus.RESOLVED, self._incident_from_row(row)
                    ),
                ),
                RowAction(
                    "Mark false positive",
                    lambda row: self._set_status(
                        IncidentStatus.FALSE_POSITIVE, self._incident_from_row(row)
                    ),
                ),
                RowAction(
                    "Assign to me",
                    lambda row: self._assign_self(self._incident_from_row(row)),
                ),
                RowAction(
                    "Add note", lambda row: self._add_note(self._incident_from_row(row))
                ),
                RowAction(
                    "Open affected host",
                    lambda row: self._open_host(self._incident_from_row(row)),
                ),
                RowAction(
                    "Copy ID", lambda row: self._copy_reference(
                        self._incident_from_row(row)
                    )
                ),
            ],
        )
        self._table.pack(fill="both", expand=True)

    def _open_host(self, incident: Incident | None = None) -> None:
        """Open the host detail page for the incident's target."""
        incident = incident or self._selected_incident()
        if incident is None:
            self.status("Select an incident first.")
            return
        if incident.affected_host_id:
            self.app.navigate("hosts", focus_host=incident.affected_host_id)
        elif incident.affected_host_ip:
            self.app.navigate("hosts", search=incident.affected_host_ip)
        else:
            self.status("This incident does not name an affected host.")

    def _build_investigation(self, parent: tk.Misc) -> None:
        """The investigation pane (§44)."""
        self._investigation_card = Card(
            parent, "Investigation", fonts=self.fonts, padding=18
        )
        self._investigation_card.pack(fill="both", expand=True, pady=(16, 0))

        self._notebook = ttk.Notebook(self._investigation_card)
        self._notebook.pack(fill="both", expand=True)

        self._build_summary_tab()

        self._tabs: dict[str, tk.Text] = {}
        for key, label in (
            ("evidence", "Evidence"),
            ("timeline", "Timeline"),
            ("mitigation", "Mitigation"),
            ("notes", "Notes & audit"),
        ):
            frame = ttk.Frame(self._notebook, style="TFrame")
            self._notebook.add(frame, text=label)
            text = tk.Text(frame, wrap="word", height=12)
            configure_text_widget(text, self.fonts)
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            text.insert("1.0", "Select an incident to investigate.")
            text.configure(state="disabled")
            self._tabs[key] = text

    def _build_summary_tab(self) -> None:
        """The summary tab: chips, facts and the severity breakdown as widgets."""
        scroller = ScrollableFrame(self._notebook)
        self._notebook.add(scroller, text="Summary & risk")
        body = scroller.interior

        header = ttk.Frame(body, style="TFrame")
        header.pack(fill="x", pady=(4, 8))
        self._summary_reference = ttk.Label(
            header, text="Select an incident", style="Heading.TLabel"
        )
        self._summary_reference.pack(side="left", padx=(0, 12))
        self._summary_chips: dict[str, SeverityChip] = {}
        for key, kind in (
            ("severity", "severity"), ("status", "status"), ("category", "severity"),
        ):
            chip = SeverityChip(
                header, "", kind=kind, fonts=self.fonts, surface=PALETTE.background
            )
            chip.pack(side="left", padx=(0, 6))
            self._summary_chips[key] = chip
        self._summary_confidence = ttk.Label(header, text="", style="Muted.TLabel")
        self._summary_confidence.pack(side="left", padx=(6, 0))

        self._summary_title = ttk.Label(
            body, text="", style="Card.TLabel", wraplength=900, justify="left",
            font=self.fonts.body_bold,
        )
        self._summary_title.configure(background=PALETTE.background)
        self._summary_title.pack(anchor="w", pady=(0, 8))

        facts_card = Card(body, "Incident facts", fonts=self.fonts, padding=18)
        facts_card.pack(fill="x")
        self._summary_facts = KeyValueList(facts_card, label_width=20, wraplength=520)
        self._summary_facts.pack(fill="x")

        devices_card = Card(
            body, "Devices involved",
            subtitle="every address this incident's evidence names",
            fonts=self.fonts, padding=18,
        )
        devices_card.pack(fill="x", pady=(16, 0))
        self._summary_devices = DataTable(
            # A four-row list inside the summary: the count is in the note
            # below it, and a filter box over four rows would be noise.
            devices_card, DEVICE_COLUMNS, height=4, show_footer=False,
            show_toolbar=False,
            empty_text="No device addresses recorded for this incident",
            # Double-click inspects the device here; the menu still offers the
            # full inventory page for when the investigation moves on to it.
            on_activate=self._inspect_device,
            actions=[
                RowAction("Inspect device", self._inspect_device),
                RowAction("Open in host inventory", self._open_device_host),
            ],
        )
        self._summary_devices.pack(fill="x")
        self._summary_devices_note = ttk.Label(
            devices_card, text="", style="CardDim.TLabel", wraplength=880,
            justify="left",
        )
        self._summary_devices_note.pack(anchor="w", pady=(6, 0))

        description_card = Card(body, "What was observed", fonts=self.fonts, padding=18)
        description_card.pack(fill="x", pady=(16, 0))
        self._summary_description = ttk.Label(
            description_card, text="", style="Card.TLabel", wraplength=880,
            justify="left",
        )
        self._summary_description.pack(anchor="w")

        risk_card = Card(
            body, "How the severity was calculated",
            subtitle="every factor that contributed", fonts=self.fonts, padding=18,
        )
        risk_card.pack(fill="x", pady=(10, 4))
        self._summary_risk = RiskFactorList(risk_card, fonts=self.fonts)
        self._summary_risk.pack(fill="x")

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload the incident list."""
        correlation = self.context.correlation
        session = self.session
        if correlation is None or session is None:
            return

        filters: dict[str, Any] = {"limit": 1000}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._severity_var.get() != "All":
            filters["severity"] = self._severity_var.get()
        if self._category_var.get() != "All":
            filters["category"] = self._category_var.get()
        status = self._status_var.get()
        if status == "Open only":
            filters["open_only"] = True
        elif status != "All":
            filters["status"] = status
        if self._cleared_at is not None:
            filters["start"] = self._cleared_at

        self.status("Loading incidents...")
        self.run_async(
            lambda: correlation.search(session, **filters),
            self._apply,
            name="incidents-load",
        )

    def _apply(self, incidents: list[Incident]) -> None:
        """Render the incident table."""
        self._incidents = {i.id: i for i in incidents if i.id is not None}
        self._summary.update_counts(_incident_counts(incidents))
        self._table.set_rows(
            [
                {
                    "_id": incident.id,
                    "reference": incident.reference,
                    "severity": str(incident.severity),
                    "confidence": f"{incident.confidence}%",
                    "category": incident.category.label,
                    "title": incident.title,
                    "sources": incident.source_label,
                    "status": str(incident.status),
                    "first_seen": format_local(incident.first_seen, "%d %b %H:%M"),
                    "last_seen": format_local(incident.last_seen, "%d %b %H:%M"),
                }
                for incident in incidents
            ]
        )
        self._count_label.configure(text=f"{len(incidents):,} incident(s)")
        multi = sum(1 for i in incidents if i.is_multi_source)
        self._summary_label.configure(
            text=(
                f"{len(incidents):,} incident(s) shown · {multi} supported by more "
                "than one subsystem · an incident lists exactly which subsystems "
                "contributed evidence."
            )
        )
        self.status(
            f"{len(incidents):,} incident(s) loaded."
            if incidents
            else "No incidents match the current filters."
        )

        if self._focus_incident is not None:
            for row_id, row in zip(
                self._table.tree.get_children(), self._table.rows(visible_only=True)
            ):
                if int(row.get("_id") or 0) == self._focus_incident:
                    self._table.tree.selection_set(row_id)
                    self._table.tree.see(row_id)
                    break
            self._focus_incident = None
        elif incidents:
            self._table.select_first()

    def _selected_incident(self) -> Incident | None:
        """The currently selected incident."""
        return self._incident_from_row(self._table.selected_row())

    def _incident_from_row(self, row: dict[str, Any] | None) -> Incident | None:
        """The incident a table row stands for."""
        if not row:
            return None
        return self._incidents.get(int(row.get("_id") or 0))

    def _copy_reference(self, incident: Incident | None = None) -> None:
        """Copy the incident's reference to the clipboard."""
        incident = incident or self._selected_incident()
        if incident is None:
            self.status("Select an incident first.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(incident.reference)
        except tk.TclError:  # pragma: no cover - no clipboard on this display
            self.status("The clipboard is not available on this display.")
            return
        self.status(f"Copied {incident.reference} to the clipboard.")

    def _load_investigation(self, _row: dict[str, Any]) -> None:
        """Load the full evidence bundle for the selected incident."""
        incident = self._selected_incident()
        correlation = self.context.correlation
        session = self.session
        if incident is None or incident.id is None or correlation is None or session is None:
            return
        incident_id = incident.id
        self.run_async(
            lambda: correlation.evidence_bundle(session, incident_id),
            self._render_investigation,
            name="incident-bundle",
        )

    def _render_investigation(self, bundle: dict[str, Any]) -> None:
        """Populate every investigation tab from real records."""
        self._bundle = bundle
        incident: Incident | None = bundle.get("incident")
        if incident is None:
            return

        self._investigation_card.set_subtitle(
            f"{incident.reference} · {incident.severity} · {incident.status}"
        )
        self._render_summary(bundle)
        self._write("evidence", self._evidence_text(bundle))
        self._write("timeline", self._timeline_text(bundle))
        self._write("mitigation", self._mitigation_text(bundle))
        self._write("notes", self._notes_text(bundle))

    def _write(self, key: str, content: str) -> None:
        """Replace one tab's contents."""
        widget = self._tabs[key]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    @staticmethod
    def _description_without_scoring(description: str) -> str:
        """The stored description minus the scoring section.

        The severity calculation is drawn as labelled bars below, so repeating
        the same lines as prose here would show every factor twice. The stored
        record itself is untouched - reports still carry the full text.
        """
        if not description:
            return "No description was recorded."
        head, marker, _tail = description.partition(
            "HOW THE SEVERITY WAS CALCULATED:"
        )
        return (head if marker else description).strip()

    def _render_summary(self, bundle: dict[str, Any]) -> None:
        """Fill the summary tab: chips, facts and the severity breakdown (§28)."""
        incident: Incident = bundle["incident"]
        host = bundle.get("host")

        self._summary_reference.configure(text=incident.reference)
        self._summary_chips["severity"].update_value(str(incident.severity))
        self._summary_chips["status"].update_value(str(incident.status))
        self._summary_chips["category"].update_value(incident.category.label)
        self._summary_confidence.configure(
            text=(
                f"{incident.confidence}% confidence  ·  {incident.source_label}  ·  "
                f"risk score {incident.risk_score}"
            )
        )
        self._summary_title.configure(text=incident.title)

        destination = incident.dst_ip or "-"
        if incident.dst_port:
            destination = f"{destination}:{incident.dst_port}"
        affected = incident.affected_host_ip or "-"
        if host is not None and host.hostname:
            affected = f"{affected} ({host.hostname})"

        self._summary_facts.set_items(
            [
                ("Source (attacker)", incident.src_ip or "-"),
                ("Destination", destination),
                ("Protocol", incident.protocol or "-"),
                ("Affected host", affected),
                ("Affected service", incident.affected_service or "-"),
                (
                    "Trusted asset",
                    "yes - an administrator registered this host as expected"
                    if host is not None and host.is_trusted
                    else "no",
                ),
                ("First seen", format_local(incident.first_seen)),
                ("Last seen", format_local(incident.last_seen)),
                ("Duration", format_duration(incident.duration_seconds)),
                (
                    "Evidence events",
                    f"{incident.event_count} "
                    f"(Snort {incident.snort_alert_count}, anomalies "
                    f"{incident.anomaly_count}, Nmap findings "
                    f"{incident.finding_count})",
                ),
                ("Assigned to", incident.assigned_username or "unassigned"),
                ("Analyst evaluation", incident.evaluation.label),
            ],
            colours={"Trusted asset": PALETTE.ok if host and host.is_trusted else PALETTE.text},
        )
        self._render_devices(bundle.get("devices", []))
        self._summary_description.configure(
            text=self._description_without_scoring(incident.description)
        )
        self._summary_risk.set_factors(
            parse_explanation_lines(incident.risk_rationale),
            total=incident.risk_score,
        )

    def _render_devices(self, devices: list[dict[str, Any]]) -> None:
        """List every device the incident's evidence names (§44).

        An incident often spans more than one device. Each address is shown
        with the role it played, and with whatever the host inventory knows
        about it - a dash where the inventory has nothing rather than a guess.
        """
        self._devices = list(devices)
        self._summary_devices.set_rows(
            [
                {
                    "_host_id": device.get("host_id"),
                    "_ip": device.get("ip", ""),
                    "role": device.get("role", "-"),
                    "ip": device.get("ip", "-"),
                    "hostname": device.get("hostname") or "-",
                    "mac": device.get("mac") or "-",
                    "os": device.get("os") or "-",
                    "status": device.get("status") or "-",
                    "risk": device.get("risk") or "-",
                    "trusted": "yes" if device.get("is_trusted") else "-",
                }
                for device in devices
            ]
        )
        sources = sum(1 for device in devices if device.get("is_source"))
        targets = len(devices) - sources
        unknown = sum(1 for device in devices if not device.get("known"))
        if not devices:
            note = (
                "This incident's evidence does not name any address. Nothing "
                "is shown rather than a placeholder."
            )
        else:
            note = (
                f"{len(devices)} device(s): {sources} acting as a source, "
                f"{targets} as a target. Double-click a row to inspect it "
                "without leaving this incident."
            )
            if unknown:
                note += (
                    f" {unknown} address(es) are not in the inventory, so only "
                    "the address itself is known."
                )
        self._summary_devices_note.configure(text=note)

    def _open_device_host(self, row: dict[str, Any]) -> None:
        """Open the host inventory for one of the incident's devices."""
        host_id = row.get("_host_id")
        address = str(row.get("_ip") or "")
        if host_id:
            self.app.navigate("hosts", focus_host=int(host_id))
        elif address:
            self.app.navigate("hosts", search=address)
        else:
            self.status("That address is not in the host inventory.")

    def _inspect_device(self, row: dict[str, Any]) -> None:
        """Inspect a device in the drawer, staying on this incident.

        Following an address usually means leaving the incident and losing your
        place in it. The drawer answers "what is this machine?" in place, and
        still offers the full inventory page for when the trail leads there.
        """
        address = str(row.get("_ip") or "")
        device = next(
            (d for d in self._devices if d.get("ip") == address),
            {"ip": address, "role": row.get("role", "-")},
        )
        host_id = row.get("_host_id")
        hosts = self.context.hosts
        session = self.session

        if not host_id or hosts is None or session is None:
            self._show_device_drawer(
                address or "Unknown address",
                subtitle=f"{device.get('role', '-')} in {self._reference()}",
                chips=incident_device_chips(device),
                sections=unknown_device_sections(device),
                address=address,
            )
            return

        identifier = int(host_id)
        self.status(f"Loading {address}...")
        self.run_async(
            lambda: hosts.detail(session, identifier),
            lambda detail: self._show_host_device(detail, device),
            name="incident-device",
        )

    def _show_host_device(
        self, detail: dict[str, Any], device: dict[str, Any]
    ) -> None:
        """Render a known device's inventory record in the drawer."""
        host = detail.get("host")
        if host is None or not self.is_alive:
            return
        self._show_device_drawer(
            host.display_name,
            subtitle=(
                f"{host.ip_address} · {device.get('role', '-')} in "
                f"{self._reference()}"
            ),
            chips=host_chips(host),
            sections=host_sections(detail),
            address=host.ip_address,
            host_id=host.id,
        )

    def _show_device_drawer(
        self,
        title: str,
        *,
        subtitle: str,
        chips: list[tuple[str, str]],
        sections: list[Any],
        address: str,
        host_id: int | None = None,
    ) -> None:
        """Open (or re-fill) the drawer for one device."""
        if self._drawer is None:
            self._drawer = DetailDrawer(self, self.fonts)
        if host_id:
            primary = (
                "Open in Host Inventory",
                lambda identifier=host_id: self.app.navigate(
                    "hosts", focus_host=identifier
                ),
            )
        elif address:
            primary = (
                "Search the inventory",
                lambda value=address: self.app.navigate("hosts", search=value),
            )
        else:
            primary = None
        self._drawer.show(
            title, subtitle=subtitle, chips=chips, sections=sections,
            primary=primary,
        )
        self.status(f"{title} detail open.")

    def _reference(self) -> str:
        """The reference of the incident currently under investigation."""
        incident = self._bundle.get("incident")
        return incident.reference if incident is not None else "this incident"

    def on_hide(self) -> None:
        """Close the drawer when the operator leaves the screen."""
        if self._drawer is not None:
            self._drawer.close()

    @staticmethod
    def _evidence_text(bundle: dict[str, Any]) -> str:
        """Every supporting record, grouped by subsystem (§96)."""
        alerts = bundle.get("alerts", [])
        anomalies = bundle.get("anomalies", [])
        findings = bundle.get("findings", [])
        lines: list[str] = []

        lines.append(f"SNORT ALERTS ({len(alerts)})")
        if alerts:
            for alert in alerts:
                lines.extend(
                    [
                        f"  {format_local(alert.effective_time)}  "
                        f"{alert.signature_text} [{alert.severity}]",
                        f"    {alert.message}",
                        f"    {alert.src_ip}:{alert.src_port or '-'} -> "
                        f"{alert.dst_ip}:{alert.dst_port or '-'} ({alert.protocol or '-'}), "
                        f"seen {alert.duplicate_count}x",
                        f"    classification: {alert.classification or 'not supplied'}",
                        "",
                    ]
                )
        else:
            lines.append("  No Snort alerts contributed to this incident.\n")

        lines.append(f"TRAFFIC ANOMALIES ({len(anomalies)})")
        if anomalies:
            for anomaly in anomalies:
                lines.extend(
                    [
                        f"  {format_local(anomaly.first_seen)}  {anomaly.rule_id} "
                        f"[{anomaly.severity}]",
                        f"    {anomaly.observation}",
                        f"    measured {anomaly.observed_value:g} against threshold "
                        f"{anomaly.threshold_value:g} over {anomaly.window_seconds}s, "
                        f"{anomaly.event_count} occurrence(s)",
                        *(f"    {line}" for line in anomaly.evidence_lines()[:8]),
                        "",
                    ]
                )
        else:
            lines.append("  No traffic anomalies contributed to this incident.\n")

        lines.append(f"NMAP FINDINGS FOR THE AFFECTED HOST ({len(findings)})")
        if findings:
            for finding in findings:
                lines.extend(
                    [
                        f"  [{finding.risk_level}] {finding.title}",
                        f"    {finding.observation}",
                        f"    {finding.risk_rationale}",
                        f"    reference: {finding.reference_text}",
                        "",
                    ]
                )
        else:
            lines.append(
                "  No assessment findings exist for this host. This incident "
                "therefore does not claim Nmap confirmation.\n"
            )
        return "\n".join(lines)

    @staticmethod
    def _timeline_text(bundle: dict[str, Any]) -> str:
        """Chronological evidence timeline from real timestamps (§80)."""
        entries = bundle.get("timeline", [])
        if not entries:
            return "No timeline entries recorded."
        lines = ["EVIDENCE TIMELINE (local time)", ""]
        for entry in entries:
            lines.append(
                f"{format_local(entry['at'])}  [{entry['source']}]  {entry['summary']}"
            )
        return "\n".join(lines)

    @staticmethod
    def _mitigation_text(bundle: dict[str, Any]) -> str:
        """Mitigation guidance bound to this incident's evidence (§30)."""
        advice = bundle.get("advice")
        if advice is None:
            from aethra_sec.services.mitigation_service import NO_RECOMMENDATION_TEXT

            return NO_RECOMMENDATION_TEXT
        return advice.as_text()

    @staticmethod
    def _notes_text(bundle: dict[str, Any]) -> str:
        """Analyst notes and the incident's own audit history."""
        incident: Incident = bundle["incident"]
        lines = ["INVESTIGATION NOTES", ""]
        if incident.notes:
            for note in incident.notes:
                lines.append(
                    f"{format_local(note.created_at)}  {note.username or 'unknown'}"
                )
                lines.append(f"    {note.note}")
                lines.append("")
        else:
            lines.append("No notes have been added to this incident.\n")

        lines.extend(["EVIDENCE ATTACHMENT HISTORY", ""])
        for event in incident.events:
            lines.append(
                f"{format_local(event.created_at)}  [{event.source.label}] "
                f"{event.event_type}  ref {event.reference_table}#{event.reference_id}"
            )
            if event.summary:
                lines.append(f"    {event.summary}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _set_status(
        self, status: IncidentStatus, incident: Incident | None = None
    ) -> None:
        """Change an incident's status (§94)."""
        incident = incident or self._selected_incident()
        correlation = self.context.correlation
        session = self.session
        if incident is None or incident.id is None or correlation is None or session is None:
            self.status("Select an incident first.")
            return
        if status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED) and not confirm(
            self, f"Mark {status}", f"Mark {incident.reference} as {status}?",
            detail=(
                "The incident and all of its evidence are retained. Only the "
                "workflow status changes, and the change is audited."
            ),
            confirm_label=str(status).title(),
        ):
            return
        incident_id = incident.id
        self.run_async(
            lambda: correlation.set_status(session, incident_id, status),
            lambda _r: (
                self.status(f"{incident.reference} marked {status}."),
                self.refresh(),
            ),
            name="incident-status",
        )

    def _mark_all_viewed(self) -> None:
        """Stamp every unread incident as read, clearing the sidebar badge.

        Only the read marker changes - status, notes and evidence are
        untouched, so nothing here counts as investigating or resolving them.
        """
        correlation = self.context.correlation
        session = self.session
        if correlation is None or session is None:
            return
        self.run_async(
            lambda: correlation.mark_all_viewed(session),
            lambda count: (
                self.status(f"{count} incident(s) marked read."),
                self.refresh(),
                self.app.refresh_nav_badges(),
            ),
            name="incident-mark-all-viewed",
        )

    def _assign_self(self, incident: Incident | None = None) -> None:
        """Assign an incident to the signed-in analyst."""
        incident = incident or self._selected_incident()
        correlation = self.context.correlation
        session = self.session
        if incident is None or incident.id is None or correlation is None or session is None:
            self.status("Select an incident first.")
            return
        incident_id = incident.id
        self.run_async(
            lambda: correlation.assign(session, incident_id, session.user_id),
            lambda _r: (
                self.status(f"{incident.reference} assigned to {session.username}."),
                self.refresh(),
            ),
            name="incident-assign",
        )

    def _add_note(self, incident: Incident | None = None) -> None:
        """Add an investigation note."""
        incident = incident or self._selected_incident()
        correlation = self.context.correlation
        session = self.session
        if incident is None or incident.id is None or correlation is None or session is None:
            self.status("Select an incident first.")
            return

        from aethra_sec.ui.widgets import FormDialog, FormField

        values = FormDialog(
            self, f"Add note to {incident.reference}",
            [FormField("note", "Note", kind="multiline", required=True)],
            fonts=self.fonts, submit_label="Add note",
            intro="Notes are attached to the incident and recorded in the audit trail.",
        ).show()
        if not values:
            return
        incident_id = incident.id
        self.run_async(
            lambda: correlation.add_note(session, incident_id, values["note"]),
            lambda _r: (self.status("Note added."), self._load_investigation({})),
            name="incident-note",
        )

    def _export(self) -> None:
        """Export the visible incidents to CSV."""
        reports = self.context.reports
        session = self.session
        if reports is None or session is None:
            return
        rows = self._table.export_rows(visible_only=True)
        columns = self._table.export_columns()
        self.run_async(
            lambda: str(
                reports.export_records(
                    session, columns, rows, filename=f"incidents_{len(rows)}",
                    description="threat incidents",
                )
            ),
            lambda path: show_message(
                self, "Export complete",
                f"{len(rows)} incident(s) exported" if rows
                else "No records available for export.",
                detail=f"Written to:\n{path}", fonts=self.fonts,
            ),
            name="incident-export",
        )

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def handle_event(self, event: Event) -> None:
        """Refresh when the correlation engine changes something."""
        if event.type in (EventType.INCIDENT_CREATED, EventType.INCIDENT_UPDATED):
            self.refresh()
