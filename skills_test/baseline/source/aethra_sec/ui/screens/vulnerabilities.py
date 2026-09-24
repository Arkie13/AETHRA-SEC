"""Vulnerability assessment screen (§17, §18, §65).

Target entry, scan profile selection, live status, host/port/finding results,
scan history and scan comparison. The authorisation boundary is shown on the
page so the operator can see which networks this installation may assess before
they start (§2).
"""

from __future__ import annotations

import time
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Any

from aethra_sec.core.events import Event, EventType
from aethra_sec.models.enums import AssessmentState, HostStatus, ScanTrigger
from aethra_sec.analytics.assessment_scope import UNAVAILABLE_MESSAGE
from aethra_sec.models.host import (
    AssessmentSummary,
    Host,
    is_confirmed_vulnerability,
)
from aethra_sec.integrations.nmap import (
    DEFAULT_PROFILE,
    TIMING_TEMPLATES,
    ScanProfile,
    available_profiles,
    has_raw_socket_privilege,
)
from aethra_sec.integrations.nmap.profiles import TIMING_DESCRIPTIONS
from aethra_sec.integrations.nmap.runner import (
    contested_subnet_warning,
    list_nmap_interfaces,
)
from aethra_sec.models.mitigation import LOOKUP_FAILED_TEXT
from aethra_sec.models.scan import PortResult, Scan, ScanHostResult
from aethra_sec.services.mitigation_service import NO_RECOMMENDATION_TEXT
from aethra_sec.ui.base import Screen
from aethra_sec.ui.detail_panels import (
    port_chips,
    port_sections,
    scan_host_chips,
    scan_host_sections,
)
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.utils.logging import get_logger
from aethra_sec.ui.widgets.tooltip import attach_tooltip
from aethra_sec.ui.widgets import (
    Card, Column, DataTable, DetailDialog, DetailDrawer, FilterBar, RowAction,
    ScrollableFrame, Toolbar, confirm, show_message,
)
from aethra_sec.ui.widgets.drawer import DrawerSection
from aethra_sec.utils.formatting import truncate
from aethra_sec.utils.timeutil import format_duration, format_local

#: Shown when Nmap is left to choose the interface itself.
INTERFACE_AUTO = "Automatic (route-based)"

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
    Column("port", "Port", width=56, anchor="e"),
    Column("protocol", "Proto", width=56),
    Column("state", "State", width=62, colour_by="state"),
    Column("service", "Service", width=92),
    Column("version", "Version", width=180),
    Column("risk", "Risk", width=112, colour_by="severity", glyph=True),
    Column("finding", "Finding", width=210, stretch=True),
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

#: The automatically populated host inventory. Every value is a stored
#: observation or a derived-from-evidence result - nothing here is typed.
INVENTORY_COLUMNS = (
    # The row is coloured by the security result - the column an operator
    # scans down - so host status and assessment stay plain text beside it.
    Column("security", "Security result", width=130, colour_by="security"),
    Column("ip", "IP address", width=125),
    Column("hostname", "Hostname", width=150),
    Column("mac", "MAC", width=130),
    Column("host_status", "Host", width=74),
    Column("assessment", "Assessment", width=104),
    Column("open_ports", "Open ports", width=80, anchor="e"),
    Column("findings", "Findings", width=72, anchor="e"),
    Column("last_scan", "Last assessment", width=140),
    Column("why", "Detail", width=240, stretch=True),
)

#: The default filter: hosts inside the monitored authorised network.
LOGGER = get_logger("ui.screens.vulnerabilities")

FILTER_MONITORED = "Monitored network"

#: Shown when the inventory table has no rows for the current filter.
INVENTORY_EMPTY_TEXT = (
    "No hosts observed yet. Discovered hosts appear here automatically."
)

#: Filter presets over the real inventory. Each maps to a predicate on a host's
#: derived security result or reachability - never on fabricated categories.
INVENTORY_FILTERS: tuple[str, ...] = (
    FILTER_MONITORED, "All inventory", "Vulnerable", "Safe",
    "No conclusion", "Exposed services", "Scanning", "Queued", "Not assessed",
    "Scan failed", "Timeout", "Offline", "Outside scope",
)

INVENTORY_SORTS: tuple[str, ...] = (
    "Last assessed", "Last seen", "IP address", "Security result",
    "Open ports", "Findings",
)


# ---------------------------------------------------------------------------
# Evidence rendering
#
# Every helper below reads one stored record and writes what is in it. A field
# the scanner did not establish is left out of the list entirely rather than
# printed as "Unknown" or filled with a plausible value: an absent CVE means
# nobody issued one, and inventing either would be the exact failure these
# screens exist to avoid.
# ---------------------------------------------------------------------------
def _is_confirmed(finding: Any) -> bool:
    """Whether a stored finding is evidence of a vulnerability."""
    return is_confirmed_vulnerability(
        verification_required=bool(
            getattr(finding, "verification_required", True)
        ),
        cvss_base_score=getattr(finding, "cvss_base_score", None),
        risk_level=getattr(finding, "risk_level", None),
        reference_id=str(getattr(finding, "reference", "") or ""),
    )


def _rows(*pairs: tuple[str, Any]) -> list[tuple[str, str]]:
    """Label/value rows, dropping every pair whose value is absent."""
    out: list[tuple[str, str]] = []
    for label, value in pairs:
        text = "" if value is None else str(value).strip()
        if text:
            out.append((label, text))
    return out


def _assessment_rows(host: Host, scan: Any) -> list[tuple[str, str]]:
    """What the assessment did, from the scan record it produced."""
    return _rows(
        ("Host status", host.host_status_text),
        ("Assessment", host.assessment_status_text),
        ("Assessment ID", scan.id if scan else host.last_scan_id),
        ("Profile", (getattr(scan, "profile_label", "") or
                     getattr(scan, "profile", "")) if scan else ""),
        ("Nmap version", getattr(scan, "nmap_version", "") if scan else ""),
        ("Command", getattr(scan, "command_line", "") if scan else ""),
        ("Started", format_local(getattr(scan, "started_at", None)) if scan else ""),
        ("Finished", format_local(getattr(scan, "finished_at", None)) if scan else ""),
        ("Duration", f"{scan.duration_seconds:.1f}s"
         if scan and getattr(scan, "duration_seconds", None) else ""),
        ("Hosts up", f"{scan.hosts_up} of {scan.hosts_total}" if scan else ""),
        ("Open ports", host.open_port_count),
        ("Findings", host.finding_count),
        ("Error", getattr(scan, "error_message", "") if scan else ""),
        ("Last assessed", format_local(host.last_assessed_at)
         if host.last_assessed_at else "never"),
    )


def _identity_rows(host: Host) -> list[tuple[str, str]]:
    """Who the device is, as far as real evidence establishes it."""
    return _rows(
        ("IP address", host.ip_address),
        ("MAC address", host.mac_address or "not observed"),
        ("Vendor", host.vendor or "Unknown"),
        ("Hostname", host.hostname or host.hostname_text),
        ("Operating system", host.os_text),
        ("Discovered by", host.discovery_source.label),
        ("Discovery evidence", host.discovery_detail),
        ("Discovered on", host.discovery_interface),
        ("First seen", format_local(host.first_seen) if host.first_seen else ""),
        ("Last seen", format_local(host.last_seen) if host.last_seen else ""),
    )


def _conclusion_section(
    host: Host, conclusion: Any, confirmed: list[Any], scan: Any
) -> DrawerSection:
    """Why this host carries the security result it does."""
    if conclusion.code == "VULNERABLE":
        text = (
            f"The assessment completed and recorded {len(confirmed)} finding"
            f"{'s' if len(confirmed) != 1 else ''} backed by vulnerability "
            "evidence. Each one is set out below with the evidence that "
            "identified it."
        )
    elif conclusion.code == "SAFE":
        text = (
            "The assessment completed, the host answered, and no finding "
            "carries evidence of a vulnerability.\n\n"
            "This states what the configured assessment established. It is "
            "not a claim that the host is secure: only the ports in the "
            "profile were examined, and only vulnerabilities the configured "
            "scripts and knowledge base can recognise would have been found."
        )
    else:
        text = (
            "No security conclusion has been reached for this host.\n\n"
            f"The assessment is {host.assessment_status_text}"
            + (f": {host.assessment_detail}" if host.assessment_detail else ".")
            + "\n\nA host is reported Safe only after an assessment completes "
            "with the host answering. Nothing here is assumed in the meantime."
        )
    return DrawerSection("Security result", subtitle=conclusion.label, text=text)


def _finding_rows(finding: Any) -> list[tuple[str, str]]:
    """One confirmed finding's stored facts."""
    port = getattr(finding, "port", None)
    return _rows(
        ("Finding", getattr(finding, "title", "")),
        ("Severity", getattr(finding, "risk_level", "")),
        ("CVSS", getattr(finding, "cvss_base_score", None)),
        ("CVSS source", getattr(finding, "cvss_source", "")),
        ("Reference", getattr(finding, "reference", "")),
        ("Reference source", getattr(finding, "reference_source", "")),
        ("Affected host", getattr(finding, "ip_address", "")),
        ("Port", f"{port}/{getattr(finding, 'protocol', '')}" if port else ""),
        ("Service", getattr(finding, "service", "")),
        ("Detected by", getattr(finding, "source", "")),
        ("Recorded", format_local(getattr(finding, "created_at", None))
         if getattr(finding, "created_at", None) else ""),
        ("Needs verification",
         "yes" if getattr(finding, "verification_required", False) else "no"),
    )


def _finding_evidence(finding: Any) -> str:
    """The scanner's own words for a finding."""
    parts = [
        str(getattr(finding, part, "") or "").strip()
        for part in ("observation", "concern", "risk_rationale", "evidence")
    ]
    return "\n\n".join(p for p in parts if p)


def _mitigation_drawer_section(
    match: Any, index: int, total: int
) -> DrawerSection:
    """The mitigation mapped to one confirmed vulnerability (§55).

    Three outcomes, kept apart exactly as the alert view keeps them: guidance
    that exists is shown with the mapping that produced it; a category nobody
    has written guidance for says so; a knowledge base that could not be read
    says *that*, because reporting a fault as "nothing is configured" would
    tell the operator something untrue about their own system.

    No text is composed here - every line is a stored knowledge-base field or
    a statement about the lookup.
    """
    heading = (
        "Mitigation recommendation"
        if total == 1
        else f"Mitigation recommendation ({index} of {total})"
    )
    if match is None:
        return DrawerSection(
            heading,
            subtitle="not looked up",
            text=(
                "The mitigation service is not available in this session, so "
                "no lookup was attempted. This is not a statement that the "
                "finding has no guidance."
            ),
        )
    if getattr(match, "lookup_failed", False):
        detail = str(getattr(match, "failure_detail", "") or "").strip()
        return DrawerSection(
            heading,
            subtitle="lookup failed",
            text=LOOKUP_FAILED_TEXT
            + (f"\n\nRecorded error: {detail}" if detail else ""),
        )
    entry = getattr(match, "recommendation", None)
    if entry is None:
        return DrawerSection(
            heading,
            subtitle="no mapping configured",
            rows=[("Threat category", str(match.category))],
            text=(
                "No mapped mitigation recommendation available for this "
                f"finding.\n\n{NO_RECOMMENDATION_TEXT}\n\n"
                + "\n".join(match.mapping_lines())
            ),
        )
    body = "\n\n".join(
        f"{label}\n{str(text).strip()}"
        for label, text in (
            ("What was observed", entry.explanation),
            ("Why it matters", entry.why_it_matters),
            ("Recommended immediate action", entry.immediate_action),
            ("Recommended long-term action", entry.long_term_action),
            ("Verification", entry.verification_steps),
            ("References", entry.references),
        )
        if str(text or "").strip()
    )
    return DrawerSection(
        heading,
        subtitle=entry.threat_name,
        rows=[
            ("Entry", f"{entry.code} - {entry.threat_name}"),
            ("Threat category", str(match.category)),
            ("Applies to service", entry.applies_to_service or "any"),
            ("Knowledge-base status", entry.status_text),
            ("Source / mapping", match.mapping_lines()[0]),
        ],
        text=(
            body
            + "\n\nAETHRA-SEC recommends only. It never blocks an address, "
            "changes a firewall rule, stops a service or locks an account - "
            "the authorised operator decides."
        ),
    )


def _exposure_line(finding: Any) -> str:
    """One open service, as a single line."""
    port = getattr(finding, "port", None)
    where = f"{port}/{getattr(finding, 'protocol', '')}" if port else "-"
    service = getattr(finding, "service", "") or "unidentified service"
    return f"{where:<12} {service:<22} {getattr(finding, 'risk_level', '')}"


@dataclass
class _AutomationView:
    """Everything the automatic-assessment tab shows, assembled off the UI thread."""

    hosts: tuple[Host, ...] = ()
    enabled: bool = False
    engine_ready: bool = False
    engine_detail: str = ""
    discovery_active: bool = False
    discovery_detail: str = ""
    authorized: str = ""
    #: Whether Nmap can fingerprint an OS here. False without raw sockets,
    #: which is why the OS column is mostly Unknown on an unelevated console.
    privileged: bool = False
    detail: str = ""
    #: Counted over the whole inventory in the database, never from ``hosts``.
    summary: AssessmentSummary = field(default_factory=AssessmentSummary)
    #: The table's rows hit the display limit.
    truncated: bool = False
    row_limit: int = 0


HISTORY_COLUMNS = (
    Column("id", "Scan", width=60, anchor="e"),
    Column("target", "Target", width=140),
    Column("profile", "Profile", width=170),
    Column("status", "Status", width=100, colour_by="state"),
    Column("started", "Started", width=140),
    Column("finished", "Finished", width=140),
    Column("duration", "Duration", width=80),
    Column("hosts", "Hosts", width=60, anchor="e"),
    Column("ports", "Open ports", width=80, anchor="e"),
    Column("findings", "Findings", width=70, anchor="e"),
    Column("result", "Result", width=240, stretch=True),
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
        #: The host whose ports the lower panel is showing.
        self._ports_host: ScanHostResult | None = None
        #: Picker label -> Nmap device name, filled from `nmap --iflist`.
        self._interface_devices: dict[str, str] = {}
        #: Nmap's own interface list, kept so diagnostics can name a device.
        self._interfaces: tuple[Any, ...] = ()
        #: The most recent automation snapshot, and the hosts behind the table.
        self._automation: _AutomationView | None = None
        self._inventory_hosts: list[Host] = []
        #: Throttle for the on-tick refresh of the automation tab.
        self._automation_refreshed_at = 0.0
        self._automation_loading = False
        #: Whether the loaded rows are the whole inventory or only the
        #: monitored network, so a filter change knows when to reload.
        self._loaded_whole_inventory = False
        #: Scan ids already announced, so a feedback line is not repeated.
        self._announced_scans: set[int] = set()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the assessment screen.

        The manual scan form used to sit above the tabs, so it cost the
        automated workspace its height on every screen - about 150px of manual
        configuration permanently above a table that is the page's actual
        subject. It now lives in the tab it belongs to, and the automatic
        assessment tab gets the window.
        """
        # Kept, not local: opening a scan from the history has to bring the
        # Results tab forward, or the operator sees nothing happen and
        # concludes the scan was lost.
        self._notebook = ttk.Notebook(self)
        notebook = self._notebook
        notebook.pack(fill="both", expand=True)

        # Automatic assessment is the primary workflow: hosts the capture
        # pipeline observed appear here on their own and are assessed without an
        # operator typing an address. It leads the tabs for that reason.
        #
        # Deliberately NOT a ScrollableFrame. A scroll host sizes its interior
        # to the content's requested height, so `expand=True` on the table
        # inside it does nothing: the table stayed at its minimum row count and
        # the whole tab scrolled instead - two scrollbars down the right edge,
        # and a host table given a fraction of the window. As a plain frame the
        # table's own expand works, it grows with the window, and the only
        # vertical scrollbar on the page is the table's.
        automation = ttk.Frame(notebook, style="TFrame", padding=10)
        self._automation_tab = automation
        notebook.add(automation, text="Automatic assessment")
        self._build_automation(automation)

        # The results tab holds three tables and two summary cards, which
        # together ask for more height than a laptop window has. Scrolling the
        # page is what keeps every one of them at a usable size; without it the
        # tables are squeezed until their rows disappear.
        results = ScrollableFrame(notebook, padding=10)
        self._results_tab = results
        notebook.add(results, text="Manual scan & results")
        self._build_controls(results.interior)
        self._build_results(results.interior)

        history = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(history, text="History & comparison")
        self._build_history(history)

    def _build_controls(self, parent: tk.Misc) -> None:
        """Target, profile, ports, timing and the run controls."""
        card = Card(parent, "New assessment", fonts=self.fonts, padding=12)
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

        # Nmap's own advice when a host does not answer discovery. It is also
        # the only way to scan a host this machine reaches over an interface
        # Nmap does not choose - two adapters claiming one subnet, say.
        ttk.Label(row, text="Interface", style="CardMuted.TLabel").pack(side="left")
        self._interface_var = tk.StringVar(value=INTERFACE_AUTO)
        self._interface_combo = ttk.Combobox(
            row, textvariable=self._interface_var, state="readonly", width=30,
            values=[INTERFACE_AUTO],
        )
        self._interface_combo.pack(side="left", padx=(8, 14))
        attach_tooltip(
            self._interface_combo,
            "Which adapter Nmap sends from. 'Automatic' lets Nmap choose, "
            "which is right unless two adapters claim the same subnet - then "
            "Nmap may probe a virtual adapter that cannot reach the target "
            "and report a live host as down.",
        )

        self._skip_discovery = tk.BooleanVar(value=False)
        skip_box = ttk.Checkbutton(
            row, text="Skip host discovery (-Pn)",
            variable=self._skip_discovery, style="Toolbar.TCheckbutton",
        )
        skip_box.pack(side="left", padx=(0, 14))
        attach_tooltip(
            skip_box,
            "Scan the target without first deciding whether it is up. Use it "
            "when a host is known to be reachable but Nmap reports it down - "
            "a firewall dropping ICMP, or probes leaving on the wrong "
            "interface. Port results are still Nmap's own.",
        )

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

        # A compact one-line warning stands in for the full interface
        # diagnostic, which is several wrapped lines and was permanently
        # occupying the space the host table needed. The text itself is real
        # and unchanged - it moves into the disclosure below, not away.
        self._interface_warning = ttk.Label(
            card, text="", style="CardMuted.TLabel", cursor="hand2", justify="left",
        )
        self._interface_warning.bind("<Button-1>", lambda _e: self._show_details())

        # Everything verbose lives behind one disclosure, collapsed by default:
        # the profile description, the authorisation boundary and the interface
        # routing diagnostic. Nothing is removed - the page simply stops
        # spending half its height explaining a scan nobody has started yet.
        self._details_open = False
        self._details_toggle = ttk.Button(
            card, text="", style="Ghost.TButton", command=self._toggle_details,
        )
        self._details_toggle.pack(anchor="w", pady=(8, 0))
        self._details_box = ttk.Frame(card, style="Card.TFrame")

        self._profile_note = ttk.Label(
            self._details_box, text="", style="CardDim.TLabel", wraplength=1000,
            justify="left",
        )
        self._profile_note.pack(anchor="w", pady=(4, 0))

        self._authorization_note = ttk.Label(
            self._details_box, text="", style="CardMuted.TLabel", wraplength=1000,
            justify="left",
        )
        self._authorization_note.pack(anchor="w", pady=(4, 0))

        # Set only when Nmap's own routes reveal an interface clash.
        self._interface_note = ttk.Label(
            self._details_box, text="", style="CardMuted.TLabel", wraplength=1000,
            justify="left",
        )
        self._interface_note.pack(anchor="w", pady=(4, 0))
        self._paint_details_toggle()

        self._scan_status = ttk.Label(
            card, text="", style="CardMuted.TLabel", wraplength=1000,
            justify="left",
        )
        self._scan_status.pack(anchor="w", pady=(6, 0))

    # ------------------------------------------------------------------
    # Automatic assessment
    # ------------------------------------------------------------------
    def _build_automation(self, parent: tk.Misc) -> None:
        """The automation status, controls and the auto-populated inventory."""
        status = Card(
            parent, "Automatic host discovery and assessment",
            fonts=self.fonts, padding=8,
        )
        status.pack(fill="x")
        self._automation_status = ttk.Label(
            status, text="Loading automatic assessment state...",
            style="CardMuted.TLabel", wraplength=1100, justify="left",
        )
        self._automation_status.pack(anchor="w")
        # The standing notes sit in their own label, always dim. They used to
        # share the label above and inherited its colour, so "Authorised
        # networks: ..." and "Automatic assessment has not run yet." were
        # painted the same alarm red as the state line - five red lines for a
        # console whose only problem was that capture had not been started.
        self._automation_notes = ttk.Label(
            status, text="", style="CardDim.TLabel", wraplength=1100,
            justify="left",
        )
        # Packed only while it has something to say: an empty label still
        # occupies a line, and this one is empty most of the time.
        self._automation_feedback = ttk.Label(
            status, text="", style="CardMuted.TLabel", wraplength=1100, justify="left",
        )

        controls = FilterBar(status)
        controls.pack(fill="x", pady=(6, 0))
        # The counts ride on the control row rather than taking a line of their
        # own; the bar drops them first when the window gets narrow.
        self._automation_counts = ttk.Label(
            controls, text="", style="CardDim.TLabel", justify="left",
        )
        self._auto_toggle_var = tk.BooleanVar(value=False)
        self._syncing_toggle = False
        self._auto_toggle = ttk.Checkbutton(
            controls, text="Automatic assessment",
            variable=self._auto_toggle_var, command=self._toggle_automation,
            style="Toolbar.TCheckbutton",
        )
        self._auto_toggle.pack(side="left")
        if not self.can("settings.manage"):
            # Only an administrator may pause or resume it; everyone else sees
            # the real state, read-only.
            self._auto_toggle.state(["disabled"])
        attach_tooltip(
            self._auto_toggle,
            "When on, hosts observed inside the authorised networks are assessed "
            "automatically with real Nmap. It scans nothing outside those "
            "networks. Discovery continues either way.",
        )
        ttk.Button(
            controls, text="Refresh", style="Ghost.TButton",
            command=self._refresh_automation,
        ).pack(side="right")
        controls.add(self._automation_counts, side="right", padx=(12, 12), optional=True)

        inventory = Card(
            parent, "Discovered hosts",
            subtitle="observed on the network, assessed automatically",
            fonts=self.fonts, padding=10,
        )
        inventory.pack(fill="both", expand=True, pady=(8, 0))

        run_action = (
            [RowAction("Assess now", self._assess_inventory_host)]
            if self.can("scan.run") else []
        )
        self._inventory_table = DataTable(
            inventory, INVENTORY_COLUMNS, height=14,
            on_activate=self._open_inventory_host,
            # The screen owns the search below, so the grid does not draw a
            # second one; its controls share this table's own toolbar row.
            show_quick_filter=False,
            empty_text=INVENTORY_EMPTY_TEXT,
            actions=[
                *run_action,
                RowAction("Open last results", self._open_inventory_last_scan),
                RowAction("Open in host inventory", self._open_inventory_in_hosts),
            ],
        )

        bar = self._inventory_table.toolbar
        assert bar is not None  # built with show_toolbar defaulting to True
        ttk.Label(bar, text="Show", style="CardMuted.TLabel").pack(side="left")
        self._filter_var = tk.StringVar(value=FILTER_MONITORED)
        filter_combo = ttk.Combobox(
            bar, textvariable=self._filter_var, state="readonly", width=18,
            values=list(INVENTORY_FILTERS),
        )
        filter_combo.pack(side="left", padx=(6, 14))
        # Switching between the monitored network and the whole inventory
        # changes which rows are loaded, so it reloads; every other preset
        # filters the rows already on hand.
        filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_filter_changed())

        ttk.Label(bar, text="Sort", style="CardMuted.TLabel").pack(side="left")
        self._sort_var = tk.StringVar(value="Last assessed")
        sort_combo = ttk.Combobox(
            bar, textvariable=self._sort_var, state="readonly", width=15,
            values=list(INVENTORY_SORTS),
        )
        sort_combo.pack(side="left", padx=(6, 14))
        sort_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_inventory())

        ttk.Label(bar, text="Search", style="CardMuted.TLabel").pack(side="left")
        self._inv_search_var = tk.StringVar()
        search_entry = ttk.Entry(bar, textvariable=self._inv_search_var, width=22)
        search_entry.pack(side="left", padx=(6, 0))
        # Client-side over the already-loaded real rows, so it is instant and
        # never issues a query per keystroke.
        search_entry.bind("<KeyRelease>", lambda _e: self._render_inventory())
        attach_tooltip(
            search_entry, "Filter by IP address, hostname or MAC. Searching "
            "never creates a host.",
        )

        self._inventory_table.pack(fill="both", expand=True)

    def _refresh_automation(self) -> None:
        """Reload the automation snapshot and inventory off the UI thread."""
        hosts_service = self.context.hosts
        session = self.session
        if hosts_service is None or session is None or self._automation_loading:
            return
        queue = self.context.assessment_queue
        nmap = self.context.nmap
        capture = self.context.capture
        self._automation_loading = True
        self._automation_refreshed_at = time.monotonic()
        # Tk variables are read here, on the Tk thread; the worker must not.
        whole_inventory = self._filter_var.get() in ("All inventory", "Outside scope")
        self._loaded_whole_inventory = whole_inventory
        row_limit = 1000

        def work() -> _AutomationView:
            view = _AutomationView(row_limit=row_limit)
            scope = queue.scope(refresh=True) if queue is not None else None
            # The tiles are counted over the whole inventory in the database,
            # with the same per-host derivation the rows use - not from the
            # rows below, which are capped for display. Counting the capped
            # rows is how a tile once read 1,000 on an inventory of 2,002.
            view.summary = hosts_service.assessment_summary(session, scope)
            hosts = hosts_service.assessment_overview(
                session, limit=row_limit, scope=scope,
                in_scope_only=not whole_inventory,
            )
            view.hosts = tuple(hosts)
            view.truncated = len(hosts) >= row_limit
            if queue is not None:
                view.enabled = queue.enabled
                try:
                    view.detail = queue.statistics().detail
                except Exception:  # noqa: BLE001
                    view.detail = ""
            from aethra_sec.integrations.nmap.profiles import (
                has_raw_socket_privilege,
            )

            view.privileged = has_raw_socket_privilege()
            if nmap is not None:
                availability = nmap.availability()
                view.engine_ready = bool(availability.available)
                view.engine_detail = availability.detail
                view.authorized = nmap.authorization_summary()
            if capture is not None:
                try:
                    state = str(capture.state)
                except Exception:  # noqa: BLE001
                    state = "UNKNOWN"
                view.discovery_active = state == "CAPTURING"
                view.discovery_detail = state
            return view

        def done(view: _AutomationView) -> None:
            self._automation_loading = False
            self._apply_automation(view)

        def failed(message: str) -> None:
            self._automation_loading = False
            self._automation_status.configure(
                text=f"Could not load automatic assessment state: {message}",
                foreground=PALETTE.critical,
            )

        self.run_async(work, done, failed, name="automation-refresh")

    def _apply_automation(self, view: _AutomationView) -> None:
        """Render a loaded automation snapshot (on the UI thread)."""
        self._automation = view
        self._inventory_hosts = list(view.hosts)

        summary = view.summary
        discovery = "ACTIVE" if view.discovery_active else "INACTIVE"
        engine = "READY" if view.engine_ready else "ERROR"
        enabled = "ON" if view.enabled else "OFF"
        if view.enabled and not summary.scope_available:
            enabled = "UNAVAILABLE"
        status_lines = [
            f"AUTOMATIC DISCOVERY: {discovery} (capture {view.discovery_detail or 'unknown'})"
            f"     AUTOMATIC ASSESSMENT: {enabled}     ASSESSMENT ENGINE: {engine}",
        ]
        if summary.scope_available:
            status_lines.append(summary.scope_text)
        else:
            # The exact wording is deliberate: automation has stopped and says
            # why, rather than guessing a network to scan.
            status_lines.append(
                summary.scope_text or UNAVAILABLE_MESSAGE
            )
        if view.authorized:
            status_lines.append(f"Manual (on-demand) scans: {view.authorized}")
        if not view.engine_ready and view.engine_detail:
            status_lines.append(view.engine_detail)
        if not view.discovery_active:
            status_lines.append(
                "Discovery is inactive because packet capture is not running. "
                "Start capture on the Live Monitoring screen; hosts are "
                "discovered from real observed traffic only."
            )
        if not view.privileged:
            # Says why a whole column reads Unknown, and what would change it.
            # Nmap's OS fingerprinting needs raw sockets; without them the
            # only operating system evidence is what a service banner happens
            # to reveal, which is coarse ("Linux/Unix") or absent. Leaving the
            # operator to guess at that is what makes Unknown look broken
            # rather than unknown.
            status_lines.append(
                "OS fingerprinting is unavailable: Nmap needs raw sockets for "
                "it, which means running AETHRA-SEC as Administrator with "
                "Npcap installed. Operating systems are reported only where a "
                "service banner names one, so most hosts read Unknown. "
                "Hostnames are unaffected."
            )
        if view.detail and view.detail not in status_lines[1]:
            status_lines.append(view.detail)
        self._automation_status.configure(
            text="\n".join(line for line in status_lines if line),
            foreground=(
                PALETTE.text_muted
                if summary.scope_available or not view.enabled
                else PALETTE.critical
            ),
        )

        # Three lines, because these are three different questions. Mixing a
        # security conclusion ("vulnerable") with an assessment outcome
        # ("timeout") and an exposure grading ("low-rated") on one line was
        # what let an unexamined host read as a graded one.
        scope_word = "IN SCOPE" if summary.scope_available else "IN INVENTORY"
        counts = (
            f"DISCOVERED HOSTS ({scope_word}) {summary.discovered}     "
            f"ACTIVE NOW {summary.active}     "
            f"HOSTS NOT SEEN RECENTLY {summary.host_offline}"
            f"\nSECURITY RESULT   VULNERABLE {summary.vulnerable}     "
            f"SAFE {summary.safe}     NO CONCLUSION {summary.not_determined}"
            f"\nASSESSMENT   QUEUED {summary.queued}     "
            f"SCANNING {summary.scanning}     "
            f"NO RESPONSE {summary.offline}     TIMEOUT {summary.timeout}     "
            f"SCAN FAILED {summary.failed}     "
            f"NOT ASSESSED {summary.not_assessed}     SKIPPED {summary.skipped}"
        )
        if summary.scope_available:
            counts += f"     OUTSIDE SCOPE {summary.outside_scope}"
        if view.truncated:
            counts += (
                f"\nThe table shows the {view.row_limit} most recently seen "
                "hosts; the counts above cover every host."
            )
        self._automation_counts.configure(text=counts)

        # Reflect the real enabled state without re-firing the toggle command.
        self._syncing_toggle = True
        try:
            self._auto_toggle_var.set(view.enabled)
        finally:
            self._syncing_toggle = False

        self._render_inventory()

    def _render_inventory(self) -> None:
        """Filter, sort and search the loaded hosts, then fill the table."""
        table = getattr(self, "_inventory_table", None)
        if table is None:
            return
        preset = self._filter_var.get()
        # "Monitored network" cannot be computed without a resolved scope. It
        # used to fall through to the whole inventory, which on this
        # installation meant ~1,600 Internet addresses observed as traffic
        # destinations were listed under a heading that says they are on the
        # monitored network. The table says why it is empty instead of
        # presenting hosts it cannot vouch for as in-scope.
        summary = getattr(self._automation, "summary", None)
        if preset == FILTER_MONITORED and summary is not None and not summary.scope_available:
            table.set_empty_text(
                "Assessment scope is not configured, so the monitored network "
                "cannot be determined. Start packet capture on the laboratory "
                "interface; hosts are discovered from real observed traffic "
                "only. Choose \"All inventory\" to see every host on record "
                "with its own provenance."
            )
            table.set_rows([])
            return
        table.set_empty_text(INVENTORY_EMPTY_TEXT)
        query = self._inv_search_var.get().strip().lower()
        rows = [
            host for host in self._inventory_hosts
            if self._matches_filter(host, preset)
            and self._matches_search(host, query)
        ]
        rows.sort(key=self._sort_key(self._sort_var.get()), reverse=self._sort_reverse())
        # Reconciled, not rebuilt: the inventory refreshes every few seconds and
        # a full rebuild threw away the scroll position and the selection each
        # time. The address is the stable identity of a row.
        table.reconcile_rows(
            [
                {
                    "_host": host,
                    # The three-valued conclusion, not the lifecycle state:
                    # Vulnerable, Safe, or "-" when the assessment reached no
                    # conclusion. What the assessment is doing is the next
                    # column along.
                    "security": host.security_conclusion.label,
                    "ip": host.ip_address,
                    "hostname": host.hostname or host.hostname_text,
                    "mac": host.mac_address or "N/A",
                    "host_status": host.host_status_text,
                    "assessment": host.assessment_status_text,
                    "open_ports": host.open_port_count,
                    "findings": host.finding_count,
                    "last_scan": (
                        format_local(host.last_assessed_at)
                        if host.last_assessed_at else "never"
                    ),
                    "why": self._detail_text(host),
                }
                for host in rows
            ],
            key="ip",
        )

    #: Longest Detail text a row carries. The classification basis and the
    #: assessment reason together run to a paragraph, which made every row as
    #: tall as its longest sentence; the full text stays on the host.
    DETAIL_CELL_CHARS = 90

    @classmethod
    def _detail_text(cls, host: Host) -> str:
        """Why the host is in its state, and what its classification rests on.

        Truncated for the cell: the untruncated text is on the host record and
        is shown in the host detail, so nothing is lost by keeping the table
        readable.
        """
        parts: list[str] = []
        reason = host.assessment_reason_text
        if reason:
            parts.append(reason)
        basis = host.classification_basis
        if basis:
            parts.append(basis)
        return truncate("; ".join(parts), cls.DETAIL_CELL_CHARS)

    def _on_filter_changed(self) -> None:
        """Reload when the row source changes; otherwise filter in place."""
        wants_all = self._filter_var.get() in ("All inventory", "Outside scope")
        if wants_all != self._loaded_whole_inventory:
            self._refresh_automation()
        else:
            self._render_inventory()

    @staticmethod
    def _matches_filter(host: Host, preset: str) -> bool:
        """Whether a host belongs in the chosen filter, by real state."""
        code = host.security_result.code
        if preset == "All inventory":
            return True
        if preset == FILTER_MONITORED:
            return host.in_scope is not False
        if preset == "Outside scope":
            return host.in_scope is False
        if preset == "Vulnerable":
            return code == "VULNERABLE"
        if preset == "Safe":
            return code == "SAFE"
        if preset == "No conclusion":
            return host.security_conclusion.code == "NOT_DETERMINED"
        if preset == "Exposed services":
            # Open ports with nothing confirmed behind them. Worth reviewing,
            # and deliberately not the same question as "Vulnerable".
            return host.finding_count > 0 and host.confirmed_finding_count == 0
        if preset == "Scanning":
            return host.assessment_state is AssessmentState.SCANNING
        if preset == "Queued":
            return host.assessment_state is AssessmentState.QUEUED
        if preset == "Not assessed":
            return code == "NOT_ASSESSED"
        if preset == "Scan failed":
            return code in ("SCAN_FAILED", "CANCELLED")
        if preset == "Timeout":
            return code == "TIMEOUT"
        if preset == "Offline":
            return code == "OFFLINE" or host.status is HostStatus.DOWN
        return True

    @staticmethod
    def _matches_search(host: Host, query: str) -> bool:
        """Match the search text against real host identifiers only."""
        if not query:
            return True
        return (
            query in host.ip_address.lower()
            or query in host.hostname.lower()
            or query in host.mac_address.lower()
        )

    @staticmethod
    def _sort_key(sort: str) -> Any:
        """A sort key over real host fields."""
        from datetime import datetime, timezone

        floor = datetime.min.replace(tzinfo=timezone.utc)
        if sort == "IP address":
            import ipaddress

            def by_ip(host: Host) -> Any:
                try:
                    return (0, int(ipaddress.ip_address(host.ip_address)))
                except ValueError:
                    return (1, 0)

            return by_ip
        if sort == "Security result":
            return lambda host: host.security_result.label
        if sort == "Open ports":
            return lambda host: host.open_port_count
        if sort == "Findings":
            return lambda host: host.finding_count
        if sort == "Last seen":
            return lambda host: host.last_seen or floor
        return lambda host: host.last_assessed_at or floor

    def _sort_reverse(self) -> bool:
        """Numeric and time sorts read most-interesting-first."""
        return self._sort_var.get() not in ("IP address", "Security result")

    def _toggle_automation(self) -> None:
        """Pause or resume automatic assessment (administrator only)."""
        if self._syncing_toggle:
            return
        queue = self.context.assessment_queue
        session = self.session
        if queue is None or session is None:
            return
        wanted = bool(self._auto_toggle_var.get())
        try:
            queue.set_enabled(session, wanted)
        except Exception as exc:  # noqa: BLE001
            # Put the toggle back to the real state and report why.
            self._syncing_toggle = True
            try:
                self._auto_toggle_var.set(not wanted)
            finally:
                self._syncing_toggle = False
            self.show_error_message(str(exc), "Could not change automatic assessment")
            return
        self.status(
            f"Automatic assessment {'enabled' if wanted else 'paused'}."
        )
        self._refresh_automation()

    def _inventory_host_for(self, row: dict[str, Any]) -> Host | None:
        """The host object behind an inventory row."""
        host = row.get("_host")
        return host if isinstance(host, Host) else None

    def _assess_inventory_host(self, row: dict[str, Any]) -> None:
        """Run a real assessment now against the selected discovered host."""
        nmap = self.context.nmap
        session = self.session
        host = self._inventory_host_for(row)
        if nmap is None or session is None or host is None:
            return
        target = host.ip_address

        def work() -> int:
            return nmap.start_scan(session, target, trigger=ScanTrigger.MANUAL)

        def started(scan_id: int) -> None:
            self._active_scan_id = scan_id
            self._announce(f"Assessing {target}...")
            self.status(f"Assessment {scan_id} started for {target}.")
            self._refresh_automation()

        def failed(message: str) -> None:
            self._announce(f"Assessment of {target} refused: {message}")
            self.show_error_message(message, "Assessment refused")

        self.run_async(work, started, failed, name="inventory-assess")

    def _open_inventory_host(self, row: dict[str, Any]) -> None:
        """Open the selected host's assessment evidence in the drawer.

        The security column states a conclusion in one word; this is where
        that word has to justify itself. Every value shown is read back from
        the stored assessment for *this* host - nothing is templated, and a
        field the scanner did not establish is omitted rather than filled in.
        """
        host = self._inventory_host_for(row)
        if host is None:
            return
        self.run_async(
            lambda h=host: self._load_host_evidence(h),
            lambda payload: self._show_host_evidence(*payload),
            lambda message: self.status(
                f"Could not load the assessment evidence: {message}"
            ),
            name="host-evidence",
        )

    def _load_host_evidence(
        self, host: Host
    ) -> tuple[Host, list[Any], Any, dict[int, Any]]:
        """Read this host's findings, its last assessment and their guidance.

        The mitigation lookup happens here, on the worker, and only for the
        findings that are evidence of a vulnerability - those are the ones the
        drawer has to answer "what do I do about it?" for. Exposures are listed
        without guidance because an open port is not by itself something to
        remediate.
        """
        nmap = self.context.nmap
        session = self.session
        if nmap is None or session is None or not host.id:
            return host, [], None, {}
        findings, scan = nmap.host_evidence(
            session, int(host.id), host.last_scan_id
        )
        guidance: dict[int, Any] = {}
        mitigation = self.context.mitigation
        if mitigation is not None:
            for finding in findings:
                if not _is_confirmed(finding):
                    continue
                key = id(finding)
                try:
                    guidance[key] = mitigation.match_for_finding(finding)
                except Exception:  # noqa: BLE001 - reported in the drawer
                    LOGGER.exception(
                        "Mitigation lookup failed for finding %s",
                        getattr(finding, "id", "?"),
                    )
        return host, findings, scan, guidance

    def _show_host_evidence(
        self,
        host: Host,
        findings: list[Any],
        scan: Any,
        guidance: dict[int, Any] | None = None,
    ) -> None:
        """Render the evidence behind this host's security result (UI thread)."""
        guidance = guidance or {}
        if self._drawer is None:
            self._drawer = DetailDrawer(self, self.fonts)
        conclusion = host.security_conclusion
        confirmed = [f for f in findings if _is_confirmed(f)]
        exposures = [f for f in findings if not _is_confirmed(f)]

        sections = [
            DrawerSection("Assessment", rows=_assessment_rows(host, scan)),
            DrawerSection("Identity", rows=_identity_rows(host)),
        ]
        sections.append(_conclusion_section(host, conclusion, confirmed, scan))
        for index, finding in enumerate(confirmed, start=1):
            sections.append(
                DrawerSection(
                    f"Vulnerability {index} of {len(confirmed)}",
                    rows=_finding_rows(finding),
                    text=_finding_evidence(finding),
                )
            )
            # §55: a confirmed vulnerability is shown with the mitigation the
            # knowledge base maps to it, so the answer to "what do I do about
            # this?" is in the same place as the evidence for it.
            sections.append(
                _mitigation_drawer_section(
                    guidance.get(id(finding)), index, len(confirmed)
                )
            )
        if exposures:
            sections.append(
                DrawerSection(
                    f"Exposure ({len(exposures)} open service"
                    f"{'s' if len(exposures) != 1 else ''})",
                    subtitle=(
                        "Ports the assessment found open. An open port is not "
                        "a vulnerability, and none of these carries evidence "
                        "of one."
                    ),
                    text="\n".join(_exposure_line(f) for f in exposures),
                )
            )
        self._drawer.show(
            host.hostname or host.ip_address,
            subtitle=f"{host.ip_address} - security result: {conclusion.label}",
            sections=sections,
            primary=(
                "Open in Host Inventory",
                lambda address=host.ip_address: self.app.navigate(
                    "hosts", search=address
                ),
            ),
        )
        self.status(f"{host.ip_address}: {conclusion.label}.")

    def _open_inventory_in_hosts(self, row: dict[str, Any]) -> None:
        """Row action: open in the host inventory screen."""
        self._open_inventory_host(row)

    def _open_inventory_last_scan(self, row: dict[str, Any]) -> None:
        """Open the most recent assessment results for a discovered host."""
        host = self._inventory_host_for(row)
        if host is None:
            return
        if not host.last_scan_id:
            self.status(f"{host.ip_address} has not been assessed yet.")
            return
        self._load_scan(int(host.last_scan_id))
        self._show_results_tab()

    def _announce(self, message: str) -> None:
        """Show a real-time discovery/assessment line (§19)."""
        label = getattr(self, "_automation_feedback", None)
        if label is None:
            return
        label.configure(text=message, foreground=PALETTE.info)
        # Claim its line only when there is a message to occupy it.
        if message and not label.winfo_ismapped():
            label.pack(anchor="w", pady=(4, 0))
        elif not message and label.winfo_ismapped():
            label.pack_forget()

    def _build_results(self, parent: tk.Misc) -> None:
        """Host, port and finding tables for the selected scan."""
        summary = Card(parent, "Scan summary", fonts=self.fonts, padding=12)
        summary.pack(fill="x")
        self._summary_label = ttk.Label(
            summary, text="No scan selected.", style="CardMuted.TLabel",
            wraplength=1000, justify="left",
        )
        self._summary_label.pack(anchor="w")

        hosts_card = Card(parent, "Discovered hosts", fonts=self.fonts, padding=12)
        hosts_card.pack(fill="both", expand=True, pady=(10, 0))
        self._hosts_table = DataTable(
            hosts_card, HOST_COLUMNS, height=4, on_select=self._show_host_ports,
            # Selecting a host fills the panels below; opening it inspects the
            # host in place, so the scan stays on screen behind the drawer.
            on_activate=self._inspect_scan_host,
            empty_text="No hosts in this assessment",
            actions=[
                RowAction("View open ports", self._focus_host_ports),
                RowAction("Inspect host", self._inspect_scan_host),
                RowAction("Open in host inventory", self._open_inventory),
            ],
        )
        self._hosts_table.pack(fill="both", expand=True)

        # Shown only when a completed scan genuinely discovered no hosts. It
        # states Nmap's own outcome rather than leaving an empty grid that
        # reads as a broken screen.
        self._empty_note = ttk.Label(
            hosts_card, text="", style="CardMuted.TLabel",
            wraplength=1000, justify="left",
        )
        self._pn_button = ttk.Button(
            hosts_card, text="Scan this target with -Pn",
            style="Ghost.TButton", command=self._rescan_with_pn,
        )

        # A split rather than a fixed 50/50 grid. The ports table carries
        # seven columns and an even division cut the last two off the right
        # edge - including the finding, which is the column that says whether
        # a port matters. Ports get the larger share, and the sash lets an
        # operator take it back for the findings list.
        #
        # Horizontal only. This row used to sit inside a *vertical* split that
        # also held the hosts table, which meant three tables bid for one
        # window's height: ttk.PanedWindow squeezes panes below their requested
        # size without limit, all of the shortfall landed on the tree (the only
        # row in DataTable's grid carrying weight), and the ports table
        # collapsed to a sliver while its toolbar, headings and footer stayed.
        # The page scrolls instead, so a short window costs a scroll rather
        # than the data.
        lower = ttk.PanedWindow(parent, orient="horizontal")
        lower.pack(fill="both", expand=True, pady=(10, 0))
        self._lower_split = lower
        # ``weight`` only shares out space added on a later resize; the sash
        # starts wherever the panes' requested widths put it, and the findings
        # table asks for more than the ports table does. So the first real
        # layout places it deliberately, once, and the operator owns it after.
        lower.bind("<Configure>", self._place_lower_sash)

        self._ports_card = Card(
            lower, "Open ports", subtitle="select a host above",
            fonts=self.fonts, padding=12,
        )
        lower.add(self._ports_card, weight=3)
        ports_bar = Toolbar(self._ports_card)
        ports_bar.pack(fill="x", pady=(0, 6))
        self._open_only = tk.BooleanVar(value=True)
        ports_bar.add_checkbox(
            "Open ports only", self._open_only, self._refresh_ports
        )
        ports_bar.add_button("Port detail", self._show_port_detail)
        self._ports_table = DataTable(
            self._ports_card, PORT_COLUMNS, height=8,
            on_activate=lambda _row: self._show_port_detail(),
            empty_text="Select a host to see the ports this scan found",
        )
        self._ports_table.pack(fill="both", expand=True)

        findings_card = Card(
            lower, "Security findings", subtitle="derived from observations",
            fonts=self.fonts, padding=12,
        )
        lower.add(findings_card, weight=2)
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


    #: Share of the lower row given to the ports table on first layout.
    PORTS_PANE_SHARE = 0.58

    def _place_lower_sash(self, event: tk.Event) -> None:
        """Put the ports/findings divider where the ports table can be read.

        Runs on the first layout that has a real width and then unbinds, so a
        sash the operator has dragged is never moved back underneath them.
        """
        if event.width < 400:
            return
        self._lower_split.unbind("<Configure>")
        try:
            self._lower_split.sashpos(0, int(event.width * self.PORTS_PANE_SHARE))
        except tk.TclError:  # pragma: no cover - pane not realised yet
            pass

    def _build_history(self, parent: tk.Misc) -> None:
        """Scan history and the comparison pane (§45)."""
        card = Card(parent, "Scan history", fonts=self.fonts, padding=12)
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

        comparison = Card(parent, "Comparison", fonts=self.fonts, padding=12)
        comparison.pack(fill="both", expand=True, pady=(10, 0))
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
        """Populate profiles, boundary text, history and the automation view."""
        self._load_profiles()
        self._load_interfaces()
        self._load_history()
        self._update_scan_controls()
        self._refresh_automation()

    #: Seconds between automatic-assessment refreshes on the UI tick. The
    #: inventory changes at scan and discovery speed, not packet speed, so a
    #: few seconds keeps it live without a query per tick.
    AUTOMATION_REFRESH_SECONDS = 5.0

    def on_tick(self) -> None:
        """Keep the automation tab current while it is on screen."""
        try:
            on_automation_tab = str(self._notebook.select()) == str(self._automation_tab)
        except (tk.TclError, AttributeError):
            return
        if not on_automation_tab or self._automation_loading:
            return
        if (time.monotonic() - self._automation_refreshed_at) >= self.AUTOMATION_REFRESH_SECONDS:
            self._refresh_automation()

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

    def _paint_details_toggle(self) -> None:
        """Label the disclosure with the direction it will move."""
        self._details_toggle.configure(
            text=("▾ Advanced scan details" if self._details_open
                  else "▸ Advanced scan details")
        )

    def _toggle_details(self) -> None:
        """Show or hide the verbose scan/interface diagnostics."""
        self._details_open = not self._details_open
        if self._details_open:
            self._details_box.pack(anchor="w", fill="x", pady=(4, 0))
        else:
            self._details_box.pack_forget()
        self._paint_details_toggle()

    def _show_details(self) -> None:
        """Open the disclosure (used by the compact warning line)."""
        if not self._details_open:
            self._toggle_details()

    def _selected_interface(self) -> str:
        """The Nmap device name chosen, or empty for automatic selection."""
        label = self._interface_var.get()
        if not label or label == INTERFACE_AUTO:
            return ""
        return self._interface_devices.get(label, "")

    def _load_interfaces(self) -> None:
        """List the interfaces Nmap itself reports, off the interface thread.

        Also surfaces a duplicate-subnet clash, which is the one condition no
        scan profile can work around: probes leave on an adapter that cannot
        reach the target, and a live host is reported down.
        """
        path = self.context.settings.tools.nmap_path if self.context.settings else None

        def work() -> tuple[Any, str]:
            return (list_nmap_interfaces(path), contested_subnet_warning(path))

        def done(result: tuple[Any, str]) -> None:
            interfaces, warning = result
            self._interfaces = tuple(interfaces)
            self._interface_devices = {
                entry.label: entry.device for entry in interfaces
            }
            self._interface_combo.configure(
                values=[INTERFACE_AUTO] + [entry.label for entry in interfaces]
            )
            if warning:
                # The full diagnostic goes in the disclosure; the page keeps a
                # single compact line so the condition stays visible without
                # costing the table several lines of height.
                self._interface_note.configure(text=warning, foreground=PALETTE.medium)
                self._interface_warning.configure(
                    text=(
                        "⚠ Network configuration warning - more than one "
                        "adapter routes the same subnet. Click for details."
                    ),
                    foreground=PALETTE.medium,
                )
                self._interface_warning.pack(anchor="w", pady=(6, 0))

        self.run_async(work, done, name="nmap-interfaces")

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
        skip_discovery = bool(self._skip_discovery.get())
        interface = self._selected_interface()

        def work() -> int:
            return nmap.start_scan(
                session, target,
                profile_key=profile.key,
                port_spec=port_spec,
                timing=timing,
                skip_host_discovery=skip_discovery,
                interface=interface,
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

        open_ports_line = scan.open_ports_line
        self._summary_label.configure(
            text=(
                f"Scan {scan.id} · {scan.target} · {scan.profile_label or scan.profile} · "
                f"{scan.status} · {scan.summary_line}\n"
                + (f"Open: {open_ports_line}\n" if open_ports_line else "")
                + f"Interface: {self._summary_interface(scan)}\n"
                + f"Arguments: {scan.arguments or '-'}   |   "
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
                    "hostname": host.hostname_text,
                    "mac": host.mac_address or "-",
                    "status": str(host.status),
                    "os": host.os_text,
                    "open_ports": len(host.open_ports),
                    "risk": str(host.highest_risk),
                }
                for host in scan.hosts
            ]
        )
        self._explain_empty_results(scan)
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
        # Open the first host's ports rather than waiting to be asked. A scan
        # of one host - the common case - then shows its ports immediately
        # instead of reporting a count beside an empty panel.
        self._ports_host = scan.hosts[0] if scan.hosts else None
        self._refresh_ports()
        if scan.hosts:
            self._hosts_table.select_first()
        self.status(f"Assessment {scan.id} loaded: {scan.summary_line}")

    def _summary_interface(self, scan: Any) -> str:
        """Interface line for the scan summary, from the executed command."""
        device = self._interface_from_command(scan)
        if not device:
            return "not pinned - Nmap chose by route metric"
        return self._describe_device(device)

    @staticmethod
    def _interface_from_command(scan: Any) -> str:
        """The Nmap device the scan actually used, from its own command line.

        Read back from what was executed rather than from the form, which the
        operator may have changed since - the diagnostics have to describe the
        run being displayed.
        """
        import re

        for source in (scan.command_line or "", scan.arguments or ""):
            match = re.search(r"-e\s+(\S+)", source)
            if match:
                return match.group(1).strip()
        return ""

    def _describe_device(self, device: str) -> str:
        """Name an Nmap device with its address, when Nmap still reports one."""
        for entry in self._interfaces:
            if entry.device == device:
                return f"{device}  ({entry.address})"
        return device

    def _explain_empty_results(self, scan: Scan) -> None:
        """Say why a completed scan discovered no hosts.

        A blank Discovered Hosts table reads as a broken screen, but "0 hosts
        up" is frequently Nmap's real answer: a target that does not reply to
        host discovery produces **no host element at all** in Nmap's XML, so
        there is genuinely nothing to list. The scan is still a real result,
        and the operator needs the reason and the next step rather than an
        empty grid.

        Nothing here is invented. The target is what the operator submitted,
        the status is the stored scan status, and "no response" is stated only
        because Nmap returned no host record for it.
        """
        if scan.hosts:
            self._empty_note.pack_forget()
            self._pn_button.pack_forget()
            return

        probed = scan.hosts_total or 0
        lines = [
            "SCAN DIAGNOSTICS",
            "",
            f"Target: {scan.target}    Scan status: {scan.status}",
        ]

        # Which interface the probes actually left on. Read back from the
        # command Nmap was given, so this reports what ran rather than what
        # the form currently shows.
        device = self._interface_from_command(scan)
        if device:
            lines.append(f"Interface used: {self._describe_device(device)}")
        else:
            lines.append(
                "Interface used: not pinned - Nmap chose by route metric."
            )
        if probed:
            lines.append(
                f"Host discovery: NO RESPONSE  ({probed} address(es) probed, "
                "0 answered)"
            )
        else:
            lines.append("Host discovery: no address was reported as probed.")
        lines.append(
            "Open ports: not available - Nmap does not scan ports on a host "
            "it considers down."
        )
        lines.append("OS detection: not available for the same reason.")
        already_skipped = "-Pn" in (scan.arguments or "")
        lines.append("")
        lines.append("What to try next:")
        if not self._interface_from_command(scan):
            lines.append(
                "  - Probes were not pinned to an interface. If more than one "
                "adapter claims this subnet, Nmap may have sent them on one "
                "that cannot reach the target. Select the interface explicitly "
                "above and re-run."
            )
        if not already_skipped:
            lines.append(
                "  - The host may be up but dropping discovery probes "
                "(a firewall, or an ICMP-filtering device). Re-run with host "
                "discovery skipped (-Pn)."
            )
        self._empty_note.configure(text=chr(10).join(lines))
        self._empty_note.pack(anchor="w", pady=(8, 0))
        if already_skipped:
            self._pn_button.pack_forget()
        else:
            self._pn_button.pack(anchor="w", pady=(8, 0))

    def _rescan_with_pn(self) -> None:
        """Re-run the displayed scan's target with host discovery skipped."""
        scan = self._current_scan
        if scan is None:
            return
        self._target_var.set(scan.target)
        self._skip_discovery.set(True)
        self._start_scan()

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
            sections=scan_host_sections(host, host.os_text),
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
        self._ports_host = self._scan_host_for(row)
        self._refresh_ports()

    def _focus_host_ports(self, row: dict[str, Any]) -> None:
        """Show a host's ports and put the keyboard on them.

        The row action for an operator who wants the ports and nothing else:
        it fills the panel, drops the "open only" filter back to on, and moves
        focus there so the list can be read and copied without the mouse.
        """
        self._open_only.set(True)
        self._show_host_ports(row)
        self._ports_table.focus_table()

    def _refresh_ports(self) -> None:
        """Rebuild the ports panel for the host currently selected.

        Each port is joined to the finding derived from it, so the risk shown
        beside a port is the risk the engine actually assigned to that port on
        that host - not a severity invented for the display.
        """
        host = self._ports_host
        if host is None:
            self._ports_table.clear()
            self._ports_card.set_subtitle("select a host above")
            return

        open_only = bool(self._open_only.get())
        ports = host.open_ports if open_only else list(host.ports)
        by_port = self._findings_by_port(host)

        self._ports_table.set_rows(
            [
                {
                    "_port": port,
                    "_finding": by_port.get((port.port, port.protocol.lower())),
                    "port": port.port,
                    "protocol": port.protocol.upper(),
                    "state": port.state.upper(),
                    "service": port.service or "unknown",
                    "version": self._version_text(port),
                    "risk": self._port_risk_text(by_port, port),
                    "finding": self._port_finding_text(by_port, port),
                }
                for port in sorted(ports, key=lambda p: (p.protocol, p.port))
            ]
        )
        total = len(host.ports)
        shown = len(ports)
        scope = "open" if open_only else "reported"
        self._ports_card.set_subtitle(
            f"{host.ip_address} · {shown} {scope} of {total} port(s) recorded"
        )

    @staticmethod
    def _findings_by_port(host: ScanHostResult) -> dict[tuple[int, str], Any]:
        """Index this host's findings by the port they were derived from.

        Where several findings share a port, the most serious is kept: that is
        the one that decides whether the port needs attention.
        """
        index: dict[tuple[int, str], Any] = {}
        for finding in host.findings:
            if finding.port is None:
                continue
            key = (int(finding.port), (finding.protocol or "tcp").lower())
            current = index.get(key)
            if current is None or (
                finding.risk_level.severity.rank > current.risk_level.severity.rank
            ):
                index[key] = finding
        return index

    @staticmethod
    def _version_text(port: PortResult) -> str:
        """Product and version as Nmap reported them, or why there is none."""
        text = " ".join(part for part in (port.product, port.version) if part)
        if text:
            return text
        if port.is_open:
            # An open port with no banner is a real state, not a gap in the
            # display: the scan either had no version detection or the service
            # volunteered nothing.
            return "no version detected"
        return "-"

    @classmethod
    def _port_risk_text(
        cls, by_port: dict[tuple[int, str], Any], port: PortResult
    ) -> str:
        """The risk assigned to this port, or blank when none was."""
        finding = by_port.get((port.port, port.protocol.lower()))
        return str(finding.risk_level) if finding else ""

    @classmethod
    def _port_finding_text(
        cls, by_port: dict[tuple[int, str], Any], port: PortResult
    ) -> str:
        """The finding derived from this port, or an honest absence."""
        finding = by_port.get((port.port, port.protocol.lower()))
        if finding:
            return finding.title
        return "no finding raised" if port.is_open else ""

    def _show_port_detail(self) -> None:
        """Open the selected port in the drawer, with its finding if it has one."""
        row = self._ports_table.selected_row()
        if row is None:
            show_message(
                self, "Port detail",
                "Select a port first.", kind="info",
            )
            return
        port: PortResult | None = row.get("_port")
        if port is None or self._ports_host is None:
            return
        if self._drawer is None:
            self._drawer = DetailDrawer(self, self.fonts)
        self._drawer.show(
            f"{port.port}/{port.protocol.upper()} · {port.service or 'unknown'}",
            subtitle=f"{self._ports_host.ip_address} · state {port.state.upper()}",
            chips=port_chips(port, row.get("_finding")),
            sections=port_sections(port, row.get("_finding")),
        )
        self.status(f"Port {port.port}/{port.protocol} detail open.")

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
                    "finished": format_local(scan.finished_at) if scan.finished_at else "-",
                    "duration": format_duration(scan.duration_seconds),
                    "hosts": scan.hosts_up,
                    "ports": scan.open_ports,
                    "findings": scan.findings_count,
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
            # Load the stored record, then bring the Results tab forward. The
            # scan is read from the database by id and nothing about it is
            # written back, so opening an old scan cannot alter it.
            self._load_scan(int(scan_id))
            self._show_results_tab()

    def _show_results_tab(self) -> None:
        """Bring the Results tab forward so a loaded scan is actually seen."""
        try:
            self._notebook.select(self._results_tab)
        except (tk.TclError, AttributeError):  # pragma: no cover - not built
            pass

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
            self._announce(f"Assessing {payload.target}...")
            self._update_scan_controls()
            self._refresh_automation()
        elif event.type == EventType.NMAP_SCAN_COMPLETED:
            payload = event.payload
            # Real-time feedback keyed on the actual outcome (§19). "0 hosts up"
            # is a real result, not a success - it is reported as no response.
            if getattr(payload, "hosts_up", 0):
                self._announce(
                    f"Assessment completed for {payload.target} - "
                    f"{payload.findings} finding(s)."
                )
            else:
                self._announce(
                    f"Assessment completed for {payload.target}: host did not "
                    "respond to the scan (no ports assessed)."
                )
            self._refresh_automation()
            text = (
                f"Completed {payload.target}: {payload.hosts_up} host(s) up, "
                f"{payload.open_ports} open port(s), {payload.findings} "
                f"finding(s) in {payload.duration_seconds:.1f}s"
            )
            colour = PALETTE.ok
            if not payload.hosts_up:
                # "0 hosts up" is Nmap's real answer, not an empty screen. It
                # means discovery got no reply - which is a different thing
                # from the host being absent, and the operator needs to be
                # told which checks distinguish them.
                text += (
                    "\nNmap's host discovery got no reply from this address, so "
                    "no ports were scanned. This is Nmap's own result, not a "
                    "display fault. If you know the host is up, tick 'Skip host "
                    "discovery (-Pn)' and scan again: a host may be silent "
                    "because a firewall drops ICMP and probe packets, or "
                    "because probes are leaving on the wrong interface when "
                    "two adapters claim the same subnet."
                )
                colour = PALETTE.medium
            self._scan_status.configure(text=text, foreground=colour)
            self._active_scan_id = None
            self._update_scan_controls()
            self._load_scan(payload.scan_id)
            self._load_history()
        elif event.type == EventType.NMAP_SCAN_FAILED:
            payload = event.payload
            self._scan_status.configure(
                text=f"Assessment failed: {payload.error}", foreground=PALETTE.critical
            )
            self._announce(
                f"Assessment failed for {payload.target} - {payload.error}"
            )
            self._active_scan_id = None
            self._update_scan_controls()
            self._load_history()
            self._refresh_automation()
