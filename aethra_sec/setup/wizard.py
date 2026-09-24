"""The AETHRA-SEC first-run setup wizard.

Seven steps, in the order the specification asks for: administrator, database,
security tools, network interface, email, health check, finish.

The wizard collects, then applies. The administrator's details are gathered and
validated in step 1 but the account is not created until step 6, because it
cannot be: an account needs a schema, and the schema is what step 2 builds. The
alternative - creating the account the moment the field loses focus - would put
a half-provisioned installation on disk any time the operator changed their mind
about the database, so the wizard deliberately holds everything in memory until
one place applies it all.

Nothing here is simulated. The database step opens a real connection, the tool
step runs the tools, the interface step reads the machine's real adapters and
routing table, the email step sends a real message when asked, and step 6
re-runs every probe and prints what came back. A step that could not be tested
says so; none of them reports success it did not observe.

Long work runs on a worker thread and returns through
:mod:`aethra_sec.ui.dispatch`, so the window keeps repainting while a scan or an
SMTP timeout is in progress and a worker never touches Tk.
"""

from __future__ import annotations

import threading
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import ttk
from typing import Callable

from aethra_sec.config import paths
from aethra_sec.config.settings import AppSettings, load_settings
from aethra_sec.setup import configfile, detection, provisioning
from aethra_sec.setup.healthcheck import HealthReport, run_health_check
from aethra_sec.setup.interfaces import (
    DetectedInterface,
    InterfaceReport,
    detect_interfaces,
    monitoring_position_note,
)
from aethra_sec.ui import dispatch
from aethra_sec.ui.theme import METRICS, PALETTE, Fonts, apply_theme
from aethra_sec.utils.logging import get_logger
from aethra_sec.version import APP_NAME, APP_VERSION

LOGGER = get_logger("setup.wizard")

STEP_TITLES = (
    "Administrator account",
    "Database",
    "Security tools",
    "Network interface",
    "Email notifications",
    "System health check",
    "Finish",
)


@dataclass
class WizardData:
    """Everything the operator entered, held until step 6 applies it.

    The two password fields are the only values in the wizard that are never
    rendered back: they are written into the hash and into the configuration
    file respectively, and cleared from here once used.
    """

    admin_username: str = ""
    admin_password: str = ""
    admin_confirm: str = ""
    admin_email: str = ""

    db_host: str = "127.0.0.1"
    db_port: str = "3306"
    db_name: str = "aethra_sec"
    db_user: str = "root"
    db_password: str = ""

    nmap_path: str = ""
    tshark_path: str = ""
    snort_path: str = ""
    snort_config: str = ""
    snort_transport: str = "disabled"
    snort_alert_file: str = ""

    capture_interface: str = ""
    authorized_networks: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8"

    smtp_host: str = ""
    smtp_port: str = "587"
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_starttls: bool = True

    interface_report: InterfaceReport | None = None
    health: HealthReport | None = None
    applied: bool = False
    notes: list[str] = field(default_factory=list)

    def to_config(self) -> dict[str, str]:
        """The configuration keys these answers produce."""
        try:
            port = int(self.db_port)
        except ValueError:
            port = 3306
        try:
            smtp_port = int(self.smtp_port)
        except ValueError:
            smtp_port = 587
        return configfile.build_values(
            db_host=self.db_host,
            db_port=port,
            db_name=self.db_name,
            db_user=self.db_user,
            db_password=self.db_password,
            nmap_path=self.nmap_path,
            tshark_path=self.tshark_path,
            snort_path=self.snort_path,
            snort_config=self.snort_config,
            snort_transport=self.snort_transport,
            snort_alert_file=self.snort_alert_file,
            capture_interface=self.capture_interface,
            authorized_networks=self.authorized_networks,
            smtp_host=self.smtp_host,
            smtp_port=smtp_port,
            smtp_user=self.smtp_user,
            smtp_password=self.smtp_password,
            smtp_from=self.smtp_from,
            smtp_to=self.smtp_to or self.admin_email,
            smtp_starttls=self.smtp_starttls,
        )


class SetupWizard(tk.Tk):
    """The setup window. Owns its own Tk root and runs before the console."""

    def __init__(self) -> None:
        """Build the wizard and show step 1."""
        super().__init__()
        self.title(f"{APP_NAME} Setup")
        self.geometry("920x680")
        self.minsize(860, 620)
        self.configure(background=PALETTE.background)

        self.fonts: Fonts = apply_theme(self)
        dispatch.ensure(self)

        self.data = WizardData()
        self._prefill_from_existing()

        self._index = 0
        self._busy = False
        self.completed = False
        self._step_frames: list[ttk.Frame] = []

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self._apply_icon()
        self._build()
        self._show_step(0)

    # ------------------------------------------------------------------
    # Chrome
    # ------------------------------------------------------------------
    def _apply_icon(self) -> None:
        """Use the application icon on the setup window too."""
        try:
            from aethra_sec.resources import APPLICATION_ICON, resolve

            icon = resolve(APPLICATION_ICON)
            if icon.available:
                self.iconbitmap(default=str(icon.path))
        except Exception:  # noqa: BLE001 - an icon must never stop setup
            LOGGER.debug("Could not set the window icon.", exc_info=True)

    def _prefill_from_existing(self) -> None:
        """Start from the current configuration when there is one.

        Re-running setup over a working installation must not present empty
        fields that would overwrite it with defaults on the way through.
        """
        existing = configfile.load()
        if not existing.exists:
            return
        get = existing.get
        self.data.db_host = get("AETHRA_DB_HOST", self.data.db_host)
        self.data.db_port = get("AETHRA_DB_PORT", self.data.db_port)
        self.data.db_name = get("AETHRA_DB_NAME", self.data.db_name)
        self.data.db_user = get("AETHRA_DB_USER", self.data.db_user)
        self.data.db_password = get("AETHRA_DB_PASSWORD", "")
        self.data.nmap_path = get("AETHRA_NMAP_PATH", "")
        self.data.tshark_path = get("AETHRA_TSHARK_PATH", "")
        self.data.snort_path = get("AETHRA_SNORT_PATH", "")
        self.data.snort_config = get("AETHRA_SNORT_CONFIG", "")
        self.data.snort_transport = get("AETHRA_SNORT_TRANSPORT", "disabled")
        self.data.snort_alert_file = get("AETHRA_SNORT_ALERT_FILE", "")
        self.data.capture_interface = get("AETHRA_CAPTURE_INTERFACE", "")
        self.data.authorized_networks = get(
            "AETHRA_AUTHORIZED_NETWORKS", self.data.authorized_networks
        )
        self.data.smtp_host = get("AETHRA_SMTP_HOST", "")
        self.data.smtp_port = get("AETHRA_SMTP_PORT", "587")
        self.data.smtp_user = get("AETHRA_SMTP_USER", "")
        self.data.smtp_password = get("AETHRA_SMTP_PASSWORD", "")
        self.data.smtp_from = get("AETHRA_SMTP_FROM", "")
        self.data.smtp_to = get("AETHRA_SMTP_TO", "")
        self.data.smtp_starttls = get("AETHRA_SMTP_STARTTLS", "true").lower() != "false"

    def _build(self) -> None:
        """Header, step rail, body and the button bar."""
        header = ttk.Frame(self, style="AuthBrand.TFrame", padding=(24, 18))
        header.pack(fill="x")
        ttk.Label(
            header, text=f"{APP_NAME} SETUP", style="AuthWordmark.TLabel"
        ).pack(anchor="w")
        self._subtitle = ttk.Label(
            header, text="", style="AuthBrandDim.TLabel"
        )
        self._subtitle.pack(anchor="w", pady=(4, 0))

        rail = ttk.Frame(self, style="TFrame", padding=(24, 10))
        rail.pack(fill="x")
        self._rail_labels: list[ttk.Label] = []
        for number, title in enumerate(STEP_TITLES, start=1):
            label = ttk.Label(
                rail, text=f"{number}. {title}", style="CardDim.TLabel"
            )
            label.pack(side="left", padx=(0, 14))
            self._rail_labels.append(label)

        self._body = ttk.Frame(self, style="TFrame", padding=(24, 8))
        self._body.pack(fill="both", expand=True)

        footer = ttk.Frame(self, style="TFrame", padding=(24, 16))
        footer.pack(fill="x", side="bottom")

        self._status = ttk.Label(footer, text="", style="CardDim.TLabel")
        self._status.pack(side="left")

        self._next_button = ttk.Button(
            footer, text="Next", style="Accent.TButton", command=self._next
        )
        self._next_button.pack(side="right")
        self._back_button = ttk.Button(
            footer, text="Back", style="Ghost.TButton", command=self._back
        )
        self._back_button.pack(side="right", padx=(0, 8))
        ttk.Button(
            footer, text="Cancel", style="Ghost.TButton", command=self._cancel
        ).pack(side="right", padx=(0, 8))

        for builder in (
            self._build_admin_step,
            self._build_database_step,
            self._build_tools_step,
            self._build_interface_step,
            self._build_email_step,
            self._build_health_step,
            self._build_finish_step,
        ):
            frame = ttk.Frame(self._body, style="TFrame")
            builder(frame)
            self._step_frames.append(frame)

    # ------------------------------------------------------------------
    # Small builders
    # ------------------------------------------------------------------
    def _heading(self, parent: tk.Misc, text: str, note: str = "") -> None:
        """A step heading and its explanatory line."""
        ttk.Label(parent, text=text, style="CardTitle.TLabel").pack(
            anchor="w", pady=(0, 4)
        )
        if note:
            label = ttk.Label(
                parent, text=note, style="CardDim.TLabel", justify="left"
            )
            label.pack(anchor="w", pady=(0, METRICS.space_md))
            parent.bind(
                "<Configure>",
                lambda event, widget=label: widget.configure(
                    wraplength=max(420, event.width - 40)
                ),
                add="+",
            )

    def _field(
        self,
        parent: tk.Misc,
        label: str,
        value: str = "",
        *,
        secret: bool = False,
        width: int = 44,
    ) -> tk.StringVar:
        """One labelled entry, returning the variable that holds its value."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, style="CardDim.TLabel", width=24).pack(side="left")
        variable = tk.StringVar(value=value)
        entry = ttk.Entry(
            row, textvariable=variable, width=width,
            show="•" if secret else "",
        )
        entry.pack(side="left", fill="x", expand=True)
        return variable

    def _output(self, parent: tk.Misc, height: int = 14) -> tk.Text:
        """A read-only text area for real command output."""
        from aethra_sec.ui.theme import configure_text_widget

        wrapper = ttk.Frame(parent, style="TFrame")
        wrapper.pack(fill="both", expand=True, pady=(METRICS.space_md, 0))
        text = tk.Text(wrapper, height=height, wrap="word", borderwidth=0)
        configure_text_widget(text, self.fonts, mono=True)
        scroll = ttk.Scrollbar(wrapper, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set, state="disabled")
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        return text

    @staticmethod
    def _write(widget: tk.Text, content: str) -> None:
        """Replace a read-only text area's contents."""
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    # ------------------------------------------------------------------
    # Step 1 - administrator
    # ------------------------------------------------------------------
    def _build_admin_step(self, parent: ttk.Frame) -> None:
        self._heading(
            parent,
            "Step 1 - Administrator account",
            "The first account, with the ADMIN role. The password is stored as "
            "an Argon2id hash and the plaintext is never written anywhere. "
            "Sign-in is a username and a password: AETHRA-SEC has no second "
            "factor and will never send anyone a login code. The email address "
            "is where administrative and security notifications go, if you "
            "configure SMTP in step 5.",
        )
        self._admin_username = self._field(parent, "Admin username", self.data.admin_username)
        self._admin_password = self._field(parent, "Admin password", secret=True)
        self._admin_confirm = self._field(parent, "Confirm admin password", secret=True)
        self._admin_email = self._field(parent, "Admin email address", self.data.admin_email)

        ttk.Label(
            parent,
            text=(
                "Password policy: at least 12 characters, using at least three "
                "of lower case, upper case, digits and symbols."
            ),
            style="CardDim.TLabel",
        ).pack(anchor="w", pady=(METRICS.space_md, 0))

        self._admin_message = ttk.Label(parent, text="", style="CardDim.TLabel")
        self._admin_message.pack(anchor="w", pady=(METRICS.space_md, 0))

    def _validate_admin(self) -> bool:
        self.data.admin_username = self._admin_username.get().strip()
        self.data.admin_password = self._admin_password.get()
        self.data.admin_confirm = self._admin_confirm.get()
        self.data.admin_email = self._admin_email.get().strip()

        problem = provisioning.validate_admin_input(
            self.data.admin_username,
            self.data.admin_password,
            self.data.admin_confirm,
            self.data.admin_email,
        )
        if problem:
            self._admin_message.configure(text=problem, foreground=PALETTE.critical)
            return False
        self._admin_message.configure(
            text="Accepted. The account is created in step 6, once the database exists.",
            foreground=PALETTE.ok,
        )
        return True

    # ------------------------------------------------------------------
    # Step 2 - database
    # ------------------------------------------------------------------
    def _build_database_step(self, parent: ttk.Frame) -> None:
        self._heading(
            parent,
            "Step 2 - Database",
            "MySQL or MariaDB. Test the connection here; the schema itself is "
            "created in step 6. If the database already exists, its contents "
            "are kept - setup applies migrations and never deletes security "
            "history.",
        )
        self._db_host = self._field(parent, "Host", self.data.db_host)
        self._db_port = self._field(parent, "Port", self.data.db_port, width=10)
        self._db_name = self._field(parent, "Database name", self.data.db_name)
        self._db_user = self._field(parent, "User", self.data.db_user)
        self._db_password = self._field(parent, "Password", self.data.db_password, secret=True)

        ttk.Button(
            parent, text="Test connection", style="Accent.TButton",
            command=self._test_database,
        ).pack(anchor="w", pady=(METRICS.space_md, 0))

        self._db_output = self._output(parent, height=10)
        self._write(
            self._db_output,
            "No connection has been tested yet.\n\n"
            "XAMPP users: start MySQL from the XAMPP Control Panel first. The "
            "default XAMPP account is 'root' with an empty password.",
        )

    def _collect_database(self) -> None:
        self.data.db_host = self._db_host.get().strip() or "127.0.0.1"
        self.data.db_port = self._db_port.get().strip() or "3306"
        self.data.db_name = self._db_name.get().strip() or "aethra_sec"
        self.data.db_user = self._db_user.get().strip() or "root"
        self.data.db_password = self._db_password.get()

    def _test_database(self) -> None:
        self._collect_database()
        self._write(self._db_output, "Connecting...")

        settings = self._settings_from_data()

        def work() -> object:
            return detection.probe_database(settings)

        def done(result: object) -> None:
            probe: detection.ProbeResult = result  # type: ignore[assignment]
            lines = [f"[{probe.status}] {probe.detail}", ""]
            lines.extend(f"  {step}" for step in probe.evidence)
            if probe.remedy:
                lines.extend(["", f"  -> {probe.remedy}"])
            self._write(self._db_output, "\n".join(lines))

        self._run_async(work, done, lambda message: self._write(self._db_output, message))

    # ------------------------------------------------------------------
    # Step 3 - security tools
    # ------------------------------------------------------------------
    def _build_tools_step(self, parent: ttk.Frame) -> None:
        self._heading(
            parent,
            "Step 3 - Security tools",
            "Leave a path empty to discover the tool automatically. Each check "
            "runs the tool rather than only looking for the file: Nmap performs "
            "a loopback scan and its XML is parsed, TShark captures for one "
            "second, and Snort validates its configuration with its own test "
            "mode. Nothing is started that could produce an alert.",
        )
        self._nmap_path = self._field(parent, "Nmap executable", self.data.nmap_path)
        self._tshark_path = self._field(parent, "TShark executable", self.data.tshark_path)
        self._snort_path = self._field(parent, "Snort executable", self.data.snort_path)
        self._snort_config = self._field(parent, "Snort configuration", self.data.snort_config)

        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Snort alert ingest", style="CardDim.TLabel", width=24).pack(side="left")
        self._snort_transport = tk.StringVar(value=self.data.snort_transport)
        ttk.Combobox(
            row, textvariable=self._snort_transport, state="readonly", width=14,
            values=("disabled", "file", "tcp", "syslog", "unixsock"),
        ).pack(side="left")
        self._snort_alert_file = self._field(
            parent, "Snort alert file", self.data.snort_alert_file
        )

        ttk.Button(
            parent, text="Detect and verify tools", style="Accent.TButton",
            command=self._detect_tools,
        ).pack(anchor="w", pady=(METRICS.space_md, 0))

        self._tools_output = self._output(parent, height=12)
        self._write(
            self._tools_output,
            "No tools have been verified yet. Select 'Detect and verify tools'.\n\n"
            "Nmap, Wireshark/TShark and Snort are installed separately and are "
            "not part of this installer. Any of them may be absent: the matching "
            "feature then reports itself unavailable rather than pretending to work.",
        )

    def _collect_tools(self) -> None:
        self.data.nmap_path = self._nmap_path.get().strip()
        self.data.tshark_path = self._tshark_path.get().strip()
        self.data.snort_path = self._snort_path.get().strip()
        self.data.snort_config = self._snort_config.get().strip()
        self.data.snort_transport = self._snort_transport.get().strip() or "disabled"
        self.data.snort_alert_file = self._snort_alert_file.get().strip()

    def _detect_tools(self) -> None:
        self._collect_tools()
        self._write(
            self._tools_output,
            "Verifying. This runs each tool, so it takes a few seconds...",
        )

        nmap = Path(self.data.nmap_path) if self.data.nmap_path else None
        tshark = Path(self.data.tshark_path) if self.data.tshark_path else None
        snort = Path(self.data.snort_path) if self.data.snort_path else None
        snort_config = Path(self.data.snort_config) if self.data.snort_config else None

        def work() -> object:
            return [
                detection.probe_nmap(nmap),
                detection.probe_tshark(tshark),
                detection.probe_pyshark(),
                detection.probe_snort(snort, snort_config),
                detection.probe_npcap(),
            ]

        def done(result: object) -> None:
            probes: list[detection.ProbeResult] = result  # type: ignore[assignment]
            lines: list[str] = []
            for probe in probes:
                lines.append(f"[{probe.status}] {probe.name}")
                lines.append(f"        {probe.detail}")
                for step in probe.evidence:
                    lines.append(f"          - {step}")
                if probe.remedy:
                    lines.append(f"        -> {probe.remedy}")
                lines.append("")
            self._write(self._tools_output, "\n".join(lines))

            # Record the discovered locations so the configuration file names
            # the tool that was actually verified rather than leaving the next
            # start to rediscover it and possibly find a different one.
            for probe, variable in (
                (probes[0], self._nmap_path),
                (probes[1], self._tshark_path),
                (probes[3], self._snort_path),
            ):
                if probe.path and not variable.get().strip():
                    variable.set(probe.path)
            self._collect_tools()

        self._run_async(
            work, done, lambda message: self._write(self._tools_output, message)
        )

    # ------------------------------------------------------------------
    # Step 4 - network interface
    # ------------------------------------------------------------------
    def _build_interface_step(self, parent: ttk.Frame) -> None:
        self._heading(
            parent,
            "Step 4 - Network interface",
            "The adapter live capture will use. The recommendation comes from "
            "this machine's routing table, not from the order the adapters "
            "happen to be listed in.",
        )
        ttk.Button(
            parent, text="Detect interfaces", style="Accent.TButton",
            command=self._detect_interfaces,
        ).pack(anchor="w")

        self._interface_list = tk.Listbox(
            parent, height=9, activestyle="none", exportselection=False
        )
        from aethra_sec.ui.theme import configure_listbox

        configure_listbox(self._interface_list, self.fonts)
        self._interface_list.pack(fill="x", pady=(METRICS.space_md, 0))
        self._interface_list.bind("<<ListboxSelect>>", lambda _e: self._on_interface_pick())

        self._interface_note = self._output(parent, height=8)
        self._write(
            self._interface_note,
            "No interfaces detected yet. Select 'Detect interfaces'.",
        )
        self._interface_choices: list[DetectedInterface] = []

    def _detect_interfaces(self) -> None:
        self._collect_tools()
        self._write(self._interface_note, "Reading adapters and routing table...")
        tshark = Path(self.data.tshark_path) if self.data.tshark_path else None

        def work() -> object:
            return detect_interfaces(tshark)

        def done(result: object) -> None:
            report: InterfaceReport = result  # type: ignore[assignment]
            self.data.interface_report = report
            self._interface_choices = list(report.interfaces)
            self._interface_list.delete(0, "end")
            for item in self._interface_choices:
                self._interface_list.insert("end", item.display_label)

            selected = 0
            if self.data.capture_interface:
                for index, item in enumerate(self._interface_choices):
                    if item.name == self.data.capture_interface:
                        selected = index
                        break
            elif report.recommended is not None:
                selected = self._interface_choices.index(report.recommended)
            if self._interface_choices:
                self._interface_list.selection_clear(0, "end")
                self._interface_list.selection_set(selected)
                self._interface_list.see(selected)
            self._on_interface_pick()

        self._run_async(
            work, done, lambda message: self._write(self._interface_note, message)
        )

    def _on_interface_pick(self) -> None:
        """Describe the selected adapter and what it can actually see."""
        report = self.data.interface_report
        selection = self._interface_list.curselection()
        if not self._interface_choices or not selection:
            return
        chosen = self._interface_choices[selection[0]]
        self.data.capture_interface = chosen.name

        lines = [
            f"Interface   : {chosen.friendly_name or chosen.name}",
            f"Device      : {chosen.name}",
            f"Description : {chosen.description or '(none reported)'}",
            f"IPv4        : {chosen.ipv4 or 'none'}",
            f"Subnet      : {chosen.subnet or 'unknown'}",
            f"Gateway     : {chosen.gateway or 'none'}",
            f"MAC         : {chosen.mac or 'unknown'}",
            f"Status      : {chosen.status or 'unknown'}",
            f"Type        : {chosen.kind}"
            + ("  (virtual/tunnel adapter)" if chosen.is_virtual else ""),
            f"Default route: {'yes' if chosen.is_default_route else 'no'}",
            "",
        ]
        if report is not None and report.reason:
            lines.extend(["Recommendation:", f"  {report.reason}", ""])
        if chosen.conflicts:
            lines.extend([
                "WARNING: this adapter shares its subnet with "
                f"{', '.join(chosen.conflicts)}.",
                "  Which one sees a given conversation depends on the routing",
                "  metric. Choose the adapter on the segment you are authorised",
                "  to monitor.",
                "",
            ])
        if report is not None:
            for warning in report.warnings:
                lines.extend([f"WARNING: {warning}", ""])
        lines.append(monitoring_position_note(chosen))
        self._write(self._interface_note, "\n".join(lines))

    # ------------------------------------------------------------------
    # Step 5 - email
    # ------------------------------------------------------------------
    def _build_email_step(self, parent: ttk.Frame) -> None:
        self._heading(
            parent,
            "Step 5 - Email notifications (optional)",
            "Email carries administrative and security notifications only. "
            "Sign-in never uses it, so leaving this empty costs you nothing but "
            "the notifications. For Gmail use smtp.gmail.com port 587 with "
            "STARTTLS, and a 16-character App Password rather than the account "
            "password.",
        )
        self._smtp_host = self._field(parent, "SMTP host", self.data.smtp_host)
        self._smtp_port = self._field(parent, "SMTP port", self.data.smtp_port, width=10)
        self._smtp_user = self._field(parent, "SMTP username", self.data.smtp_user)
        self._smtp_password = self._field(
            parent, "SMTP password", self.data.smtp_password, secret=True
        )
        self._smtp_from = self._field(parent, "Sender address", self.data.smtp_from)
        self._smtp_to = self._field(
            parent, "Notify address", self.data.smtp_to
        )

        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="", width=24, style="CardDim.TLabel").pack(side="left")
        self._smtp_starttls = tk.BooleanVar(value=self.data.smtp_starttls)
        ttk.Checkbutton(
            row, text="Use STARTTLS (port 587). Clear it for implicit TLS (port 465).",
            variable=self._smtp_starttls, style="TCheckbutton",
        ).pack(side="left")

        ttk.Button(
            parent, text="Send a test message", style="Accent.TButton",
            command=self._test_smtp,
        ).pack(anchor="w", pady=(METRICS.space_md, 0))

        self._smtp_output = self._output(parent, height=8)
        self._write(
            self._smtp_output,
            "SMTP NOT CONFIGURED.\n\n"
            "Leave these fields empty to skip email entirely. AETHRA-SEC will "
            "start normally and show notifications in the application.",
        )

    def _collect_smtp(self) -> None:
        self.data.smtp_host = self._smtp_host.get().strip()
        self.data.smtp_port = self._smtp_port.get().strip() or "587"
        self.data.smtp_user = self._smtp_user.get().strip()
        self.data.smtp_password = self._smtp_password.get()
        self.data.smtp_from = self._smtp_from.get().strip()
        self.data.smtp_to = self._smtp_to.get().strip()
        self.data.smtp_starttls = bool(self._smtp_starttls.get())

    def _test_smtp(self) -> None:
        """Send one real message and report exactly what happened."""
        self._collect_smtp()
        settings = self._settings_from_data()
        destination = self.data.smtp_to or self.data.admin_email

        if not settings.smtp.is_configured:
            self._write(
                self._smtp_output,
                "SMTP NOT CONFIGURED - a host and a sender address are needed "
                "before a message can be sent.\n\nNothing was sent.",
            )
            return
        if not destination:
            self._write(
                self._smtp_output,
                "No destination address. Enter a notify address, or an "
                "administrator email in step 1.\n\nNothing was sent.",
            )
            return

        self._write(self._smtp_output, f"Sending to {destination}...")

        def work() -> object:
            from aethra_sec.services.email_service import (
                EmailNotifier,
                test_message_body,
            )

            notifier = EmailNotifier(settings.smtp)
            return notifier.send(
                destination,
                f"{APP_NAME} notification test",
                test_message_body(destination),
            )

        def done(result: object) -> None:
            delivery = result  # type: ignore[assignment]
            if getattr(delivery, "delivered", False):
                self._write(
                    self._smtp_output,
                    f"SENT.\n\n{getattr(delivery, 'detail', '')}\n\n"
                    "The mail server accepted the message. Check the mailbox to "
                    "confirm it arrived - acceptance by a relay is not the same "
                    "as delivery to an inbox.",
                )
            else:
                self._write(
                    self._smtp_output,
                    "NOT SENT.\n\n"
                    f"{getattr(delivery, 'detail', 'The message was not sent.')}\n\n"
                    "The settings are kept so you can correct them. AETHRA-SEC "
                    "still starts and signs in normally without email.",
                )

        self._run_async(
            work, done, lambda message: self._write(self._smtp_output, f"NOT SENT.\n\n{message}")
        )

    # ------------------------------------------------------------------
    # Step 6 - health check
    # ------------------------------------------------------------------
    def _build_health_step(self, parent: ttk.Frame) -> None:
        self._heading(
            parent,
            "Step 6 - System health check",
            "This applies everything: the configuration file is written, the "
            "database is created and migrated, the administrator is created, "
            "and every dependency is re-tested. Each result below comes from a "
            "check that actually ran.",
        )
        self._apply_button = ttk.Button(
            parent, text="Apply configuration and run the health check",
            style="Accent.TButton", command=self._apply_everything,
        )
        self._apply_button.pack(anchor="w")
        self._health_output = self._output(parent, height=18)
        self._write(
            self._health_output,
            "Nothing has been written yet. Nothing on this machine changes "
            "until you select the button above.",
        )

    def _apply_everything(self) -> None:
        """Write the configuration, provision the database, create the admin."""
        self._collect_database()
        self._collect_tools()
        self._collect_smtp()
        self._write(self._health_output, "Applying configuration...")
        self._apply_button.state(["disabled"])

        data = self.data
        values = data.to_config()

        def work() -> object:
            report: list[str] = []

            # 1. Configuration file.
            try:
                written = configfile.write(values)
                report.append(f"Configuration written to {written}")
            except OSError as exc:
                report.append(f"FAILED to write the configuration file: {exc}")
                return ("\n".join(report), None)

            restricted, permission_detail = configfile.permissions_are_restricted(written)
            report.append(
                f"Configuration permissions: {permission_detail}"
                + ("" if restricted else "  (WARNING: readable by other users)")
            )

            # Re-read the settings from the file that was just written, so
            # everything below is exercised against the deployed configuration
            # rather than against what the wizard happens to hold in memory.
            settings = load_settings(written)

            # 2. Database schema.
            provision = provisioning.prepare_database(settings.database)
            report.append("")
            report.append(f"Database: {provision.detail}")
            if provision.preserved_rows:
                kept = ", ".join(
                    f"{name}={count}" for name, count in provision.preserved_rows.items()
                )
                report.append(f"  Existing records kept: {kept}")
            if not provision.ok:
                if provision.remedy:
                    report.append(f"  -> {provision.remedy}")
                return ("\n".join(report), None)

            # 3. Administrator.
            admin = provisioning.create_administrator(
                settings.database,
                data.admin_username,
                data.admin_password,
                data.admin_email,
            )
            report.append("")
            report.append(f"Administrator: {admin.detail}")
            if not admin.ok:
                return ("\n".join(report), None)

            # 4. Health check, from real probes.
            health = run_health_check(
                settings,
                interface_report=data.interface_report,
                selected_interface=data.capture_interface,
            )
            return ("\n".join(report), health)

        def done(result: object) -> None:
            text, health = result  # type: ignore[misc]
            self._apply_button.state(["!disabled"])
            body = [text, ""]
            if health is not None:
                self.data.health = health
                self.data.applied = True
                body.append(health.render())
                # The password is not needed again. Dropping it here keeps it
                # out of the process for the rest of the wizard's life.
                self.data.admin_password = ""
                self.data.admin_confirm = ""
            else:
                body.append(
                    "Setup did not complete. Correct the problem above and "
                    "select the button again - nothing is left half-applied: "
                    "re-running repeats every step safely."
                )
            self._write(self._health_output, "\n".join(body))
            self._refresh_buttons()

        def failed(message: str) -> None:
            self._apply_button.state(["!disabled"])
            self._write(self._health_output, f"Setup failed.\n\n{message}")

        self._run_async(work, done, failed)

    # ------------------------------------------------------------------
    # Step 7 - finish
    # ------------------------------------------------------------------
    def _build_finish_step(self, parent: ttk.Frame) -> None:
        self._heading(parent, "Step 7 - Finish", "")
        self._finish_output = self._output(parent, height=20)

    def _render_finish(self) -> None:
        health = self.data.health
        lines = [
            f"{APP_NAME} {APP_VERSION} is configured.",
            "",
            f"Configuration file : {paths.config_file()}",
            f"Application data   : {paths.data_dir()}",
            f"Logs               : {paths.log_dir()}",
            f"Reports            : {paths.report_dir()}",
            f"Captures           : {paths.capture_dir()}",
            "",
            f"Sign in as         : {self.data.admin_username}",
            "Sign-in method     : username and password (no second factor)",
            "",
        ]
        if health is not None:
            lines.append(health.render())
            lines.append("")
            if health.failures:
                lines.append(
                    "The failures above do not prevent AETHRA-SEC from starting. "
                    "Each affected feature reports itself unavailable on the "
                    "System Health screen rather than showing invented data."
                )
        lines.extend([
            "",
            "Select Finish to close setup and start AETHRA-SEC.",
        ])
        self._write(self._finish_output, "\n".join(lines))

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    def _show_step(self, index: int) -> None:
        for frame in self._step_frames:
            frame.pack_forget()
        self._index = max(0, min(index, len(self._step_frames) - 1))
        self._step_frames[self._index].pack(fill="both", expand=True)
        self._subtitle.configure(
            text=f"Step {self._index + 1} of {len(STEP_TITLES)} - "
                 f"{STEP_TITLES[self._index]}"
        )
        for position, label in enumerate(self._rail_labels):
            label.configure(
                style="CardTitle.TLabel" if position == self._index else "CardDim.TLabel"
            )
        if self._index == 3 and not self._interface_choices:
            self._detect_interfaces()
        if self._index == 6:
            self._render_finish()
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        self._back_button.state(["!disabled"] if self._index > 0 else ["disabled"])
        if self._index == len(STEP_TITLES) - 1:
            self._next_button.configure(text="Finish")
        elif self._index == 5:
            self._next_button.configure(text="Next")
        else:
            self._next_button.configure(text="Next")

        # Step 6 is the gate: the wizard will not advance past it until the
        # configuration has actually been applied, because step 7 describes an
        # installation that would not exist yet.
        if self._index == 5 and not self.data.applied:
            self._next_button.state(["disabled"])
            self._status.configure(
                text="Apply the configuration to continue.",
                foreground=PALETTE.text_dim,
            )
        else:
            self._next_button.state(["!disabled"])
            self._status.configure(text="")

    def _next(self) -> None:
        if self._busy:
            return
        if self._index == 0 and not self._validate_admin():
            return
        if self._index == 1:
            self._collect_database()
        if self._index == 2:
            self._collect_tools()
        if self._index == 4:
            self._collect_smtp()
        if self._index == len(STEP_TITLES) - 1:
            self.completed = True
            self.destroy()
            return
        self._show_step(self._index + 1)

    def _back(self) -> None:
        if not self._busy:
            self._show_step(self._index - 1)

    def _cancel(self) -> None:
        """Close without finishing.

        Cancelling after step 6 leaves a working installation - the
        configuration was already applied, and undoing it would be a
        destructive act the operator did not ask for. Cancelling before it
        leaves the machine untouched.
        """
        self.completed = self.data.applied
        self.destroy()

    # ------------------------------------------------------------------
    # Worker plumbing
    # ------------------------------------------------------------------
    def _settings_from_data(self) -> AppSettings:
        """Build settings from the current answers without writing anything.

        Used by the individual test buttons so a connection or an SMTP attempt
        can be tried before the operator commits to writing a configuration
        file.
        """
        import os

        overrides = {
            key: value for key, value in self.data.to_config().items()
        }
        previous = {key: os.environ.get(key) for key in overrides}
        try:
            os.environ.update(overrides)
            # An explicit non-existent path stops load_settings from reading
            # the deployed file and mixing it with what is on screen.
            return load_settings(Path(os.devnull))
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def _run_async(
        self,
        work: Callable[[], object],
        on_success: Callable[[object], None],
        on_error: Callable[[str], None],
    ) -> None:
        """Run slow work off the Tk thread, returning through the dispatcher."""
        self._busy = True

        def finish(callback: Callable[[], None]) -> None:
            self._busy = False
            callback()

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - reported, never swallowed
                LOGGER.exception("A setup step failed.")
                message = str(exc)
                dispatch.post(lambda: finish(lambda: on_error(message)))
            else:
                dispatch.post(lambda: finish(lambda: on_success(result)))

        threading.Thread(target=runner, name="setup-worker", daemon=True).start()


def run_wizard() -> bool:
    """Show the wizard and return whether setup completed.

    Returns:
        True when the configuration was applied, so the caller may start the
        application. False when the operator cancelled before applying, in
        which case nothing on the machine was changed.
    """
    paths.ensure_data_dirs()
    wizard = SetupWizard()
    wizard.mainloop()
    try:
        dispatch.shutdown()
    except Exception:  # noqa: BLE001
        pass
    return wizard.completed


def setup_is_required() -> bool:
    """True when this installation has not been configured yet.

    Checked on start. Deliberately narrow: it asks whether a configuration file
    naming a database exists, not whether that configuration works. A broken
    configuration belongs on the System Health screen, which explains it -
    re-running the wizard over a deployment because its database was briefly
    down would be a far worse outcome.
    """
    return not configfile.is_configured()
