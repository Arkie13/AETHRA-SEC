"""About and Help screens (§53, §117, §118).

The Help screen is deliberately educational: AETHRA-SEC is built for a Network
Security teaching laboratory, so it explains what each detection means, how the
risk levels are derived, and what an open port does and does not imply (§86).
"""

from __future__ import annotations

import platform
import sys
import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.analytics.anomaly_rules import RULE_DEFINITIONS
from aethra_sec.analytics.risk_engine import (
    SCORE_HIGH,
    SCORE_LOW,
    SCORE_MEDIUM,
)
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.ui.widgets import Card, ScrollableFrame
from aethra_sec.version import (
    APP_FULL_NAME,
    APP_NAME,
    APP_PURPOSE,
    APP_VERSION,
    AUTHORIZED_USE_NOTICE,
    EDUCATIONAL_USE_NOTICE,
    SCHEMA_VERSION,
    TECHNOLOGY_STACK,
)


class AboutScreen(Screen):
    """Product identity, technology stack and use notices (§117)."""

    title = "About AETHRA-SEC"
    subtitle = "System identity, technology stack and conditions of use"

    def build(self) -> None:
        """Construct the about page."""
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        identity = Card(root, "System", fonts=self.fonts, padding=16)
        identity.pack(fill="x")
        ttk.Label(identity, text=APP_NAME, style="CardHeading.TLabel",
                  font=self.fonts.title).pack(anchor="w")
        ttk.Label(
            identity, text=APP_FULL_NAME, style="CardMuted.TLabel",
            wraplength=980, justify="left",
        ).pack(anchor="w", pady=(4, 12))
        for label, value in (
            ("Version", APP_VERSION),
            ("Database schema version", str(SCHEMA_VERSION)),
            ("Python", platform.python_version()),
            ("Platform", f"{platform.system()} {platform.release()}"),
            ("Interpreter", sys.executable),
        ):
            row = ttk.Frame(identity, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=label, style="CardDim.TLabel", width=26,
                      anchor="w").pack(side="left")
            ttk.Label(row, text=value, style="Card.TLabel").pack(side="left")

        purpose = Card(root, "Purpose", fonts=self.fonts, padding=16)
        purpose.pack(fill="x", pady=(10, 0))
        ttk.Label(
            purpose, text=APP_PURPOSE, style="Card.TLabel", wraplength=980,
            justify="left",
        ).pack(anchor="w")

        stack = Card(root, "Technology stack", fonts=self.fonts, padding=16)
        stack.pack(fill="x", pady=(10, 0))
        for item in TECHNOLOGY_STACK:
            row = ttk.Frame(stack, style="Card.TFrame")
            row.pack(anchor="w", fill="x", pady=1)
            tk.Frame(row, background=PALETTE.accent, width=3, height=13).pack(
                side="left", padx=(0, 8)
            )
            ttk.Label(row, text=item, style="Card.TLabel").pack(side="left")

        notices = Card(root, "Conditions of use", fonts=self.fonts, padding=16)
        notices.pack(fill="x", pady=(10, 0))
        for text, style in (
            (AUTHORIZED_USE_NOTICE, "Critical.TLabel"),
            (EDUCATIONAL_USE_NOTICE, "CardMuted.TLabel"),
        ):
            ttk.Label(
                notices, text=text, style=style, wraplength=980, justify="left"
            ).pack(anchor="w", pady=(0, 8))

        boundaries = Card(root, "What AETHRA-SEC does not do", fonts=self.fonts, padding=16)
        boundaries.pack(fill="x", pady=(10, 0))
        for line in (
            "It does not exploit discovered vulnerabilities - Nmap is used for "
            "discovery, port state, service/version and OS detection only.",
            "It does not perform credential attacks or destructive testing.",
            "It does not apply mitigations. No firewall rule is changed, no "
            "address is blocked, no service is stopped and no account is locked. "
            "Mitigation output is advisory.",
            "It does not scan targets outside the configured authorised "
            "networks; such requests are refused and audited.",
            "It does not fabricate data. Every packet, alert, finding and "
            "metric originates from Nmap, PyShark/TShark, Snort, or a "
            "deterministic rule applied to those records. Where there is no "
            "data, the interface says so.",
        ):
            ttk.Label(
                boundaries, text=f"•  {line}", style="CardMuted.TLabel",
                wraplength=960, justify="left",
            ).pack(anchor="w", pady=2)


class HelpScreen(Screen):
    """Educational help for every subsystem (§53, §86, §118)."""

    title = "Help"
    subtitle = "What each screen shows, how detections are made, and what they mean"

    def build(self) -> None:
        """Construct the help page."""
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        for label, content in (
            ("Getting started", self._getting_started()),
            ("Accounts & access", self._accounts()),
            ("Monitoring", self._monitoring()),
            ("Assessment", self._assessment()),
            ("Detection rules", self._detection_rules()),
            ("Risk & correlation", self._risk()),
            ("Mitigation & reports", self._mitigation()),
            ("Common errors", self._errors()),
        ):
            frame = ttk.Frame(notebook, style="TFrame", padding=10)
            notebook.add(frame, text=label)
            text = tk.Text(frame, wrap="word")
            configure_text_widget(text, self.fonts)
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            text.insert("1.0", content)
            text.configure(state="disabled")
            text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    # Content
    # ------------------------------------------------------------------
    @staticmethod
    def _getting_started() -> str:
        """First-run guidance."""
        return """GETTING STARTED

AETHRA-SEC brings three tools into one workflow: Nmap for assessment, PyShark
(TShark/Wireshark) for live traffic analysis, and Snort for intrusion
detection. It then correlates what they independently observed.

A NEW INSTALLATION SHOWS ZEROS. That is correct, not a fault: the system has
not observed anything yet. Populate it in this order.

1. SYSTEM HEALTH
   Open System Health and run diagnostics. Fix anything marked FAIL before
   going further; WARNING items are usually optional features.

2. START PACKET CAPTURE
   Network Monitoring > choose an interface > Start capture. Only traffic that
   physically reaches the monitoring interface can be captured. On a switched
   network you will otherwise see only this machine's own traffic plus
   broadcasts - connect the interface to a mirror/SPAN port to observe traffic
   between other hosts.

3. RUN AN AUTHORISED ASSESSMENT
   Vulnerability Assessment > enter a target inside your authorised networks >
   choose a profile > Start scan. The authorised networks are shown on that
   screen; targets outside them are refused and the refusal is audited.

4. CONNECT SNORT (optional but recommended)
   AETHRA-SEC does not start Snort. Run the sensor separately and point
   AETHRA_SNORT_TRANSPORT at its alert output - see docs/SNORT_INTEGRATION.md.
   Until then the interface reports "Snort unavailable", which is the truth.

5. REVIEW ALERTS
   Detected threats appear on IDS Alerts, from Snort and from AETHRA-SEC's own
   traffic rules. Open an alert to read its full evidence and the mitigation
   guidance mapped to it, then mark it reviewed, acknowledge or escalate it,
   and record whether it was a true or false positive.
"""

    @staticmethod
    def _accounts() -> str:
        """Roles, registration and password recovery."""
        return """ACCOUNTS AND ACCESS

TWO ROLES
  USER (analyst)  Dashboard, live monitoring, authorised assessments, hosts,
                  alerts, mitigation guidance, reports and system
                  health. Enough to run a shift.
  ADMIN           Everything a USER can do, plus accounts, password recovery,
                  settings, the audit trail, detection classification and
                  mitigation knowledge.

Permissions are decided when you sign in and re-checked by the service layer on
every action. A control the interface hides is a control the backend would
refuse anyway - the hiding is a convenience, not the security. If your role
changes, your sessions end, because the old session still carries the old
permissions.

GETTING AN ACCOUNT
Only an administrator creates accounts: Users > Accounts > Create account. They
choose the role and either set the first password or have one generated. It is
shown to them once and handed to you; you are normally required to change it at
first sign-in, so that in the end only you know it.

IF YOU FORGET YOUR PASSWORD
Nothing here resets a password automatically, and there is no self-service
reset. The path runs through a person.

1. On the sign-in screen choose "Forgot password?" and enter your username.
   Saying why, and how you can be reached, is what makes the request easy to
   act on. Your password does not change at this point.
2. The screen answers the same way whether or not the username was right. That
   is deliberate: the form must not be usable to discover which accounts exist.
3. An administrator confirms who you are - in person, by phone, through your
   manager - and approves the request. That gives them a one-time code, which
   they pass to you.
4. Back at the sign-in screen choose "I have a recovery code", enter your
   username, the code and the password you want. Nobody else ever learns it.

The code works once, for your account only, and expires in about an hour.
Hyphens, spaces and capitals in it do not matter. Five wrong attempts revoke it -
ask for a new request rather than guessing.

FOR ADMINISTRATORS REVIEWING REQUESTS
Users > Password recovery lists what is waiting; the sidebar badge counts it.
The queue tells you what someone typed into a form - it is not identification.
Confirm who is asking away from the console, then approve and record how you
confirmed it. That note is audited with your name. If anything looks wrong,
reject: any code already issued stops working immediately and the account keeps
the password it had.

Where you would rather simply hand someone a new password - onboarding, or an
account whose owner has left - use Reset password on the Accounts tab instead.
"""

    @staticmethod
    def _monitoring() -> str:
        """Traffic monitoring guidance."""
        return """NETWORK MONITORING

WHAT YOU ARE SEEING
Packets decoded by TShark through PyShark, on the interface you selected.
Fields a packet does not carry are shown as '-': an ARP frame has no ports,
an ICMP packet has no TCP flags. Nothing is substituted.

CAPTURE COUNTERS
  captured    - packets TShark delivered to AETHRA-SEC.
  dropped     - packets discarded because the processing queue was full. The
                queue is deliberately bounded so a busy network cannot exhaust
                memory; dropping and telling you is better than crashing.
  stored      - packet metadata rows written to MySQL.
  not stored  - packets analysed and counted, but not written as rows because
                the per-minute storage cap was reached. Traffic aggregates
                still count them, so the statistics stay accurate.

PAUSE DISPLAY vs STOP CAPTURE
  Pause display freezes the table; capture, analysis and detection continue.
  Stop capture stops everything.

FILTERS - TWO KINDS, NEVER CONFUSED
  CAPTURE FILTER (BPF), in the capture strip: applied by dumpcap before a
  packet is captured, so excluded traffic is never recorded, analysed or
  stored. Changing it restarts capture. Example: tcp port 80
  DISPLAY FILTER, above the packet table: applied to packets already
  captured. It never restarts capture and never changes what is analysed or
  stored. CAPTURED keeps counting; DISPLAYED says how many packets match.
    Presets     All Traffic, Incoming, Outgoing, Transit; HTTP, HTTPS/TLS,
                Sites, TCP, UDP, ICMP, DNS, ARP. A direction and a
                protocol combine. Pressing the active protocol again clears it.
    IP, Port    searched against captured packets as source, destination or
                either. Searching for an address never creates a host.
    Expression  Wireshark-style: http, tls, dns || icmp, !arp,
                ip.addr == <address>, tcp.port == 443,
                http.host contains "name", direction == incoming.
                An invalid expression is refused with the reason, and the
                previous filter stays active.

DIRECTION
  Decided from the capture interface's own addresses, never from ports.
  Incoming  - to an address of this interface.
  Outgoing  - from an address of this interface.
  Transit   - between two other devices. A switched or wireless network only
              delivers that here through a mirror (SPAN) port, a network TAP,
              or with AETHRA-SEC in the traffic path.
  Broadcast - broadcast or multicast from other devices, which every station
              on the segment receives.
  Unknown   - the interface's addresses could not be read.

HTTP AND HTTPS
  HTTP is identified by TShark's HTTP decode, not by port 80. HTTPS/TLS is
  identified by TShark's TLS decode, not by port 443. HTTPS is encrypted:
  AETHRA-SEC shows the TLS and network metadata it can see - server name,
  handshake, versions - and never claims to see the HTTP inside it.

STORAGE
  Per-packet metadata is kept for a short, configurable window; interval
  aggregates are kept far longer. That is what makes long-range traffic charts
  possible without storing every packet forever.
"""

    @staticmethod
    def _assessment() -> str:
        """Assessment guidance, including the open-port distinction."""
        return """VULNERABILITY ASSESSMENT

AN OPEN PORT IS NOT AUTOMATICALLY A VULNERABILITY.
It indicates an exposed network service. The questions that matter are:
is the service required, is it reachable only from the networks that need it,
is it configured safely, and is it patched?

AETHRA-SEC therefore separates two things:
  OBSERVATION      - what Nmap reported, for example "3306/tcp is open,
                     identified as mysql".
  SECURITY FINDING - a concern derived from that observation by a documented
                     rule, with an explicit statement of why the risk level was
                     assigned.

VULNERABILITY REFERENCES
Where a configured vulnerability source matches a service - the administrator's
knowledge base, or a real NSE script that printed identifiers - the finding
cites it. Where none matched, the finding says:

  "Potential exposure identified; further vulnerability verification required."

AETHRA-SEC never invents a CVE identifier.

SCAN PROFILES
Profiles are a fixed catalogue. Your input reaches Nmap only as a strictly
validated port specification and a timing template; everything else is a
constant. Profiles needing raw sockets (SYN, OS detection, UDP) appear only
when the process is elevated.

AUTHORISATION
Targets outside the configured authorised networks are refused before Nmap is
invoked, and the refusal is recorded in the audit trail. Hostnames are resolved
first, so the decision is made on the address that would actually be contacted.
"""

    @staticmethod
    def _detection_rules() -> str:
        """Explain each deterministic rule from its own definition."""
        lines = [
            "DETERMINISTIC DETECTION RULES",
            "",
            "These rules run over live PyShark observations. Each one compares a",
            "measured value against a configurable threshold over a configurable",
            "window, and records all three - so any detection can be audited",
            "rather than taken on trust. There is no machine learning here.",
            "",
            "Thresholds are edited on Settings > Tunable settings (category",
            "'detection') and take effect immediately.",
            "",
        ]
        for rule in RULE_DEFINITIONS:
            lines.extend(
                [
                    f"{rule.rule_id} - {rule.title}",
                    f"  Category      : {rule.category.label}",
                    f"  Base severity : {rule.base_severity}",
                    f"  How it works  : {rule.description}",
                    f"  Threshold key : {rule.threshold_setting}",
                    f"  Window key    : {rule.window_setting}",
                    f"  Why it matters: {rule.why_it_matters}",
                    f"  What to check : {rule.what_to_check}",
                    "",
                ]
            )
        lines.extend(
            [
                "WORDING",
                "  Rule output describes behaviour, not proven attacks: 'Port",
                "  scanning behaviour detected', 'Potential TCP SYN flood',",
                "  'Traffic anomaly'. Confirming an attack needs analyst review.",
                "",
                "FALSE-POSITIVE CONTROL",
                "  Repeat detections inside the suppression window are folded",
                "  into the existing record with an occurrence count instead of",
                "  creating new noise.",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _risk() -> str:
        """Explain risk scoring and correlation."""
        return f"""RISK SCORING AND CORRELATION

SEVERITY IS CALCULATED, NOT GUESSED
Alert severity comes from the sensor: a Snort alert's own priority, mapped
onto HIGH / MEDIUM / LOW, and for AETHRA-SEC's flood rules the manuscript's
packet-rate bands. Open an alert on IDS Alerts to see the priority it arrived
with and the raw alert text it was mapped from.

Behind the scenes a correlation engine still groups related detections, scores
each group from named factors, and binds it to mitigation guidance. That is
what supplies the evidence and the firewall parameters on the Mitigation
screen.

Score bands:
  {SCORE_HIGH:>3}+  HIGH
  {SCORE_MEDIUM:>3}+  MEDIUM
  {SCORE_LOW:>3}+  LOW
   below  INFO

Contributing factors include the threat category, the Snort priority, how many
independent subsystems reported supporting evidence, whether an assessment
confirmed the targeted service is actually reachable, how sensitive the
affected service is, how much evidence accumulated, and whether the source or
destination is a registered trusted asset.

CONFIDENCE
Confidence reflects evidence breadth: a single traffic anomaly is a weak
signal; the same pattern plus a Snort alert plus a confirmed exposure is a
strong one.

CORRELATION
Related evidence is grouped using a category-aware key. Rate
based categories group by source and destination; scan and sweep categories
group by source and destination host, because the varying ports are the
pattern. New evidence inside the correlation window joins the existing group
rather than starting a new one.

EVIDENCE PROVENANCE
Every alert records which engine raised it - Snort, or AETHRA-SEC's own
traffic rules - in its "Detected by" column. AETHRA-SEC never implies that one
subsystem confirmed something only another observed.

TRUSTED ASSETS
Marking a host as trusted does not suppress detection. It lowers the score
slightly and records the trust in the evidence, so an analyst can weigh it.
"""

    @staticmethod
    def _mitigation() -> str:
        """Explain mitigation and reporting."""
        return """MITIGATION AND REPORTING

MITIGATION IS ADVICE, NEVER ACTION
When a threat is detected, AETHRA-SEC selects the best-matching entry from the
mitigation knowledge base and binds it to the real evidence that triggered the
detection. It does not block addresses, change firewall rules, stop services or
lock accounts. You read the guidance and decide.

Each recommendation carries: what was observed, why it matters, the evidence,
an immediate action, a long-term action, and verification steps.

Administrators maintain the knowledge base on the Mitigation screen. Entries
are deactivated rather than deleted, so detections that already cite an entry
keep their guidance.

REPORTS
Reports are built from stored records only. Preview a report before exporting
to see exactly how many records each section covers - a section with no rows
says "No records available", it is not padded.

Every generated report records who produced it, when, over what period, and the
row count of each section, so a report can be audited later.

Formats: PDF (presentation), Excel (one sheet per section), CSV (single file).

AUDIT TRAIL
Security-relevant actions are written to an append-only audit trail whose
records are chained with SHA-256 hashes. Logs > Verify integrity recomputes the
chain and reports any record that was changed, removed or re-ordered. A failed
verification is reported as LOG INTEGRITY WARNING and is never silently
corrected.
"""

    @staticmethod
    def _errors() -> str:
        """Troubleshooting guidance."""
        return """COMMON ERRORS AND WHAT THEY MEAN

"DATABASE OFFLINE"
  MySQL could not be reached. Check the service is running and that the
  AETHRA_DB_* values in .env are correct. AETHRA-SEC keeps running and reports
  the outage rather than pretending to work.

"Nmap is not available"
  The nmap executable was not found or could not run. Install Nmap and, if it
  is in an unusual location, set AETHRA_NMAP_PATH in .env.

"TShark ... is not available"
  Install Wireshark including TShark. On Windows also install Npcap, which
  provides the capture driver.

"Permission denied opening <interface>"
  Capture needs privileges. On Windows run AETHRA-SEC as Administrator with
  Npcap installed; on Linux run as root or grant capabilities:
      sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)

"Snort unavailable"
  No alert transport is configured, or the configured one could not start. The
  message names the transport and the exact reason. AETHRA-SEC never starts
  Snort itself - run the sensor separately. See docs/SNORT_INTEGRATION.md.

"Assessment refused ... outside the authorised networks"
  The target is outside AETHRA_AUTHORIZED_NETWORKS. Widen that setting only if
  you are genuinely authorised to assess the additional range.

"This scan profile requires raw-socket privileges"
  Choose a TCP connect profile such as 'Standard scan', or restart elevated.

"LOG INTEGRITY WARNING"
  One or more audit records fail their hash check. Investigate who had direct
  database access. Note that an administrator pruning old audit records also
  truncates the chain prefix, which is reported the same way on the oldest
  surviving record.

Packets dropped, or "not row-stored (rate cap)"
  The pipeline is shedding load deliberately. Increase capture.queue_size or
  capture.max_packet_rows_per_minute on the Settings screen if the hardware can
  sustain it, or apply a BPF capture filter to reduce the volume at source.
"""
