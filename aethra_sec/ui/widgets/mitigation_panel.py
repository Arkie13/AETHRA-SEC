"""The actionable half of the mitigation screen (§29, §30).

A recommendation used to be rendered as one ``tk.Text`` blob: eight headings
and their prose concatenated into a single scrolling wall. Everything was
present and nothing was findable - the containment steps an operator needs in
the first minute sat below three paragraphs of background, in the same size
and colour as the background.

This renders the same stored fields as distinct sections instead, ordered by
how urgently they are needed: what it is, what to do now, the evidence it was
bound to, the firewall parameters that evidence supports, and the checks that
close it out.

Two rules hold throughout. The knowledge-base text is generic by design and is
shown as written. The *evidence* - addresses, ports, counts, timestamps - is
read from the detections the correlation engine actually bound to this
recommendation, and where there are none the panel says so. It never composes an example address to fill
the firewall card, because a plausible-looking rule is the one mistake that
would get applied to a real network.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Any, Callable

from aethra_sec.ui.theme import METRICS, PALETTE, Fonts, severity_colour
from aethra_sec.ui.widgets.cards import ScrollableFrame

#: Shown wherever the bound evidence genuinely lacks a value.
NOT_AVAILABLE = "Not available"

#: Above this, a port on *this* host is an ephemeral client port - one the
#: operating system allocated for an outbound connection. Traffic arriving at
#: such a port is a reply to something this machine asked for, not an inbound
#: attack, so no firewall rule should be proposed for it. A genuine inbound
#: attack targets a service port below this boundary.
EPHEMERAL_PORT_FLOOR = 1024


@dataclass(frozen=True)
class FirewallProposal:
    """Firewall parameters derived from real evidence, or a refusal."""

    supported: bool
    reason: str = ""
    action: str = ""
    direction: str = ""
    source: str = ""
    destination: str = ""
    protocol: str = ""
    port: str = ""
    scope: str = ""

    @property
    def command(self) -> str:
        """A Windows Defender Firewall command for review - never executed."""
        if not self.supported or not self.source:
            return ""
        name = f"AETHRA-SEC block {self.source}"
        parts = [
            "New-NetFirewallRule",
            f'-DisplayName "{name}"',
            "-Direction Inbound",
            "-Action Block",
            f"-RemoteAddress {self.source}",
        ]
        if self.protocol and self.protocol != NOT_AVAILABLE:
            parts.append(f"-Protocol {self.protocol}")
        if self.port and self.port.isdigit():
            parts.append(f"-LocalPort {self.port}")
        return " ".join(parts)


def build_firewall_proposal(incidents: list[Any]) -> FirewallProposal:
    """Derive firewall parameters from incidents actually bound to an entry.

    Refuses in three situations rather than guessing: no bound evidence at
    all, no source address in that evidence, and evidence whose traffic is a
    response to a connection this host opened. The last is the important one -
    the addresses in a "UDP flood" raised by QUIC return traffic are content
    servers, and a rule blocking them would break browsing while stopping no
    attack.
    """
    if not incidents:
        return FirewallProposal(
            supported=False,
            reason=(
                "No detection has been bound to this recommendation yet, so "
                "there is no evidence to build a rule from."
            ),
        )

    incident = incidents[0]
    source = str(getattr(incident, "src_ip", "") or "")
    destination = str(getattr(incident, "dst_ip", "") or "")
    protocol = str(getattr(incident, "protocol", "") or "")
    port = getattr(incident, "dst_port", None)

    if not source:
        return FirewallProposal(
            supported=False,
            reason=(
                "The bound evidence records no source address, so a specific "
                "rule cannot be proposed."
            ),
        )

    # The protected host appearing as the *source* means the traffic went
    # outward from this machine. Proposing to block that address would block
    # the monitored host itself - the single most damaging rule this panel
    # could suggest, and one that looks entirely plausible in the card.
    protected = str(getattr(incident, "affected_host_ip", "") or "")
    if protected and protected == source:
        return FirewallProposal(
            supported=False,
            reason=(
                f"The evidence records {source} as the source, which is the "
                "monitored host itself - this traffic left this machine rather "
                "than arriving at it. Blocking that address would cut off the "
                "host you are protecting. Investigate what on this host "
                "generated the traffic instead."
            ),
        )

    # A private source talking to a public destination is outbound traffic
    # from inside this network. The remote party is then the *destination*,
    # not the source, so blocking the source would block a local asset. The
    # affected-host check above catches this when the incident recorded one;
    # this catches it from the addresses themselves when it did not.
    if _is_private(source) and _is_public(destination):
        return FirewallProposal(
            supported=False,
            reason=(
                f"The evidence shows {source} (a local address) connecting out "
                f"to {destination}. The source here is an asset on this "
                "network, so an inbound block on it would restrict your own "
                "host rather than a remote party. Investigate what generated "
                "the outbound traffic instead."
            ),
        )

    # The destination port is on this host. An ephemeral one means the
    # operating system opened it for an outbound connection, so the traffic
    # is a reply - the "attacker" is a server this machine chose to talk to.
    # Proposing a block there would break ordinary browsing and stop no
    # attack, which is precisely the mistake worth refusing to make.
    try:
        destination_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        destination_port = None
    if destination_port is not None and destination_port >= EPHEMERAL_PORT_FLOOR:
        return FirewallProposal(
            supported=False,
            reason=(
                f"The evidence shows traffic arriving at {destination or 'this host'}"
                f":{destination_port}, an ephemeral port this host opened for an "
                "outbound connection - so this is reply traffic from a server "
                "it contacted, not an inbound attack. Blocking "
                f"{source} would break ordinary traffic without stopping "
                "anything. Review the detection rule rather than the firewall."
            ),
        )

    return FirewallProposal(
        supported=True,
        action="BLOCK",
        direction="INBOUND",
        source=source,
        destination=destination or NOT_AVAILABLE,
        protocol=protocol or NOT_AVAILABLE,
        port=str(port) if port else NOT_AVAILABLE,
        scope="Single host",
    )


class MitigationPanel(ScrollableFrame):
    """Structured, actionable rendering of one recommendation."""

    #: The checks an operator ticks off after acting. Local to the session -
    #: nothing here is written back as a security record.
    VERIFICATION = (
        "Firewall or control change reviewed by a second person",
        "Traffic from the source has returned to baseline",
        "Affected service confirmed available to legitimate users",
        "New events reviewed for recurrence",
        "Related alerts reviewed and marked in IDS Alerts",
    )

    def __init__(
        self,
        parent: tk.Misc,
        *,
        fonts: Fonts | None = None,
        on_copy: Callable[[str, str], None] | None = None,
    ) -> None:
        """Create an empty panel; call :meth:`show` to fill it."""
        super().__init__(parent, padding=(METRICS.space_lg, METRICS.space_md))
        self._fonts = fonts
        self._on_copy = on_copy
        self._checks: list[tk.BooleanVar] = []
        self._entry: Any = None
        self._incidents: list[Any] = []
        self.interior.bind("<Configure>", self._reflow, add="+")
        self._empty()

    # ------------------------------------------------------------------
    # Text wrapping
    #
    # Tk labels do not wrap to their container - ``wraplength`` is a frozen
    # pixel count. A fixed constant therefore clips the moment the panel is
    # narrower than the guess, which is exactly what the master/detail split
    # does at smaller window sizes. So the wrap width is derived from the real
    # panel width on every resize, minus how far the label is indented.
    # ------------------------------------------------------------------
    #: Breathing room kept clear at the right edge, in pixels.
    WRAP_GUTTER = 18
    #: Never wrap narrower than this, or deep indentation makes text unreadable.
    MIN_WRAP = 180

    def _indent_of(self, widget: tk.Misc) -> int:
        """How far ``widget`` sits from the left edge of the panel interior."""
        offset = 0
        node: tk.Misc | None = widget
        while node is not None and node is not self.interior:
            offset += node.winfo_x()
            node = node.master
        return offset

    def _wrapping_labels(self, parent: tk.Misc | None = None) -> list[ttk.Label]:
        """Every label that asked to wrap, at any depth."""
        found: list[ttk.Label] = []
        for child in (parent or self.interior).winfo_children():
            if isinstance(child, ttk.Label):
                try:
                    if int(child.cget("wraplength")) > 0:
                        found.append(child)
                except (TypeError, ValueError, tk.TclError):
                    pass
            found.extend(self._wrapping_labels(child))
        return found

    def _reflow(self, _event: tk.Event | None = None) -> None:
        """Re-wrap every label to the panel's current width."""
        try:
            width = self.interior.winfo_width()
        except tk.TclError:
            return
        if width <= 1:
            return
        for label in self._wrapping_labels():
            try:
                available = width - self._indent_of(label) - self.WRAP_GUTTER
                label.configure(wraplength=max(self.MIN_WRAP, available))
            except tk.TclError:
                continue

    # ------------------------------------------------------------------
    def _clear(self) -> None:
        """Remove the previous recommendation's widgets."""
        for child in self.interior.winfo_children():
            child.destroy()
        self._checks.clear()

    def _empty(self, message: str = "Select a recommendation from the playbook.") -> None:
        """Resting state."""
        self._clear()
        ttk.Label(
            self.interior, text=message, style="CardMuted.TLabel",
            wraplength=520, justify="left",
        ).pack(anchor="w", pady=(METRICS.space_lg, 0))
        self.after_idle(self._reflow)

    # ------------------------------------------------------------------
    def show(self, entry: Any, incidents: list[Any]) -> None:
        """Render one recommendation and the real evidence bound to it."""
        self._entry = entry
        self._incidents = incidents or []
        self._clear()
        if entry is None:
            self._empty()
            return

        self._render_header(entry)
        self._section("Why this matters", entry.why_it_matters)
        self._render_actions(entry)
        self._render_evidence(self._incidents)
        self._render_firewall(build_firewall_proposal(self._incidents))
        self._render_verification(entry)
        # Widths are only real after layout runs, so wrap on the next idle.
        self.after_idle(self._reflow)
        self._section("Long-term action", entry.long_term_action)
        if entry.references:
            self._section("References", entry.references)

        ttk.Label(
            self.interior,
            text=(
                "AETHRA-SEC recommends only. It never applies a firewall rule, "
                "blocks an address or stops a service - apply changes through "
                "your normal change-control process."
            ),
            style="CardDim.TLabel", wraplength=560, justify="left",
        ).pack(anchor="w", pady=(METRICS.space_lg, METRICS.space_md))

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------
    def _heading(self, text: str) -> None:
        """A section label, consistent with the rest of the console."""
        ttk.Label(
            self.interior, text=text.upper(), style="CardTitle.TLabel"
        ).pack(anchor="w", pady=(METRICS.space_lg, METRICS.space_xs))

    def _section(self, title: str, body: str) -> None:
        """A titled block of the knowledge base's own prose."""
        if not body:
            return
        self._heading(title)
        ttk.Label(
            self.interior, text=body.strip(), style="Card.TLabel",
            wraplength=560, justify="left",
        ).pack(anchor="w")

    def _render_header(self, entry: Any) -> None:
        """Severity, threat and the facts that classify it."""
        colour = severity_colour(str(entry.severity))
        head = ttk.Frame(self.interior, style="Card.TFrame")
        head.pack(fill="x")

        band = ttk.Frame(head, style="Card.TFrame")
        band.pack(fill="x")
        tk.Frame(band, background=colour, width=3, height=16).pack(
            side="left", padx=(0, METRICS.space_sm)
        )
        ttk.Label(
            band, text=str(entry.severity).upper(), style="CardTitle.TLabel",
            foreground=colour,
        ).pack(side="left")
        ttk.Label(band, text=entry.code, style="CardDim.TLabel").pack(
            side="left", padx=(METRICS.space_sm, 0)
        )

        ttk.Label(
            self.interior, text=entry.threat_name, style="Heading.TLabel",
            wraplength=560, justify="left",
        ).pack(anchor="w", pady=(METRICS.space_xs, METRICS.space_sm))

        facts = ttk.Frame(self.interior, style="Card.TFrame")
        facts.pack(fill="x")
        source = (
            entry.detection_source.label if entry.detection_source else "any source"
        )
        for label, value in (
            ("Category", entry.category.label),
            ("Detection source", source),
            ("Applies to", entry.applies_to_service or "any service"),
            ("Status", entry.status_text + (" · built-in" if entry.is_builtin else "")),
        ):
            row = ttk.Frame(facts, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(
                row, text=label, style="CardDim.TLabel", width=18, anchor="w"
            ).pack(side="left")
            ttk.Label(
                row, text=value, style="Card.TLabel", wraplength=380,
                justify="left",
            ).pack(side="left")

        if entry.explanation:
            ttk.Label(
                self.interior, text=entry.explanation.strip(),
                style="CardMuted.TLabel", wraplength=560, justify="left",
            ).pack(anchor="w", pady=(METRICS.space_sm, 0))

    def _render_actions(self, entry: Any) -> None:
        """The containment steps, numbered and given the most prominence."""
        steps = _split_steps(entry.immediate_action)
        self._heading("Immediate action")
        if not steps:
            ttk.Label(
                self.interior, text="No immediate action is recorded for this entry.",
                style="CardMuted.TLabel", wraplength=560, justify="left",
            ).pack(anchor="w")
            return
        for index, step in enumerate(steps, start=1):
            row = ttk.Frame(self.interior, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(
                row, text=f"{index:02d}", style="CardTitle.TLabel",
                foreground=PALETTE.accent, width=4, anchor="w",
            ).pack(side="left")
            ttk.Label(
                row, text=step, style="Card.TLabel", wraplength=520,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

    def _render_evidence(self, incidents: list[Any]) -> None:
        """Real stored evidence, or an honest statement that there is none."""
        self._heading("Evidence")
        if not incidents:
            ttk.Label(
                self.interior,
                text=(
                    "Evidence unavailable for this recommendation: no detection "
                    "has been bound to it. The guidance above is the generic "
                    "knowledge-base entry."
                ),
                style="CardMuted.TLabel", wraplength=560, justify="left",
            ).pack(anchor="w")
            return

        incident = incidents[0]
        ttk.Label(
            self.interior,
            text=(
                f"From {len(incidents)} correlated detection group(s). "
                "Most recent shown below; the individual alerts are in "
                "IDS Alerts."
            ),
            style="CardDim.TLabel", wraplength=560, justify="left",
        ).pack(anchor="w", pady=(0, METRICS.space_xs))

        for label, value in (
            ("Source", getattr(incident, "src_ip", "")),
            ("Source port", getattr(incident, "src_port", None)),
            ("Destination", getattr(incident, "dst_ip", "")),
            ("Destination port", getattr(incident, "dst_port", None)),
            ("Protocol", getattr(incident, "protocol", "")),
            ("Events", getattr(incident, "event_count", None)),
            ("First seen", getattr(incident, "first_seen", None)),
            ("Last seen", getattr(incident, "last_seen", None)),
        ):
            row = ttk.Frame(self.interior, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(
                row, text=label, style="CardDim.TLabel", width=18, anchor="w"
            ).pack(side="left")
            ttk.Label(
                row, text=_present(value), style="Card.TLabel",
                wraplength=380, justify="left",
            ).pack(side="left")


    def _render_firewall(self, proposal: FirewallProposal) -> None:
        """Firewall parameters, or the reason none can be proposed."""
        self._heading("Firewall recommendation")
        if not proposal.supported:
            ttk.Label(
                self.interior, text=proposal.reason, style="CardMuted.TLabel",
                wraplength=560, justify="left",
            ).pack(anchor="w")
            return

        for label, value in (
            ("Action", proposal.action),
            ("Direction", proposal.direction),
            ("Source", proposal.source),
            ("Destination", proposal.destination),
            ("Protocol", proposal.protocol),
            ("Port", proposal.port),
            ("Scope", proposal.scope),
        ):
            row = ttk.Frame(self.interior, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(
                row, text=label, style="CardDim.TLabel", width=18, anchor="w"
            ).pack(side="left")
            ttk.Label(row, text=value, style="Card.TLabel").pack(side="left")

        command = proposal.command
        if not command:
            return
        ttk.Label(
            self.interior,
            text="Windows Defender Firewall - review before applying:",
            style="CardDim.TLabel", wraplength=560, justify="left",
        ).pack(anchor="w", pady=(METRICS.space_sm, 2))
        box = tk.Text(self.interior, height=3, wrap="word")
        if self._fonts:
            from aethra_sec.ui.theme import configure_text_widget

            configure_text_widget(box, self._fonts, mono=True)
        box.insert("1.0", command)
        box.configure(state="disabled")
        box.pack(fill="x")

        actions = ttk.Frame(self.interior, style="Card.TFrame")
        actions.pack(fill="x", pady=(METRICS.space_sm, 0))
        if self._on_copy is not None:
            ttk.Button(
                actions, text="Copy command", style="Ghost.TButton",
                command=lambda: self._on_copy("Firewall command", command),
            ).pack(side="left")
            ttk.Button(
                actions, text="Copy parameters", style="Ghost.TButton",
                command=lambda: self._on_copy(
                    "Firewall parameters",
                    "\n".join(
                        f"{k}: {v}" for k, v in (
                            ("Action", proposal.action),
                            ("Direction", proposal.direction),
                            ("Source", proposal.source),
                            ("Destination", proposal.destination),
                            ("Protocol", proposal.protocol),
                            ("Port", proposal.port),
                        )
                    ),
                ),
            ).pack(side="left", padx=(METRICS.space_sm, 0))

    def _render_verification(self, entry: Any) -> None:
        """The close-out checklist, as real checkboxes."""
        self._heading("Verification")
        recorded = _split_steps(entry.verification_steps)
        for text in (recorded or list(self.VERIFICATION)):
            variable = tk.BooleanVar(value=False)
            self._checks.append(variable)
            ttk.Checkbutton(
                self.interior, text=text, variable=variable,
                style="Toolbar.TCheckbutton",
            ).pack(anchor="w", pady=1)


def _is_private(address: str) -> bool:
    """True for an RFC1918/loopback/link-local address."""
    try:
        import ipaddress

        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def _is_public(address: str) -> bool:
    """True for a routable address on the public internet."""
    try:
        import ipaddress

        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        parsed.is_private or parsed.is_loopback or parsed.is_link_local
        or parsed.is_multicast or parsed.is_reserved
    )


def _present(value: Any) -> str:
    """Render a stored value, or say plainly that the record lacks one."""
    if value is None or value == "" or value == 0:
        return NOT_AVAILABLE if value is None or value == "" else str(value)
    return str(value)


def _split_steps(text: str) -> list[str]:
    """Split stored guidance into steps without inventing any.

    The knowledge base stores these as prose - numbered lines, or one line per
    step. Both are split on line breaks; nothing is added, reordered or
    rephrased.
    """
    if not text:
        return []
    steps: list[str] = []
    for raw in str(text).replace("\\r", "").split("\n"):
        line = raw.strip()
        if not line:
            continue
        while line and (line[0].isdigit() or line[0] in ".)-•"):
            line = line[1:].lstrip(".) -")
            if not line[:1].isdigit():
                break
        if line:
            steps.append(line)
    return steps
