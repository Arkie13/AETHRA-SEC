"""Nmap assessment models (§16-§20, §45).

An important distinction is encoded here (§19): a **port observation** is not a
vulnerability. ``PortResult`` records what Nmap saw; ``ScanFinding`` records a
security *concern* derived from that observation by a documented rule, and
always states why the risk level was assigned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import ScanTrigger, EvidenceSource, HostStatus, RiskLevel, ScanStatus


@dataclass
class PortResult:
    """One port exactly as Nmap reported it."""

    id: int | None = None
    scan_host_id: int | None = None
    port: int = 0
    protocol: str = "tcp"
    state: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    reason: str = ""
    tunnel: str = ""

    @property
    def is_open(self) -> bool:
        """True when Nmap reported the port as open (not filtered/closed)."""
        return self.state.lower() == "open"

    @property
    def service_text(self) -> str:
        """Service, product and version combined for display."""
        parts = [p for p in (self.service, self.product, self.version) if p]
        return " ".join(parts) if parts else "-"

    @property
    def endpoint(self) -> str:
        """``443/tcp`` style label."""
        return f"{self.port}/{self.protocol}"


@dataclass
class ScanFinding:
    """A security concern derived from real scan output.

    Attributes:
        title: short description of the concern.
        observation: the factual thing Nmap reported.
        concern: why that observation may matter.
        risk_level: classification produced by the risk engine.
        risk_rationale: the explicit reason the level was assigned (§20).
        evidence: the raw data supporting the finding.
        reference: CVE/knowledge-base identifier *only* when a configured
            source supplied one. Empty otherwise - AETHRA-SEC never invents
            CVE identifiers (§19).
        verification_required: true when no vulnerability source confirmed the
            concern, which the UI renders as "further vulnerability
            verification required".
    """

    id: int | None = None
    scan_id: int | None = None
    scan_host_id: int | None = None
    host_id: int | None = None
    ip_address: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""
    title: str = ""
    observation: str = ""
    concern: str = ""
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    risk_rationale: str = ""
    evidence: str = ""
    reference: str = ""
    reference_source: str = ""
    verification_required: bool = True
    source: EvidenceSource = EvidenceSource.NMAP
    resolved_at: datetime | None = None
    created_at: datetime | None = None
    #: CVSS v3.1 base score, only when a real source supplied one: a score the
    #: ``vulners`` NSE script printed beside a CVE, or one an administrator
    #: recorded in the vulnerability knowledge base. Never estimated.
    cvss_base_score: float | None = None
    #: Where the score came from ("Nmap NSE vulners", "Configured knowledge
    #: base"); empty when there is no score.
    cvss_source: str = ""

    @property
    def effective_rating(self) -> RiskLevel:
        """The rating §3.9.9 classifies on: the CVSS band where scored, else
        the rating the finding was recorded with."""
        if self.cvss_base_score is not None:
            from aethra_sec.models.host import cvss_band

            band = cvss_band(self.cvss_base_score)
            if band is not None:
                return band
        return self.risk_level

    @property
    def status_text(self) -> str:
        """``OPEN`` until an operator marks the finding resolved."""
        return "RESOLVED" if self.resolved_at else "OPEN"

    @property
    def reference_text(self) -> str:
        """Reference identifier, or the honest 'verification required' text."""
        if self.reference:
            return f"{self.reference} ({self.reference_source or 'configured source'})"
        return "Potential exposure identified; further vulnerability verification required."


#: Shown where Nmap ran a probe and it returned nothing. Distinct from an
#: empty value, which would read as though the field was never examined.
NOT_DETECTED = "Not detected"

@dataclass
class ScanHostResult:
    """One host inside a scan result."""

    id: int | None = None
    scan_id: int | None = None
    host_id: int | None = None
    ip_address: str = ""
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    status: HostStatus = HostStatus.UNKNOWN
    os_name: str = ""
    os_version: str = ""
    os_cpe: str = ""
    os_accuracy: int | None = None
    os_family: str = ""
    #: How the hostname and OS were established ("SMB", "NetBIOS", "reverse
    #: DNS", "Nmap fingerprint"), so a result can be judged on its source.
    hostname_source: str = ""
    os_source: str = ""
    #: Why a field is unknown, when it is.
    identity_notes: tuple[str, ...] = ()
    ports: list[PortResult] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)

    @property
    def hostname_text(self) -> str:
        """The hostname, or ``Not detected`` when discovery found none.

        "Not detected" rather than "Unknown": it states that a probe ran and
        returned nothing, which is a result, instead of implying the field was
        never examined.
        """
        return self.hostname.strip() or NOT_DETECTED

    @property
    def os_text(self) -> str:
        """The operating system with its version and confidence, or Unknown.

        Accuracy is shown when the answer came from a fingerprint, because a
        fingerprint is an inference. A value the host reported about itself
        over SMB needs no such qualifier.
        """
        if not self.os_name:
            # A family without a specific match is still an answer worth
            # showing - "Windows" narrows the field even when the build does
            # not. It is labelled so nobody reads it as a precise match.
            return (
                f"{self.os_family} (family only)"
                if self.os_family
                else NOT_DETECTED
            )
        text = self.os_name
        if self.os_version and self.os_version not in text:
            text = f"{text} {self.os_version}"
        if self.os_accuracy:
            text = f"{text} ({self.os_accuracy}%)"
        return text

    @property
    def open_ports(self) -> list[PortResult]:
        """Only the ports Nmap reported as open."""
        return [p for p in self.ports if p.is_open]

    @property
    def highest_risk(self) -> RiskLevel:
        """The most serious risk level among this host's findings."""
        if not self.findings:
            return RiskLevel.INFORMATIONAL
        return max(
            (f.risk_level for f in self.findings),
            key=lambda level: level.severity.rank,
        )


@dataclass
class Scan:
    """One Nmap assessment run."""

    id: int | None = None
    target: str = ""
    target_kind: str = ""
    profile: str = ""
    profile_label: str = ""
    port_spec: str = ""
    timing: str = ""
    arguments: str = ""
    status: ScanStatus = ScanStatus.QUEUED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    hosts_total: int = 0
    hosts_up: int = 0
    open_ports: int = 0
    findings_count: int = 0
    error_message: str = ""
    nmap_version: str = ""
    command_line: str = ""
    #: What caused this assessment to run. Recorded so automatic assessment
    #: is demonstrable: a history in which every row reads MANUAL proves
    #: nothing about automation.
    trigger_source: ScanTrigger = ScanTrigger.MANUAL
    initiated_by: int | None = None
    initiated_by_username: str = ""
    created_at: datetime | None = None
    hosts: list[ScanHostResult] = field(default_factory=list)

    @property
    def status_text(self) -> str:
        """Status string used by the scan history table."""
        return str(self.status)

    @property
    def summary_line(self) -> str:
        """One-line summary derived from the real result counts."""
        if self.status is ScanStatus.FAILED:
            return f"Failed: {self.error_message or 'unknown error'}"
        if self.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            return f"{self.status} - {self.target}"
        return (
            f"{self.hosts_up} host(s) up, {self.open_ports} open port(s), "
            f"{self.findings_count} finding(s)"
        )

    #: Ports named inline before the summary falls back to a bare count.
    OPEN_PORT_PREVIEW = 12

    @property
    def open_ports_line(self) -> str:
        """The open ports themselves, per host, not just how many there are.

        A count answers "is there anything here"; it does not answer "what".
        An operator reading "6 open port(s)" still has to go and find out
        which six, so the six are named here as well.

        Returns an empty string when the scan is not finished or found no open
        port - there is then nothing to name, and an empty line says that more
        honestly than "none" beside a zero that is already on screen.
        """
        parts: list[str] = []
        for host in self.hosts:
            ports = host.open_ports
            if not ports:
                continue
            ordered = sorted(ports, key=lambda p: (p.protocol, p.port))
            shown = ordered[: self.OPEN_PORT_PREVIEW]
            listed = ", ".join(
                f"{port.port}/{port.protocol}"
                + (f" ({port.service})" if port.service else "")
                for port in shown
            )
            if len(ordered) > len(shown):
                listed += f", and {len(ordered) - len(shown)} more"
            parts.append(f"{host.ip_address}: {listed}")
        return "   ".join(parts)


@dataclass
class ScanComparison:
    """Difference between two scans of the same target (§45)."""

    baseline_scan_id: int
    current_scan_id: int
    newly_open_ports: tuple[tuple[str, int, str], ...] = ()
    closed_ports: tuple[tuple[str, int, str], ...] = ()
    changed_services: tuple[tuple[str, int, str, str, str], ...] = ()
    new_hosts: tuple[str, ...] = ()
    missing_hosts: tuple[str, ...] = ()
    recurring_findings: tuple[str, ...] = ()

    @property
    def has_changes(self) -> bool:
        """True when any difference was detected."""
        return any(
            (
                self.newly_open_ports,
                self.closed_ports,
                self.changed_services,
                self.new_hosts,
                self.missing_hosts,
            )
        )
