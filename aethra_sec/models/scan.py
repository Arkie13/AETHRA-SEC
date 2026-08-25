"""Nmap assessment models (§16-§20, §45).

An important distinction is encoded here (§19): a **port observation** is not a
vulnerability. ``PortResult`` records what Nmap saw; ``ScanFinding`` records a
security *concern* derived from that observation by a documented rule, and
always states why the risk level was assigned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import EvidenceSource, HostStatus, RiskLevel, ScanStatus


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
    os_accuracy: int | None = None
    os_family: str = ""
    ports: list[PortResult] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)

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
