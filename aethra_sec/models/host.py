"""Network host inventory models (§15, §46, §47)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import EvidenceSource, HostStatus, RiskLevel


@dataclass
class Host:
    """A host AETHRA-SEC has actually observed or scanned.

    Every field is populated from a real observation. ``hostname`` stays empty
    when reverse resolution fails - the UI then shows the IP address rather
    than inventing a name (§15).
    """

    id: int | None
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    #: When reverse DNS was last attempted. ``None`` means never, which is why
    #: an empty hostname is not by itself evidence that the address has no name.
    hostname_checked_at: datetime | None = None
    vendor: str = ""
    os_name: str = ""
    os_accuracy: int | None = None
    status: HostStatus = HostStatus.UNKNOWN
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    discovery_source: EvidenceSource = EvidenceSource.PYSHARK
    is_trusted: bool = False
    trust_note: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    # Derived counters, populated by inventory queries rather than stored.
    open_port_count: int = 0
    alert_count: int = 0
    incident_count: int = 0
    finding_count: int = 0
    packet_count: int = 0
    protocols_observed: tuple[str, ...] = ()

    @property
    def display_name(self) -> str:
        """Hostname when known, otherwise the IP address."""
        return self.hostname.strip() or self.ip_address

    @property
    def hostname_text(self) -> str:
        """The hostname, or why there isn't one.

        A blank cell tells an operator nothing, and a dash tells them nothing
        twice: it looks identical whether the address has no DNS record or
        whether nobody has ever asked. These two answers are different, and
        only one of them is worth acting on.
        """
        name = self.hostname.strip()
        if name:
            return name
        return "no DNS record" if self.hostname_checked_at else "not resolved"

    @property
    def os_text(self) -> str:
        """OS description with accuracy, or why it is not known.

        Capture cannot fingerprint an operating system - only an assessment
        can - so an unscanned host says so rather than showing a dash.
        """
        if not self.os_name:
            return "not scanned"
        if self.os_accuracy:
            return f"{self.os_name} ({self.os_accuracy}%)"
        return self.os_name


@dataclass
class HostObservation:
    """A rolled-up record of traffic seen for one host in one interval.

    This is what keeps the host inventory current without inserting a row per
    packet: the capture worker aggregates observations in memory and flushes
    them on the configured interval.
    """

    id: int | None
    host_id: int
    interface: str = ""
    protocol: str = ""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: EvidenceSource = EvidenceSource.PYSHARK


@dataclass
class TrustedHost:
    """An asset the administrator has marked as authorised (§93).

    Trust is *context*, not an exemption: traffic from a trusted host is still
    analysed and still raises anomalies, but the incident view labels the
    source as a known asset so the analyst can weigh it.
    """

    id: int | None
    ip_address: str
    label: str = ""
    reason: str = ""
    added_by: int | None = None
    created_at: datetime | None = None
    is_active: bool = True


@dataclass
class HostDetail:
    """Everything the host detail screen shows, assembled from real records."""

    host: Host
    observations: tuple[HostObservation, ...] = ()
    open_ports: tuple[object, ...] = ()
    scans: tuple[object, ...] = ()
    alerts: tuple[object, ...] = ()
    incidents: tuple[object, ...] = ()
    findings: tuple[object, ...] = ()
    timeline: tuple[dict[str, object], ...] = field(default_factory=tuple)
