"""Controlled vocabularies shared by every layer.

These enumerations are stored as strings in MySQL so that database contents stay
readable during an investigation and so that a schema change is not required to
audit historical values.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String-valued enum whose ``str()`` is the bare value."""

    def __str__(self) -> str:  # noqa: D105
        return str(self.value)

    @classmethod
    def parse(cls, value: object, default: "StrEnum | None" = None) -> "StrEnum":
        """Parse ``value`` case-insensitively, falling back to ``default``.

        Unknown values never raise: data arriving from external tools must not
        be able to crash ingestion. Callers that need strictness compare the
        result against the input instead.
        """
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value.upper() == text or member.name == text:
                return member
        if default is not None:
            return default
        return next(iter(cls))


class Severity(StrEnum):
    """Security severity, ordered INFO < LOW < MEDIUM < HIGH < CRITICAL."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric ordering used for sorting and threshold comparisons."""
        return _SEVERITY_RANK[self]

    def at_least(self, other: "Severity") -> bool:
        """True when this severity is at least as serious as ``other``."""
        return self.rank >= other.rank

    @classmethod
    def from_rank(cls, rank: int) -> "Severity":
        """Inverse of :attr:`rank`, clamped to the valid range."""
        clamped = max(0, min(4, rank))
        return _RANK_SEVERITY[clamped]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_RANK_SEVERITY: dict[int, Severity] = {v: k for k, v in _SEVERITY_RANK.items()}


class RiskLevel(StrEnum):
    """Risk classification applied to assessment findings (§20)."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def severity(self) -> Severity:
        """Equivalent security severity."""
        return {
            RiskLevel.INFORMATIONAL: Severity.INFO,
            RiskLevel.LOW: Severity.LOW,
            RiskLevel.MEDIUM: Severity.MEDIUM,
            RiskLevel.HIGH: Severity.HIGH,
            RiskLevel.CRITICAL: Severity.CRITICAL,
        }[self]


class EvidenceSource(StrEnum):
    """Which subsystem produced a record (§96 - source traceability)."""

    NMAP = "NMAP"
    PYSHARK = "PYSHARK"
    SNORT = "SNORT"
    WINDOWS_FIREWALL = "WINDOWS_FIREWALL"
    CORRELATION = "CORRELATION"
    SYSTEM = "SYSTEM"

    @property
    def label(self) -> str:
        """Display label used throughout the interface."""
        return {
            EvidenceSource.NMAP: "Nmap",
            EvidenceSource.PYSHARK: "PyShark",
            EvidenceSource.SNORT: "Snort",
            EvidenceSource.WINDOWS_FIREWALL: "Windows Firewall",
            EvidenceSource.CORRELATION: "Correlation Engine",
            EvidenceSource.SYSTEM: "System",
        }[self]


class ThreatCategory(StrEnum):
    """Categories the correlation and mitigation engines key on.

    Every category maps to at least one seeded mitigation recommendation.
    """

    PORT_SCAN = "PORT_SCAN"
    HOST_SWEEP = "HOST_SWEEP"
    BRUTE_FORCE = "BRUTE_FORCE"
    TCP_SYN_FLOOD = "TCP_SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    ICMP_FLOOD = "ICMP_FLOOD"
    HTTP_FLOOD = "HTTP_FLOOD"
    SUSPICIOUS_PAYLOAD = "SUSPICIOUS_PAYLOAD"
    SERVICE_EXPOSURE = "SERVICE_EXPOSURE"
    MALWARE_INDICATOR = "MALWARE_INDICATOR"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    UNCLASSIFIED = "UNCLASSIFIED"

    @property
    def label(self) -> str:
        """Human-readable category name."""
        return self.value.replace("_", " ").title()


class IncidentStatus(StrEnum):
    """Incident lifecycle (§94)."""

    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"

    @property
    def is_open(self) -> bool:
        """True while the incident still requires analyst attention."""
        return self in {
            IncidentStatus.NEW,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ACKNOWLEDGED,
        }


class AlertStatus(StrEnum):
    """Analyst workflow state of an individual IDS alert (§43)."""

    NEW = "NEW"
    REVIEWED = "REVIEWED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ESCALATED = "ESCALATED"
    SUPPRESSED = "SUPPRESSED"


class EvaluationLabel(StrEnum):
    """Analyst classification used for detection-accuracy evaluation (§82).

    These labels are applied by an authorised evaluator; the system never
    assigns them automatically.
    """

    UNCLASSIFIED = "UNCLASSIFIED"
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    BENIGN_EXPECTED = "BENIGN_EXPECTED"
    UNKNOWN = "UNKNOWN"

    @property
    def label(self) -> str:
        """Display label."""
        return self.value.replace("_", " ").title()


class ScanStatus(StrEnum):
    """Lifecycle of an Nmap assessment run."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        """True when the scan will not change state again."""
        return self in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }


class ServiceState(StrEnum):
    """Runtime state of an AETHRA-SEC subsystem, as actually observed.

    A state is only ever set from a real probe result. ``UNKNOWN`` is used
    before the first probe rather than assuming a healthy state.
    """

    UNKNOWN = "UNKNOWN"
    AVAILABLE = "AVAILABLE"
    RUNNING = "RUNNING"
    CONNECTED = "CONNECTED"
    CAPTURING = "CAPTURING"
    STOPPED = "STOPPED"
    OFFLINE = "OFFLINE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    DISABLED = "DISABLED"

    @property
    def is_healthy(self) -> bool:
        """True for states that represent a working subsystem."""
        return self in {
            ServiceState.AVAILABLE,
            ServiceState.RUNNING,
            ServiceState.CONNECTED,
            ServiceState.CAPTURING,
        }


class CheckResult(StrEnum):
    """Diagnostics outcome (§71)."""

    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


class HostStatus(StrEnum):
    """Inventory state of a discovered host."""

    UP = "UP"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class NotificationLevel(StrEnum):
    """In-application notification level."""

    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ReportType(StrEnum):
    """Report catalogue (§48)."""

    SECURITY_ASSESSMENT = "SECURITY_ASSESSMENT"
    VULNERABILITY = "VULNERABILITY"
    NETWORK_MONITORING = "NETWORK_MONITORING"
    IDS_ALERT = "IDS_ALERT"
    THREAT_INCIDENT = "THREAT_INCIDENT"
    MITIGATION = "MITIGATION"
    SYSTEM_ACTIVITY = "SYSTEM_ACTIVITY"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"

    @property
    def label(self) -> str:
        """Display title, as it appears on the screen and in the export."""
        titles = {
            "SECURITY_ASSESSMENT": "Security Assessment Report",
            "VULNERABILITY": "Vulnerability Report",
            "NETWORK_MONITORING": "Network Monitoring Report",
            "IDS_ALERT": "IDS Alert Report",
            "THREAT_INCIDENT": "Threat Incident Report",
            "MITIGATION": "Mitigation Report",
            "SYSTEM_ACTIVITY": "System Activity Report",
            "EXECUTIVE_SUMMARY": "Executive Summary Report",
        }
        return titles.get(self.value, self.value.replace("_", " ").title() + " Report")


class ExportFormat(StrEnum):
    """Supported export formats (§50)."""

    CSV = "CSV"
    PDF = "PDF"
    XLSX = "XLSX"

    @property
    def extension(self) -> str:
        """Filename extension including the dot."""
        return {"CSV": ".csv", "PDF": ".pdf", "XLSX": ".xlsx"}[self.value]
