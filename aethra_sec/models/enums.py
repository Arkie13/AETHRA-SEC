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
    """Security severity, ordered INFO < LOW < MEDIUM < HIGH < CRITICAL.

    Not every member applies to every module. The IDS Alerts and Threat
    Incidents severity model is HIGH / MEDIUM / LOW - see
    :data:`~aethra_sec.models.severity_source.DETECTION_SEVERITIES`, which is
    the authority - and nothing in those two modules produces CRITICAL.

    CRITICAL remains here because :class:`RiskLevel` maps onto this enum and
    assessment findings do use it: a CRITICAL Nmap finding is a real thing.
    """

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
    CORRELATION = "CORRELATION"
    SYSTEM = "SYSTEM"
    MANUAL = "MANUAL"
    #: Recorded before this installation enforced provenance, by a pipeline
    #: that entered an address it had only seen *named* by another device -
    #: the destination of an ARP request, say - rather than seen transmitting.
    #: Such a row proves the address was mentioned on the wire and nothing
    #: more, so it says so instead of claiming a subsystem discovered it.
    LEGACY = "LEGACY"

    @property
    def label(self) -> str:
        """Display label used throughout the interface."""
        return {
            EvidenceSource.NMAP: "Nmap",
            EvidenceSource.PYSHARK: "PyShark",
            EvidenceSource.SNORT: "Snort",
            EvidenceSource.CORRELATION: "Correlation Engine",
            EvidenceSource.SYSTEM: "System",
            EvidenceSource.MANUAL: "Entered by an operator",
            EvidenceSource.LEGACY: "Legacy record - source unknown",
        }[self]

    @property
    def is_evidenced(self) -> bool:
        """Whether this source establishes that the host really exists.

        :data:`LEGACY` does not: it marks a row kept for its history whose
        origin this installation cannot vouch for.
        """
        return self is not EvidenceSource.LEGACY


class ThreatCategory(StrEnum):
    """Categories the correlation and mitigation engines key on.

    Every category maps to at least one seeded mitigation recommendation, and
    every category is one the sensors can actually produce.

    The first five are the attack scenarios the manuscript defines and tests;
    :mod:`aethra_sec.models.scope` is the authority on which those are, and
    this enum deliberately does not repeat the list. The rest are real events
    the sensors observe outside the tested scenarios - a host sweep, an exposed
    service, a payload Snort flagged - and they are kept because discarding a
    genuine observation to match a chapter heading would falsify the record.

    Brute force and malware were removed. Both appear in the manuscript only as
    background and literature, neither is a tested scenario, and neither could
    ever be produced by AETHRA-SEC's own detection engine: they existed solely
    as keyword buckets for classifying a Snort signature's text, and had never
    matched a stored record.
    """

    PORT_SCAN = "PORT_SCAN"
    TCP_SYN_FLOOD = "TCP_SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    ICMP_FLOOD = "ICMP_FLOOD"
    HTTP_FLOOD = "HTTP_FLOOD"
    HOST_SWEEP = "HOST_SWEEP"
    SUSPICIOUS_PAYLOAD = "SUSPICIOUS_PAYLOAD"
    SERVICE_EXPOSURE = "SERVICE_EXPOSURE"
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


class AssessmentState(StrEnum):
    """Where a discovered host stands in the automatic assessment cycle.

    The cycle exists because discovery and assessment answer different
    questions and run at wildly different rates: PyShark observes a host the
    moment it sends a frame, and Nmap takes seconds to minutes to assess one.
    Launching a scan per observation would start hundreds of processes; the
    state is what makes "observed" and "assessed" separate facts.
    """

    #: Observed on the network; not yet considered for assessment.
    DISCOVERED = "DISCOVERED"
    #: Accepted for assessment and waiting for a worker.
    QUEUED = "QUEUED"
    #: An Nmap process is running against it now.
    SCANNING = "SCANNING"
    #: Assessed successfully; the results are stored.
    COMPLETED = "COMPLETED"
    #: Nmap ran to completion and the host did not answer it (0 hosts up).
    #:
    #: Distinct from COMPLETED because the two say opposite things. A scan
    #: that finished without the host replying establishes nothing about what
    #: that host exposes, so reporting it as COMPLETED beside "0 open ports,
    #: 0 findings" reads as a clean bill of health for a host that was never
    #: examined. It is also distinct from FAILED: nothing went wrong with the
    #: scan, and from the host being OFFLINE, which is a statement about the
    #: host rather than about the assessment.
    NO_RESPONSE = "NO_RESPONSE"
    #: The assessment ran and failed. Retried subject to the attempt cap.
    FAILED = "FAILED"
    #: Nmap did not finish in time. Retried with back-off, like a failure,
    #: but reported separately because it says something different.
    TIMEOUT = "TIMEOUT"
    #: Deliberately not assessed - outside the authorised networks, excluded
    #: by configuration, or the sensor's own address.
    SKIPPED = "SKIPPED"
    #: Assessed recently enough that it is not due again yet.
    COOLDOWN = "COOLDOWN"

    @property
    def is_pending(self) -> bool:
        """True while the host is waiting on or inside an assessment."""
        return self in (AssessmentState.QUEUED, AssessmentState.SCANNING)


class ScanTrigger(StrEnum):
    """What caused an assessment to run.

    Recorded so the automation can be demonstrated: a scan history in which
    every row reads MANUAL proves nothing about automatic assessment.
    """

    MANUAL = "MANUAL"
    AUTOMATIC_DISCOVERY = "AUTOMATIC_DISCOVERY"
    SCHEDULED_REASSESSMENT = "SCHEDULED_REASSESSMENT"


class ScanStatus(StrEnum):
    """Lifecycle of an Nmap assessment run."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    #: Nmap did not finish inside its time limit, or abandoned the host on
    #: ``--host-timeout``. Not a result about the host; never "no findings".
    TIMEOUT = "TIMEOUT"

    @property
    def is_terminal(self) -> bool:
        """True when the scan will not change state again."""
        return self in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
            ScanStatus.TIMEOUT,
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
