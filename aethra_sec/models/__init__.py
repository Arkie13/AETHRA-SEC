"""Plain dataclasses shared by every AETHRA-SEC layer.

Models carry no I/O and no business rules beyond derived display properties, so
they can be constructed freely in tests and passed across thread boundaries.
"""

from __future__ import annotations

from aethra_sec.models.alert import SnortAlert, SnortStatus
from aethra_sec.models.enums import (
    AlertStatus,
    CheckResult,
    EvaluationLabel,
    EvidenceSource,
    ExportFormat,
    HostStatus,
    IncidentStatus,
    NotificationLevel,
    ReportType,
    RiskLevel,
    ScanStatus,
    ServiceState,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.host import Host, HostObservation, TrustedHost
from aethra_sec.models.incident import (
    Incident,
    IncidentEvent,
    IncidentNote,
    RiskAssessment,
)
from aethra_sec.models.mitigation import MitigationAdvice, MitigationRecommendation
from aethra_sec.models.scan import PortResult, Scan, ScanFinding, ScanHostResult
from aethra_sec.models.system import (
    DashboardSnapshot,
    DiagnosticCheck,
    DiagnosticsReport,
    Notification,
    ReportRecord,
    ServiceStatus,
    SystemSetting,
)
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.models.traffic import (
    CapturedPacket,
    CaptureStatistics,
    TrafficAggregate,
    TrafficRecord,
)
from aethra_sec.models.user import AuditRecord, LoginAttempt, Role, User

__all__ = [
    "AlertStatus", "AuditRecord", "CapturedPacket", "CaptureStatistics",
    "CheckResult", "DashboardSnapshot", "DiagnosticCheck", "DiagnosticsReport",
    "EvaluationLabel", "EvidenceSource", "ExportFormat", "Host",
    "HostObservation", "HostStatus", "Incident", "IncidentEvent",
    "IncidentNote", "IncidentStatus", "LoginAttempt", "MitigationAdvice",
    "MitigationRecommendation", "Notification", "NotificationLevel",
    "PortResult", "ReportRecord", "ReportType", "RiskAssessment", "RiskLevel",
    "Role", "Scan", "ScanFinding", "ScanHostResult", "ScanStatus",
    "ServiceState", "ServiceStatus", "Severity", "SnortAlert", "SnortStatus",
    "SystemSetting", "ThreatCategory", "TrafficAggregate", "TrafficAnomaly",
    "TrafficRecord", "TrustedHost", "User",
]
