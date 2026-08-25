"""Service layer: orchestration, threading, lifecycle and RBAC enforcement.

Every mutating method on every service re-checks the calling session's
permissions. The user interface hides controls a role cannot use, but that is a
convenience - this layer is the control (§8, §55).
"""

from __future__ import annotations

from aethra_sec.services.backup_service import (
    BackupFile,
    BackupService,
    BackupStatus,
)
from aethra_sec.services.correlation_service import CorrelationService
from aethra_sec.services.dashboard_service import DashboardService
from aethra_sec.services.health_service import HealthService, SubsystemProbes
from aethra_sec.services.host_service import HostService
from aethra_sec.services.log_service import LogService
from aethra_sec.services.mitigation_service import MitigationService
from aethra_sec.services.nmap_service import NmapService
from aethra_sec.services.notification_service import NotificationService
from aethra_sec.services.packet_capture import PacketCaptureService
from aethra_sec.services.recovery_service import (
    Approval,
    PasswordRecoveryService,
    RecoveryPolicy,
)
from aethra_sec.services.report_service import ReportService
from aethra_sec.services.retention_service import RetentionService
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.services.snort_service import SnortService
from aethra_sec.services.user_service import UserService

__all__ = [
    "Approval",
    "BackupFile",
    "BackupService",
    "BackupStatus",
    "CorrelationService",
    "DashboardService",
    "HealthService",
    "HostService",
    "LogService",
    "MitigationService",
    "NmapService",
    "NotificationService",
    "PacketCaptureService",
    "PasswordRecoveryService",
    "RecoveryPolicy",
    "ReportService",
    "RetentionService",
    "SettingsService",
    "SnortService",
    "SubsystemProbes",
    "UserService",
]
