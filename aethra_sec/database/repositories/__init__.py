"""Repository layer: the only place SQL is written.

Every method uses bound parameters. Where an identifier must be placed into a
statement (a sort column, a table alias) it comes from a module-level whitelist
inside the repository, never from caller input.
"""

from __future__ import annotations

from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.incidents import IncidentRepository
from aethra_sec.database.repositories.mitigation import MitigationRepository
from aethra_sec.database.repositories.password_resets import PasswordResetRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.database.repositories.settings import (
    ErrorRepository,
    IntegrationStatusRepository,
    NotificationRepository,
    ReportRepository,
    SettingsRepository,
)
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.database.repositories.users import UserRepository

__all__ = [
    "AlertRepository",
    "AuditRepository",
    "ErrorRepository",
    "HostRepository",
    "IncidentRepository",
    "IntegrationStatusRepository",
    "MitigationRepository",
    "NotificationRepository",
    "PasswordResetRepository",
    "ReportRepository",
    "ScanRepository",
    "SettingsRepository",
    "TrafficRepository",
    "UserRepository",
]
