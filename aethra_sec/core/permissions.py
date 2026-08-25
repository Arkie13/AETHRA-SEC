"""Permission vocabulary and role definitions (§7, §8, §55-Elevation of Privilege).

Permissions are enforced in the **service layer**, not only in the UI. Screens
use :func:`aethra_sec.core.permissions.PermissionSet.has` to hide or disable
controls, but every mutating service method independently re-checks the calling
session, so a user who bypasses the interface still cannot act beyond their role.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, NamedTuple

ROLE_ADMIN = "ADMIN"
ROLE_USER = "USER"


class PermissionSpec(NamedTuple):
    """Declarative permission definition used to seed the database."""

    code: str
    name: str
    description: str
    category: str


class Permission:
    """Permission code constants."""

    DASHBOARD_VIEW = "dashboard.view"

    MONITOR_VIEW = "monitor.view"
    MONITOR_CONTROL = "monitor.control"
    MONITOR_EXPORT = "monitor.export"

    SCAN_VIEW = "scan.view"
    SCAN_RUN = "scan.run"
    SCAN_STOP = "scan.stop"

    HOST_VIEW = "host.view"
    HOST_MANAGE = "host.manage"

    ALERT_VIEW = "alert.view"
    ALERT_MANAGE = "alert.manage"

    INCIDENT_VIEW = "incident.view"
    INCIDENT_MANAGE = "incident.manage"

    MITIGATION_VIEW = "mitigation.view"
    MITIGATION_MANAGE = "mitigation.manage"

    REPORT_GENERATE = "report.generate"
    REPORT_EXPORT = "report.export"

    LOG_VIEW = "log.view"
    LOG_EXPORT = "log.export"
    LOG_VERIFY = "log.verify"

    USER_MANAGE = "user.manage"
    USER_RESET_APPROVE = "user.reset_approve"
    SETTINGS_MANAGE = "settings.manage"

    HEALTH_VIEW = "health.view"
    HEALTH_DETAIL = "health.detail"

    EVALUATION_CLASSIFY = "evaluation.classify"
    DATA_MAINTAIN = "data.maintain"


PERMISSION_SPECS: tuple[PermissionSpec, ...] = (
    PermissionSpec(
        Permission.DASHBOARD_VIEW, "View dashboard",
        "Open the security operations dashboard.", "dashboard",
    ),
    PermissionSpec(
        Permission.MONITOR_VIEW, "View live traffic",
        "View live packets, traffic statistics and capture status.", "monitoring",
    ),
    PermissionSpec(
        Permission.MONITOR_CONTROL, "Control packet capture",
        "Start and stop packet capture and select the capture interface.",
        "monitoring",
    ),
    PermissionSpec(
        Permission.MONITOR_EXPORT, "Export traffic data",
        "Export captured packet metadata and traffic statistics.", "monitoring",
    ),
    PermissionSpec(
        Permission.SCAN_VIEW, "View assessments",
        "View vulnerability assessment results and scan history.", "assessment",
    ),
    PermissionSpec(
        Permission.SCAN_RUN, "Run assessments",
        "Start an authorised Nmap vulnerability assessment.", "assessment",
    ),
    PermissionSpec(
        Permission.SCAN_STOP, "Stop assessments",
        "Stop a running assessment.", "assessment",
    ),
    PermissionSpec(
        Permission.HOST_VIEW, "View host inventory",
        "View discovered hosts and host detail pages.", "inventory",
    ),
    PermissionSpec(
        Permission.HOST_MANAGE, "Manage host inventory",
        "Edit host labels, trust status and inventory records.", "inventory",
    ),
    PermissionSpec(
        Permission.ALERT_VIEW, "View IDS alerts",
        "View Snort alerts and their evidence.", "detection",
    ),
    PermissionSpec(
        Permission.ALERT_MANAGE, "Manage IDS alerts",
        "Acknowledge, review and classify IDS alerts.", "detection",
    ),
    PermissionSpec(
        Permission.INCIDENT_VIEW, "View incidents",
        "View correlated threat incidents and investigations.", "detection",
    ),
    PermissionSpec(
        Permission.INCIDENT_MANAGE, "Manage incidents",
        "Change incident status, assign owners and add investigation notes.",
        "detection",
    ),
    PermissionSpec(
        Permission.MITIGATION_VIEW, "View mitigation guidance",
        "View mitigation recommendations for threats and findings.", "mitigation",
    ),
    PermissionSpec(
        Permission.MITIGATION_MANAGE, "Manage mitigation knowledge",
        "Create, edit and deactivate mitigation recommendations.", "mitigation",
    ),
    PermissionSpec(
        Permission.REPORT_GENERATE, "Generate reports",
        "Generate reports from stored records.", "reporting",
    ),
    PermissionSpec(
        Permission.REPORT_EXPORT, "Export reports",
        "Export reports and record sets to CSV, Excel or PDF.", "reporting",
    ),
    PermissionSpec(
        Permission.LOG_VIEW, "View logs and audit trail",
        "View system logs and the audit trail.", "administration",
    ),
    PermissionSpec(
        Permission.LOG_EXPORT, "Export logs",
        "Export log and audit records.", "administration",
    ),
    PermissionSpec(
        Permission.LOG_VERIFY, "Verify log integrity",
        "Run the audit log integrity verification.", "administration",
    ),
    PermissionSpec(
        Permission.USER_MANAGE, "Manage users",
        "Create, edit, deactivate and reset user accounts.", "administration",
    ),
    PermissionSpec(
        Permission.USER_RESET_APPROVE, "Approve password recovery",
        "Review, approve and reject password-reset requests raised at sign-in.",
        "administration",
    ),
    PermissionSpec(
        Permission.SETTINGS_MANAGE, "Manage system settings",
        "Change configuration, thresholds and retention settings.",
        "administration",
    ),
    PermissionSpec(
        Permission.HEALTH_VIEW, "View system health",
        "View subsystem status indicators.", "administration",
    ),
    PermissionSpec(
        Permission.HEALTH_DETAIL, "View detailed diagnostics",
        "View full diagnostics including paths, environment and schema state.",
        "administration",
    ),
    PermissionSpec(
        Permission.EVALUATION_CLASSIFY, "Classify detections",
        "Label detections as true/false positives for accuracy evaluation.",
        "detection",
    ),
    PermissionSpec(
        Permission.DATA_MAINTAIN, "Perform data maintenance",
        "Run retention pruning, backups and database maintenance.",
        "administration",
    ),
)

ALL_PERMISSION_CODES: tuple[str, ...] = tuple(spec.code for spec in PERMISSION_SPECS)

#: Permissions granted to the normal USER role (§8). Deliberately excludes every
#: administrative capability; the service layer refuses anything absent here.
USER_PERMISSIONS: tuple[str, ...] = (
    Permission.DASHBOARD_VIEW,
    Permission.MONITOR_VIEW,
    Permission.MONITOR_CONTROL,
    Permission.MONITOR_EXPORT,
    Permission.SCAN_VIEW,
    Permission.SCAN_RUN,
    Permission.SCAN_STOP,
    Permission.HOST_VIEW,
    Permission.ALERT_VIEW,
    Permission.INCIDENT_VIEW,
    Permission.MITIGATION_VIEW,
    Permission.REPORT_GENERATE,
    Permission.REPORT_EXPORT,
    Permission.HEALTH_VIEW,
)

#: The ADMIN role holds every permission (§7).
ADMIN_PERMISSIONS: tuple[str, ...] = ALL_PERMISSION_CODES

ROLE_DEFINITIONS: dict[str, dict[str, object]] = {
    ROLE_ADMIN: {
        "description": (
            "Full administrative access: user management, configuration, "
            "mitigation knowledge, logs, audit and all monitoring functions."
        ),
        "permissions": ADMIN_PERMISSIONS,
    },
    ROLE_USER: {
        "description": (
            "Standard analyst access: dashboard, monitoring, authorised "
            "assessments, alerts, incidents, mitigation guidance and reports."
        ),
        "permissions": USER_PERMISSIONS,
    },
}


@dataclass(frozen=True)
class PermissionSet:
    """An immutable set of permission codes resolved for a user at login."""

    codes: frozenset[str]

    @classmethod
    def of(cls, codes: Iterable[str]) -> "PermissionSet":
        """Build a permission set from any iterable of codes."""
        return cls(frozenset(str(code).strip() for code in codes if str(code).strip()))

    @classmethod
    def for_role(cls, role: str) -> "PermissionSet":
        """Default permission set for a role name (fallback when the database
        has not yet been consulted)."""
        definition = ROLE_DEFINITIONS.get(str(role).upper())
        if not definition:
            return cls(frozenset())
        return cls.of(definition["permissions"])  # type: ignore[arg-type]

    def has(self, permission: str) -> bool:
        """True when the permission is granted."""
        return permission in self.codes

    def has_any(self, *permissions: str) -> bool:
        """True when at least one of the permissions is granted."""
        return any(p in self.codes for p in permissions)

    def has_all(self, *permissions: str) -> bool:
        """True when every permission is granted."""
        return all(p in self.codes for p in permissions)

    def sorted_codes(self) -> tuple[str, ...]:
        """Permission codes in stable order (for display and audit)."""
        return tuple(sorted(self.codes))
