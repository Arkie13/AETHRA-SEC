"""System health and diagnostics (§10, §39, §71, §73).

Every status this service reports is the outcome of a real probe performed at
the moment of the call. A subsystem is shown as healthy only when it answered;
before the first probe its state is ``UNKNOWN``, never an optimistic guess
(§120).
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from aethra_sec.config.environment import describe_environment, loaded_env_file
from aethra_sec.config.settings import AppSettings
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType, ServiceStatusPayload
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.database.migrations import LATEST_VERSION, current_version, verify_schema
from aethra_sec.database.repositories.settings import IntegrationStatusRepository
from aethra_sec.models.enums import CheckResult, ServiceState
from aethra_sec.models.system import (
    DiagnosticCheck,
    DiagnosticsReport,
    ServiceStatus,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import format_uptime, utcnow
from aethra_sec.version import APP_VERSION

LOGGER = get_logger("services.health")


@dataclass
class SubsystemProbes:
    """Callables the health service uses to interrogate live subsystems.

    Injected rather than imported so the health service stays independent of
    the services it reports on (and remains trivially testable).
    """

    nmap: Callable[[], Any] | None = None
    tshark: Callable[[], Any] | None = None
    capture_status: Callable[[], Any] | None = None
    snort_status: Callable[[], Any] | None = None
    snort_executable: Callable[[], tuple[bool, str]] | None = None
    correlation_stats: Callable[[], Any] | None = None
    scheduler_status: Callable[[], list[dict[str, Any]]] | None = None
    event_bus_stats: Callable[[], dict[str, Any]] | None = None
    session_count: Callable[[], int] | None = None
    password_algorithm: Callable[[], str] | None = None
    otp_status: Callable[[], Any] | None = None
    mitigation_count: Callable[[], int] | None = None


class HealthService:
    """Probes every subsystem and records what it actually found."""

    def __init__(
        self,
        db: DatabaseManager,
        integration_status: IntegrationStatusRepository,
        settings: AppSettings,
        event_bus: EventBus,
        probes: SubsystemProbes | None = None,
    ) -> None:
        """Wire the service to the things it will probe."""
        self._db = db
        self._integration = integration_status
        self._settings = settings
        self._bus = event_bus
        self._probes = probes or SubsystemProbes()
        self._lock = threading.RLock()
        self._statuses: dict[str, ServiceStatus] = {}
        self._started_at = utcnow()
        self._last_probe: datetime | None = None

    @property
    def started_at(self) -> datetime:
        """When the application started (real monitoring uptime anchor)."""
        return self._started_at

    def uptime_text(self) -> str:
        """Application uptime derived from the real start timestamp."""
        return format_uptime(self._started_at)

    # ------------------------------------------------------------------
    # Status probing
    # ------------------------------------------------------------------
    def probe_all(self) -> dict[str, ServiceStatus]:
        """Probe every subsystem and return the fresh statuses."""
        statuses = {
            "application": self._probe_application(),
            "database": self._probe_database(),
            "nmap": self._probe_nmap(),
            "tshark": self._probe_tshark(),
            "capture": self._probe_capture(),
            "snort": self._probe_snort(),
        }
        with self._lock:
            for name, status in statuses.items():
                previous = self._statuses.get(name)
                self._statuses[name] = status
                if previous is None or previous.state is not status.state:
                    self._publish(status)
            self._last_probe = utcnow()

        for status in statuses.values():
            try:
                self._integration.upsert(status)
            except Exception:  # noqa: BLE001 - health must survive a DB outage
                LOGGER.debug("Could not persist status for %s", status.name, exc_info=True)
        return statuses

    def statuses(self) -> dict[str, ServiceStatus]:
        """Most recent statuses, probing once if none exist yet."""
        with self._lock:
            if self._statuses:
                return dict(self._statuses)
        return self.probe_all()

    def _publish(self, status: ServiceStatus) -> None:
        """Publish a subsystem state change."""
        event = (
            EventType.DATABASE_STATUS_CHANGED
            if status.name == "database"
            else EventType.SERVICE_STATUS_CHANGED
        )
        self._bus.publish(
            event,
            ServiceStatusPayload(
                service=status.name, state=status.state, detail=status.detail
            ),
        )

    def _probe_application(self) -> ServiceStatus:
        """The application itself is running if this code is executing."""
        return ServiceStatus(
            name="application",
            state=ServiceState.RUNNING,
            detail=f"AETHRA-SEC {APP_VERSION} - uptime {self.uptime_text()}",
            last_checked=utcnow(),
            last_success=utcnow(),
            metadata={"version": APP_VERSION, "python": platform.python_version()},
        )

    def _probe_database(self) -> ServiceStatus:
        """Ping MySQL and report the true connection state."""
        now = utcnow()
        try:
            connected = self._db.ping()
        except Exception as exc:  # noqa: BLE001
            return ServiceStatus(
                name="database",
                state=ServiceState.OFFLINE,
                detail=f"DATABASE OFFLINE - {exc}",
                last_checked=now,
                last_error=str(exc),
            )
        if not connected:
            return ServiceStatus(
                name="database",
                state=ServiceState.OFFLINE,
                detail=f"DATABASE OFFLINE - {self._db.last_error or 'no response'}",
                last_checked=now,
                last_error=self._db.last_error,
            )
        settings = self._settings.database
        return ServiceStatus(
            name="database",
            state=ServiceState.CONNECTED,
            detail=(
                f"Connected to {settings.host}:{settings.port}/{settings.database} "
                f"({self._db.server_version()})"
            ),
            last_checked=now,
            last_success=now,
            metadata=self._db.pool_status(),
        )

    def _probe_nmap(self) -> ServiceStatus:
        """Report whether Nmap can actually be executed."""
        now = utcnow()
        if self._probes.nmap is None:
            return ServiceStatus(
                name="nmap", state=ServiceState.UNKNOWN,
                detail="Nmap has not been probed.", last_checked=now,
            )
        availability = self._probes.nmap()
        if getattr(availability, "available", False):
            return ServiceStatus(
                name="nmap",
                state=ServiceState.AVAILABLE,
                detail=str(getattr(availability, "detail", "")),
                last_checked=now,
                last_success=now,
                metadata={
                    "executable": getattr(availability, "executable", ""),
                    "version": getattr(availability, "version", ""),
                },
            )
        return ServiceStatus(
            name="nmap",
            state=ServiceState.UNAVAILABLE,
            detail=str(getattr(availability, "detail", "Nmap is not available.")),
            last_checked=now,
            last_error=str(getattr(availability, "detail", "")),
        )

    def _probe_tshark(self) -> ServiceStatus:
        """Report whether TShark/PyShark can actually capture."""
        now = utcnow()
        if self._probes.tshark is None:
            return ServiceStatus(
                name="tshark", state=ServiceState.UNKNOWN,
                detail="TShark has not been probed.", last_checked=now,
            )
        availability = self._probes.tshark()
        if getattr(availability, "available", False):
            return ServiceStatus(
                name="tshark",
                state=ServiceState.AVAILABLE,
                detail=str(getattr(availability, "detail", "")),
                last_checked=now,
                last_success=now,
                metadata={
                    "executable": getattr(availability, "executable", ""),
                    "version": getattr(availability, "version", ""),
                    "pyshark": getattr(availability, "pyshark_available", False),
                },
            )
        return ServiceStatus(
            name="tshark",
            state=ServiceState.UNAVAILABLE,
            detail=str(getattr(availability, "detail", "TShark is not available.")),
            last_checked=now,
            last_error=str(getattr(availability, "detail", "")),
        )

    def _probe_capture(self) -> ServiceStatus:
        """Report the real capture state - CAPTURING only when it is."""
        now = utcnow()
        if self._probes.capture_status is None:
            return ServiceStatus(
                name="capture", state=ServiceState.UNKNOWN,
                detail="Capture has not been probed.", last_checked=now,
            )
        stats = self._probes.capture_status()
        if getattr(stats, "is_running", False):
            return ServiceStatus(
                name="capture",
                state=ServiceState.CAPTURING,
                detail=(
                    f"Capturing on '{stats.interface}' - {stats.total_packets:,} "
                    f"packet(s), {stats.dropped:,} dropped"
                ),
                last_checked=now,
                last_success=now,
                metadata={
                    "interface": stats.interface,
                    "packets": stats.total_packets,
                    "dropped": stats.dropped,
                    "queue_depth": stats.queue_depth,
                    "last_packet_at": stats.last_packet_at,
                },
            )
        error = getattr(stats, "last_error", "")
        return ServiceStatus(
            name="capture",
            state=ServiceState.ERROR if error else ServiceState.STOPPED,
            detail=error or "PACKET CAPTURE STOPPED - no interface is being monitored.",
            last_checked=now,
            last_error=error,
            metadata={"interface": getattr(stats, "interface", "")},
        )

    def _probe_snort(self) -> ServiceStatus:
        """Report the real Snort ingest state."""
        now = utcnow()
        if self._probes.snort_status is None:
            return ServiceStatus(
                name="snort", state=ServiceState.UNKNOWN,
                detail="Snort has not been probed.", last_checked=now,
            )
        status = self._probes.snort_status()
        if getattr(status, "is_connected", False):
            return ServiceStatus(
                name="snort",
                state=ServiceState.RUNNING,
                detail=(
                    f"{status.detail or 'Alert ingest active'} - "
                    f"{status.alerts_received:,} alert(s) received"
                ),
                last_checked=now,
                last_success=now,
                metadata={
                    "transport": status.transport,
                    "endpoint": status.endpoint,
                    "alerts_received": status.alerts_received,
                    "parse_failures": status.parse_failures,
                    "last_alert_at": status.last_alert_at,
                },
            )
        disabled = getattr(status, "transport", "disabled") == "disabled"
        return ServiceStatus(
            name="snort",
            state=ServiceState.DISABLED if disabled else ServiceState.OFFLINE,
            detail=status.detail or "Snort unavailable.",
            last_checked=now,
            last_error=status.last_error,
            metadata={"transport": status.transport, "endpoint": status.endpoint},
        )

    # ------------------------------------------------------------------
    # Diagnostics page (§71)
    # ------------------------------------------------------------------
    def run_diagnostics(self) -> DiagnosticsReport:
        """Run every diagnostic check and report PASS / WARNING / FAIL."""
        now = utcnow()
        checks: list[DiagnosticCheck] = []

        def add(
            name: str,
            category: str,
            result: CheckResult,
            summary: str,
            detail: str = "",
            remedy: str = "",
        ) -> None:
            checks.append(
                DiagnosticCheck(
                    name=name, category=category, result=result, summary=summary,
                    detail=detail, remedy=remedy, checked_at=now,
                )
            )

        # --- Python environment -----------------------------------------
        version = sys.version_info
        add(
            "Python runtime",
            "environment",
            CheckResult.PASS if version >= (3, 10) else CheckResult.FAIL,
            f"Python {platform.python_version()} on {platform.system()} {platform.release()}",
            detail=sys.executable,
            remedy="" if version >= (3, 10) else "AETHRA-SEC requires Python 3.10 or newer.",
        )
        self._check_dependencies(add)

        # --- Configuration ----------------------------------------------
        env_file = loaded_env_file()
        add(
            "Configuration file",
            "configuration",
            CheckResult.PASS if env_file else CheckResult.WARNING,
            f"Loaded {env_file}" if env_file else "No .env file found; defaults are in use.",
            detail=(
                "Non-secret AETHRA_* variables: "
                + ", ".join(f"{k}={v}" for k, v in list(describe_environment().items())[:12])
            ),
            remedy="" if env_file else "Copy .env.example to .env and set your values.",
        )
        invalid = self._settings.authorization.invalid_networks
        add(
            "Authorisation boundary",
            "configuration",
            CheckResult.WARNING if invalid or self._settings.authorization.allow_public else CheckResult.PASS,
            (
                "Public targets ENABLED"
                if self._settings.authorization.allow_public
                else f"{len(self._settings.authorization.parsed_networks)} authorised network(s)"
            ),
            detail=", ".join(str(n) for n in self._settings.authorization.parsed_networks),
            remedy=(
                f"These entries could not be parsed and are ignored: {', '.join(invalid)}"
                if invalid
                else (
                    "AETHRA_ALLOW_PUBLIC_TARGETS is true. Only leave this "
                    "enabled if you are authorised to assess public addresses."
                    if self._settings.authorization.allow_public
                    else ""
                )
            ),
        )

        # --- Database ----------------------------------------------------
        db_status = self._probe_database()
        add(
            "MySQL connection",
            "database",
            CheckResult.PASS if db_status.is_healthy else CheckResult.FAIL,
            db_status.detail,
            detail=str(db_status.metadata),
            remedy=(
                ""
                if db_status.is_healthy
                else (
                    "Check that the MySQL service is running and that "
                    "AETHRA_DB_* values in .env are correct."
                )
            ),
        )
        if db_status.is_healthy:
            ok, detail = verify_schema(self._db)
            add(
                "Database schema",
                "database",
                CheckResult.PASS if ok else CheckResult.FAIL,
                detail,
                detail=f"Required version {LATEST_VERSION}, found {current_version(self._db)}",
                remedy="" if ok else "Run: python scripts/init_db.py",
            )
            size = self._db.database_size_bytes()
            add(
                "Database size",
                "database",
                CheckResult.PASS,
                f"{size / (1024 * 1024):.1f} MB on disk",
                detail="Retention settings control growth; see the Settings screen.",
            )

        # --- External tools ----------------------------------------------
        for status, remedy in (
            (
                self._probe_nmap(),
                "Install Nmap from https://nmap.org/download and set "
                "AETHRA_NMAP_PATH if it is not on PATH.",
            ),
            (
                self._probe_tshark(),
                "Install Wireshark (including TShark and Npcap on Windows) and "
                "set AETHRA_TSHARK_PATH if it is not on PATH.",
            ),
        ):
            add(
                f"{status.name.upper()} availability",
                "tools",
                CheckResult.PASS if status.is_healthy else CheckResult.FAIL,
                status.detail,
                detail=str(status.metadata),
                remedy="" if status.is_healthy else remedy,
            )

        if self._probes.snort_executable is not None:
            found, detail = self._probes.snort_executable()
            add(
                "Snort executable",
                "tools",
                CheckResult.PASS if found else CheckResult.WARNING,
                detail if found else "Snort executable not found",
                detail=detail,
                remedy=(
                    ""
                    if found
                    else (
                        "AETHRA-SEC does not start Snort. Install and run the "
                        "sensor separately, then point AETHRA_SNORT_TRANSPORT "
                        "at its alert output."
                    )
                ),
            )

        snort_status = self._probe_snort()
        add(
            "Snort alert ingest",
            "detection",
            CheckResult.PASS
            if snort_status.is_healthy
            else CheckResult.WARNING
            if snort_status.state is ServiceState.DISABLED
            else CheckResult.FAIL,
            snort_status.detail,
            detail=str(snort_status.metadata),
            remedy=(
                ""
                if snort_status.is_healthy
                else "See docs/SNORT_INTEGRATION.md for transport configuration."
            ),
        )

        # --- Capture -----------------------------------------------------
        capture_status = self._probe_capture()
        add(
            "Packet capture",
            "monitoring",
            CheckResult.PASS
            if capture_status.state is ServiceState.CAPTURING
            else CheckResult.WARNING,
            capture_status.detail,
            detail=str(capture_status.metadata),
            remedy=(
                ""
                if capture_status.state is ServiceState.CAPTURING
                else "Select an interface on the Network Monitoring screen and start capture."
            ),
        )
        add(
            "Capture privileges",
            "monitoring",
            CheckResult.PASS if self._has_capture_privilege() else CheckResult.WARNING,
            (
                "Running with raw-socket privileges"
                if self._has_capture_privilege()
                else "Not running elevated"
            ),
            detail=f"Platform: {platform.system()}",
            remedy=(
                ""
                if self._has_capture_privilege()
                else (
                    "Capture and SYN/OS scan profiles may fail. Run as "
                    "Administrator (Windows) or grant dumpcap capabilities "
                    "(Linux)."
                )
            ),
        )
        add(
            "Selected interface",
            "monitoring",
            CheckResult.PASS if self._settings.capture.interface else CheckResult.WARNING,
            self._settings.capture.interface or "No interface configured",
            remedy=(
                ""
                if self._settings.capture.interface
                else "Choose a capture interface on the Settings screen."
            ),
        )

        # --- Storage -----------------------------------------------------
        for label, directory in (
            ("Log directory", self._settings.log_dir),
            ("Report directory", self._settings.report_dir),
        ):
            writable, message = self._check_directory(directory)
            add(
                label,
                "storage",
                CheckResult.PASS if writable else CheckResult.FAIL,
                message,
                detail=str(directory),
                remedy="" if writable else f"Grant write access to {directory}.",
            )
        add(*self._check_disk_space())

        # --- Security ----------------------------------------------------
        if self._probes.password_algorithm is not None:
            algorithm = self._probes.password_algorithm()
            add(
                "Password hashing",
                "security",
                CheckResult.PASS if "argon2" in algorithm.lower() else CheckResult.WARNING,
                algorithm,
                remedy=(
                    ""
                    if "argon2" in algorithm.lower()
                    else "Install argon2-cffi for the preferred hashing algorithm."
                ),
            )
        if self._probes.otp_status is not None:
            otp = self._probes.otp_status()
            add(
                "Two-factor authentication",
                "security",
                CheckResult.PASS if getattr(otp, "operational", False) else CheckResult.WARNING,
                str(getattr(otp, "detail", "Not configured")),
                remedy=(
                    ""
                    if getattr(otp, "operational", False)
                    else "Optional. Set AETHRA_OTP_ENABLED and the SMTP values in .env to enable."
                ),
            )
        if self._probes.mitigation_count is not None:
            count = self._probes.mitigation_count()
            add(
                "Mitigation knowledge base",
                "mitigation",
                CheckResult.PASS if count else CheckResult.WARNING,
                f"{count} active recommendation(s)",
                remedy="" if count else "Run the seeding step: python scripts/init_db.py",
            )

        return DiagnosticsReport(generated_at=now, checks=tuple(checks))

    @staticmethod
    def _check_dependencies(add: Callable[..., None]) -> None:
        """Verify that each Python dependency is importable."""
        modules = (
            ("mysql.connector", "mysql-connector-python", True),
            ("pyshark", "pyshark", True),
            ("nmap", "python-nmap", True),
            ("psutil", "psutil", True),
            ("argon2", "argon2-cffi", False),
            ("reportlab", "reportlab", False),
            ("openpyxl", "openpyxl", False),
            ("tkinter", "tkinter (python3-tk)", True),
        )
        for module_name, package, required in modules:
            try:
                __import__(module_name)
                add(
                    f"Dependency: {package}",
                    "environment",
                    CheckResult.PASS,
                    "Installed",
                )
            except Exception as exc:  # noqa: BLE001
                add(
                    f"Dependency: {package}",
                    "environment",
                    CheckResult.FAIL if required else CheckResult.WARNING,
                    f"Not available: {exc}",
                    remedy=f"Install it: pip install {package.split(' ')[0]}",
                )

    @staticmethod
    def _check_directory(directory: Path) -> tuple[bool, str]:
        """Check that a directory exists and is writable."""
        try:
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".aethra_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True, f"Writable: {directory}"
        except OSError as exc:
            return False, f"Not writable: {exc}"

    def _check_disk_space(self) -> tuple[str, str, CheckResult, str, str, str]:
        """Report free disk space on the volume holding the reports directory."""
        try:
            usage = shutil.disk_usage(
                self._settings.report_dir
                if self._settings.report_dir.exists()
                else Path.cwd()
            )
        except OSError as exc:
            return (
                "Disk space", "storage", CheckResult.WARNING,
                f"Could not determine free space: {exc}", "", "",
            )
        free_gb = usage.free / (1024 ** 3)
        percent_free = (usage.free / usage.total * 100) if usage.total else 0
        result = (
            CheckResult.FAIL
            if free_gb < 0.5
            else CheckResult.WARNING
            if free_gb < 5
            else CheckResult.PASS
        )
        return (
            "Disk space",
            "storage",
            result,
            f"{free_gb:.1f} GB free ({percent_free:.0f}%)",
            f"Total {usage.total / (1024 ** 3):.1f} GB",
            (
                "Free disk space or reduce retention settings; live capture "
                "writes continuously."
                if result is not CheckResult.PASS
                else ""
            ),
        )

    @staticmethod
    def _has_capture_privilege() -> bool:
        """Best-effort check for elevated/raw-socket capability."""
        if os.name == "nt":  # pragma: no cover - platform specific
            try:
                import ctypes

                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:  # noqa: BLE001
                return False
        try:
            return os.geteuid() == 0
        except AttributeError:  # pragma: no cover
            return False

    # ------------------------------------------------------------------
    # Runtime detail for the health screen
    # ------------------------------------------------------------------
    def runtime_details(self) -> dict[str, Any]:
        """Assorted real runtime figures shown on the System Health screen."""
        details: dict[str, Any] = {
            "application_version": APP_VERSION,
            "python_version": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()}",
            "started_at": self._started_at,
            "uptime": self.uptime_text(),
            "last_probe": self._last_probe,
            "database_pool": self._db.pool_status(),
            "log_directory": str(self._settings.log_dir),
            "report_directory": str(self._settings.report_dir),
            "env_file": str(loaded_env_file() or "(none)"),
        }
        if self._probes.event_bus_stats:
            details["event_bus"] = self._probes.event_bus_stats()
        if self._probes.scheduler_status:
            details["scheduler"] = self._probes.scheduler_status()
        if self._probes.correlation_stats:
            details["correlation"] = self._probes.correlation_stats()
        if self._probes.session_count:
            details["active_sessions"] = self._probes.session_count()
        if self._probes.capture_status:
            stats = self._probes.capture_status()
            details["capture"] = {
                "interface": stats.interface,
                "status": stats.status_text,
                "packets": stats.total_packets,
                "dropped": stats.dropped,
                "sampled_out": stats.sampled_out,
                "persisted_rows": stats.persisted_rows,
                "queue_depth": stats.queue_depth,
                "last_packet_at": stats.last_packet_at,
            }
        if self._probes.snort_status:
            status = self._probes.snort_status()
            details["snort"] = {
                "transport": status.transport,
                "endpoint": status.endpoint,
                "connected": status.is_connected,
                "alerts_received": status.alerts_received,
                "parse_failures": status.parse_failures,
                "last_alert_at": status.last_alert_at,
            }
        return details
