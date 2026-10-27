"""Application context: the single wiring point for every subsystem (§74).

Startup sequence:

1. load configuration and configure logging;
2. connect to MySQL, run migrations, seed static configuration;
3. build repositories, then the security layer, then the services;
4. start the background scheduler and (if configured) Snort ingest;
5. record an ``APPLICATION_STARTED`` audit entry.

Shutdown reverses it: stop capture, disconnect Snort, stop the scheduler, write
the shutdown audit entry, close the connection pool.

Every step is individually fault-tolerant. A missing Nmap binary, an offline
Snort sensor or an unwritable report directory does not prevent the application
from starting - it is reported on the System Health screen instead (§58).
"""

from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.config.settings import AppSettings, load_settings
from aethra_sec.core.errors import DatabaseUnavailableError, SchemaError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import EventType, ServiceStatusPayload
from aethra_sec.core.scheduler import PeriodicScheduler
from aethra_sec.core.session import Session, SessionManager
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.database.migrations import (
    ensure_database_exists,
    run_migrations,
    verify_schema,
)
from aethra_sec.database.repositories import (
    AlertRepository,
    AuditRepository,
    ErrorRepository,
    HostRepository,
    IncidentRepository,
    IntegrationStatusRepository,
    MitigationRepository,
    NotificationRepository,
    PasswordResetRepository,
    ReportRepository,
    ScanRepository,
    SettingsRepository,
    TrafficRepository,
    UserRepository,
)
from aethra_sec.database.seed import seed_all
from aethra_sec.models.enums import ServiceState
from aethra_sec.reports.builder import ReportBuilder
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.authentication import (
    AuthenticationPolicy,
    AuthenticationService,
)
from aethra_sec.security.password import PasswordHashService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services import (
    AssessmentQueueService,
    AudioAlertService,
    CorrelationService,
    DashboardService,
    EmailNotifier,
    HealthService,
    BackupService,
    HostService,
    LogService,
    MitigationService,
    NmapService,
    NotificationService,
    PacketCaptureService,
    PasswordRecoveryService,
    RecoveryPolicy,
    ReportService,
    RetentionService,
    SettingsService,
    SnortService,
    SubsystemProbes,
    UserService,
)
from aethra_sec.utils.logging import configure_logging, get_logger
from aethra_sec.version import APP_NAME, APP_VERSION

LOGGER = get_logger("core.application")


@dataclass
class StartupReport:
    """What happened during startup, for the first-run and health screens."""

    database_connected: bool = False
    schema_ok: bool = False
    schema_detail: str = ""
    migrations_applied: tuple[int, ...] = ()
    seeded: dict[str, int] | None = None
    snort_started: bool = False
    admin_exists: bool = False
    errors: tuple[str, str] = ()  # type: ignore[assignment]
    warnings: tuple[str, ...] = ()
    log_file: Path | None = None

    @property
    def is_usable(self) -> bool:
        """True when the application can actually be used."""
        return self.database_connected and self.schema_ok


class ApplicationContext:
    """Owns every long-lived object in the running application."""

    def __init__(self, settings: AppSettings | None = None) -> None:
        """Create the context. Nothing connects until :meth:`start`."""
        self.settings = settings or load_settings()
        self.event_bus = EventBus()
        self.scheduler = PeriodicScheduler()
        self.sessions = SessionManager()
        self.risk_engine = RiskEngine()
        self.passwords = PasswordHashService()
        # Email is a notification channel. It is constructed here, before the
        # database, precisely because nothing about signing in depends on it -
        # if it were part of authentication its failure would be a lockout.
        self.email = EmailNotifier(self.settings.smtp, audit=self._audit_email)
        self.startup = StartupReport()
        self._lock = threading.RLock()
        self._started = False
        self._db: DatabaseManager | None = None
        self.current_session: Session | None = None

        # Populated by _build_services().
        self.audit: AuditService | None = None
        self.access: AccessControl | None = None
        self.authentication: AuthenticationService | None = None
        self.settings_service: SettingsService | None = None
        self.users: UserService | None = None
        self.recovery: PasswordRecoveryService | None = None
        self.nmap: NmapService | None = None
        self.capture: PacketCaptureService | None = None
        self.snort: SnortService | None = None
        self.mitigation: MitigationService | None = None
        self.correlation: CorrelationService | None = None
        self.dashboard: DashboardService | None = None
        #: Declared here like every other service, so a start-up path
        #: that does not build it still leaves a defined attribute.
        self.assessment_queue: AssessmentQueueService | None = None
        self.hosts: HostService | None = None
        self.reports: ReportService | None = None
        self.logs: LogService | None = None
        self.notifications: NotificationService | None = None
        self.audio_alerts: AudioAlertService | None = None
        self.health: HealthService | None = None
        self.retention: RetentionService | None = None
        self.backup: BackupService | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def db(self) -> DatabaseManager:
        """The database manager.

        Raises:
            DatabaseUnavailableError: when :meth:`start` has not run.
        """
        if self._db is None:
            raise DatabaseUnavailableError(
                "The application context has not been started.",
                user_message="AETHRA-SEC is still starting. Please wait.",
            )
        return self._db

    @property
    def is_started(self) -> bool:
        """True once startup has completed."""
        return self._started

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------
    def start(self, *, run_migrations_on_start: bool = True) -> StartupReport:
        """Bring every subsystem up, reporting what succeeded and what did not."""
        with self._lock:
            if self._started:
                return self.startup

            report = StartupReport()
            report.log_file = configure_logging(
                self.settings.log_dir, self.settings.log_level
            )
            LOGGER.info("%s %s starting.", APP_NAME, APP_VERSION)

            warnings: list[str] = []
            errors: list[str] = []

            # --- Database ------------------------------------------------
            try:
                if run_migrations_on_start:
                    ensure_database_exists(self.settings.database)
                self._db = DatabaseManager(
                    self.settings.database, status_callback=self._on_database_status
                )
                report.database_connected = self._db.ping()
                if not report.database_connected:
                    errors.append(
                        f"DATABASE OFFLINE - {self._db.last_error or 'no response'}"
                    )
            except SchemaError as exc:
                errors.append(exc.user_message)
                self._db = DatabaseManager(self.settings.database)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Database initialisation failed: {exc}")
                self._db = DatabaseManager(self.settings.database)

            if report.database_connected and run_migrations_on_start:
                try:
                    report.migrations_applied = tuple(run_migrations(self.db))
                    report.seeded = seed_all(self.db)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"Schema setup failed: {exc}")

            if report.database_connected:
                report.schema_ok, report.schema_detail = verify_schema(self.db)
                if not report.schema_ok:
                    errors.append(report.schema_detail)

            # --- Services ------------------------------------------------
            try:
                self._build_services()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Service initialisation failed: {exc}")
                LOGGER.exception("Service initialisation failed.")

            # --- First-run state ------------------------------------------
            if report.database_connected and report.schema_ok:
                try:
                    report.admin_exists = (
                        UserRepository(self.db).count_admins(active_only=True) > 0
                    )
                    if not report.admin_exists:
                        warnings.append(
                            "No administrator account exists yet. Create one "
                            "with: python scripts/create_admin.py"
                        )
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"Could not check for an administrator: {exc}")

            # --- Optional subsystems --------------------------------------
            if self.snort is not None:
                try:
                    report.snort_started = self.snort.start()
                    if not report.snort_started and self.settings.snort.enabled:
                        warnings.append(self.snort.status().detail)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"Snort ingest could not start: {exc}")

            if self.nmap is not None and not self.nmap.availability().available:
                warnings.append(self.nmap.availability().detail)
            if self.capture is not None and not self.capture.availability().available:
                warnings.append(self.capture.availability().detail)

            self._register_jobs()
            self.scheduler.start()

            if self.audit is not None:
                self.audit.record(
                    AuditAction.APPLICATION_STARTED,
                    category=AuditCategory.SYSTEM,
                    detail=(
                        f"{APP_NAME} {APP_VERSION} started. "
                        f"Database: {'connected' if report.database_connected else 'OFFLINE'}; "
                        f"Snort ingest: {'running' if report.snort_started else 'not running'}."
                    ),
                )

            report.errors = tuple(errors)  # type: ignore[assignment]
            report.warnings = tuple(warnings)
            self.startup = report
            self._started = True
            LOGGER.info(
                "Startup complete: database=%s schema=%s snort=%s (%d warning(s), "
                "%d error(s))",
                report.database_connected, report.schema_ok, report.snort_started,
                len(warnings), len(errors),
            )
            return report

    def _build_services(self) -> None:
        """Construct every repository and service exactly once."""
        db = self.db

        user_repo = UserRepository(db)
        reset_repo = PasswordResetRepository(db)
        audit_repo = AuditRepository(db)
        host_repo = HostRepository(db)
        scan_repo = ScanRepository(db)
        traffic_repo = TrafficRepository(db)
        alert_repo = AlertRepository(db)
        incident_repo = IncidentRepository(db)
        mitigation_repo = MitigationRepository(db)
        settings_repo = SettingsRepository(db)
        integration_repo = IntegrationStatusRepository(db)
        notification_repo = NotificationRepository(db)
        error_repo = ErrorRepository(db)
        report_repo = ReportRepository(db)

        self.audit = AuditService(audit_repo)
        self.access = AccessControl(self.sessions, self.audit)
        self.settings_service = SettingsService(settings_repo, self.access, self.audit)

        self.authentication = AuthenticationService(
            user_repo, self.sessions, self.passwords, self.audit,
            self._authentication_policy(),
        )
        self.users = UserService(
            user_repo, self.passwords, self.authentication, self.audit, self.access
        )
        self.recovery = PasswordRecoveryService(
            reset_repo, user_repo, self.passwords, self.authentication,
            self.audit, self.access, self._recovery_policy(),
        )
        # Security policy edited on the Settings screen takes effect at once,
        # rather than at the next restart.
        self.settings_service.add_listener(self._on_setting_changed)

        self.nmap = NmapService(
            scan_repo, host_repo, self.event_bus, self.audit, self.access,
            self.settings.tools, self.settings.authorization, self.risk_engine,
            timeout_provider=lambda: self.settings_service.get_int(
                "assessment.scan_timeout_seconds", 1800
            ),
        )
        self.capture = PacketCaptureService(
            traffic_repo, host_repo, alert_repo, self.settings_service,
            self.event_bus, self.audit, self.access, self.settings.tools,
            self.settings.capture, self.settings.capture_dir,
        )
        self.snort = SnortService(
            alert_repo, host_repo, self.settings_service, self.event_bus,
            self.audit, self.access, self.settings.snort, self.settings.tools,
            self.risk_engine,
        )
        # New Snort alerts are graded on the §3.9.8 pps legend from the live
        # capture rate of their source, the same bands as a flood.
        self.snort.set_rate_probe(self.capture.rules.source_rate)
        self.mitigation = MitigationService(
            mitigation_repo, self.audit, self.access, incident_repo
        )
        self.correlation = CorrelationService(
            incident_repo, alert_repo, scan_repo, host_repo, self.mitigation,
            self.settings_service, self.event_bus, self.audit, self.access,
            self.risk_engine,
        )
        self.dashboard = DashboardService(
            traffic_repo, alert_repo, scan_repo, host_repo,
            audit_repo, self.access,
        )
        #: Automatic assessment of hosts the capture pipeline has observed.
        #: Bounded by the *monitored* authorised network: the subnet of the
        #: adapter capture is using, inside the configured authorised ranges
        #: Nmap also enforces. Not "any private address".
        self.assessment_queue = AssessmentQueueService(
            host_repo, self.nmap, self.settings_service,
            authorized_networks=self.settings.authorization.networks,
            scope_provider=self.assessment_scope,
            audit=self.audit,
            sessions=self.sessions,
        )
        self.dashboard.set_scope_provider(self.assessment_queue.scope)
        # Anything left SCANNING by a process that did not finish would never
        # be assessed again, so the claim is released at start-up.
        try:
            released = host_repo.reset_stuck_assessments()
            if released:
                LOGGER.info(
                    "Released %d host(s) left mid-assessment by a previous run.",
                    released,
                )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not release stuck assessments.", exc_info=True)

        # The same reasoning for the scan rows themselves: an Nmap child
        # cannot outlive the console, so anything still RUNNING at start-up
        # belongs to a run that died. Closing it keeps the scan list honest
        # about what is actually happening now.
        try:
            abandoned = scan_repo.reset_stuck_scans(
                "Interrupted: the console stopped before this scan finished."
            )
            if abandoned:
                LOGGER.warning(
                    "Closed %d scan(s) left running by a previous session: %s",
                    len(abandoned),
                    ", ".join(str(scan_id) for scan_id in abandoned),
                )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not close abandoned scans.", exc_info=True)

        self.hosts = HostService(
            host_repo, scan_repo, alert_repo, traffic_repo,
            self.audit, self.access,
        )
        self.reports = ReportService(
            ReportBuilder(scan_repo, alert_repo, incident_repo, host_repo,
                          traffic_repo, audit_repo, mitigation=self.mitigation),
            report_repo, self.event_bus, self.audit, self.access,
            self.settings.report_dir,
        )
        self.logs = LogService(
            audit_repo, error_repo, self.audit, self.access, self.settings.log_dir
        )
        self.notifications = NotificationService(
            notification_repo, error_repo, self.settings_service, self.event_bus
        )
        # Sign-in security alerts go through the notification service that
        # already exists rather than a parallel one. Attached here because the
        # authentication service is constructed earlier in the start-up order.
        self.authentication.attach_notifications(self.notifications)
        # Sounds for notifications the service above has already raised from
        # real evidence. It observes; it never detects, so it cannot originate
        # an event of its own.
        self.audio_alerts = AudioAlertService(self.settings_service)
        self.retention = RetentionService(
            db, traffic_repo, alert_repo, scan_repo, report_repo,
            self.settings_service, self.audit, self.access,
        )
        self.backup = BackupService(
            db, self.settings_service, self.audit, self.access,
            self.settings.report_dir / "backups", self.event_bus,
        )
        self.health = HealthService(
            db, integration_repo, self.settings, self.event_bus,
            SubsystemProbes(
                nmap=self.nmap.availability,
                tshark=self.capture.availability,
                capture_status=self.capture.statistics,
                # Traffic that approached or crossed a rule and raised no
                # detection, so an empty Alerts table can be told apart from
                # traffic that never came close.
                detection_near_misses=lambda: self.capture.rules.near_misses(),
                # What the capture point can SEE, counted from real frames.
                # Separate from capture_status on purpose: that reports whether
                # the sensor is running, this reports how much of the network
                # reaches it, and a healthy sensor on an ordinary switched port
                # still cannot observe traffic between two other machines.
                capture_visibility=lambda: self.capture.view.visibility.report(),
                interface_roles=self._interface_roles,
                snort_status=self.snort.status,
                snort_executable=self.snort.executable_status,
                correlation_stats=lambda: self.correlation.statistics
                if self.correlation
                else None,
                scheduler_status=self.scheduler.job_status,
                event_bus_stats=self.event_bus.statistics,
                session_count=self.sessions.count,
                password_algorithm=lambda: self.passwords.algorithm_description,
                smtp_status=self.email.statistics,
                mitigation_count=self.mitigation.count_active,
            ),
        )

    def assessment_scope(self) -> Any:
        """The automatic assessment scope for the interface being monitored.

        Read fresh on every call from the live adapter table, so it follows the
        machine if it moves network. The capture service's interface is the
        one currently or most recently monitored; before capture has run on
        anything, there is no monitored network and the scope is unavailable.
        """
        from aethra_sec.analytics.assessment_scope import resolve_scope

        interface = self.capture.interface if self.capture is not None else ""
        max_addresses = 1024
        if self.settings_service is not None:
            max_addresses = self.settings_service.get_int(
                "assessment.max_scope_addresses", 1024
            )
        return resolve_scope(
            interface,
            self.settings.authorization.networks,
            max_addresses=max_addresses,
        )

    def _audit_email(self, delivered: bool, recipient: str, detail: str) -> None:
        """Record a notification email's real outcome in the audit trail.

        The address is already masked by the notifier and the credential never
        reaches this point, so what is written says what happened without
        disclosing who or with what.
        """
        if self.audit is None:
            return
        self.audit.record(
            AuditAction.NOTIFICATION_EMAIL_SENT
            if delivered
            else AuditAction.NOTIFICATION_EMAIL_FAILED,
            category=AuditCategory.SYSTEM,
            result="SUCCESS" if delivered else "FAILURE",
            target_type="email",
            target_id=recipient,
            detail=detail,
        )

    def _authentication_policy(self) -> AuthenticationPolicy:
        """Read the authentication policy from stored settings."""
        settings = self.settings_service
        if settings is None:
            return AuthenticationPolicy()
        return AuthenticationPolicy(
            max_failed_logins=settings.get_int("security.max_failed_logins", 5),
            lockout_minutes=settings.get_int("security.lockout_minutes", 15),
            session_timeout_minutes=settings.get_int(
                "security.session_timeout_minutes", 60
            ),
            password_min_length=settings.get_int("security.password_min_length", 12),
        )

    def _recovery_policy(self) -> RecoveryPolicy:
        """Read the password recovery policy from stored settings."""
        settings = self.settings_service
        if settings is None:
            return RecoveryPolicy()
        return RecoveryPolicy(
            request_ttl_hours=settings.get_int("security.reset_request_ttl_hours", 24),
            code_ttl_minutes=settings.get_int("security.reset_code_ttl_minutes", 60),
            max_code_attempts=settings.get_int("security.reset_max_code_attempts", 5),
        )

    def _on_setting_changed(self, key: str, _value: Any) -> None:
        """Re-apply the security policy after an administrator edits it."""
        if not key.startswith("security."):
            return
        if self.authentication is not None:
            self.authentication.apply_policy(self._authentication_policy())
        if self.recovery is not None:
            self.recovery.apply_policy(self._recovery_policy())

    def _interface_roles(self) -> Any:
        """Resolve the configured interface roles against the adapters present.

        Roles are recorded by stable capture device name, so an adapter that
        Windows has renamed or renumbered still resolves. A configured device
        that is absent is reported as missing rather than quietly falling back
        to another adapter - falling back is how a sensor ends up monitoring
        the wrong segment while still reporting success.
        """
        from aethra_sec.analytics.interface_roles import (
            SETTING_MANAGEMENT,
            SETTING_MONITORING,
            SETTING_SPAN_DECLARED,
            resolve,
        )

        settings = self.settings_service
        monitoring = management = ""
        declared = False
        if settings is not None:
            monitoring = settings.get(SETTING_MONITORING, "") or ""
            management = settings.get(SETTING_MANAGEMENT, "") or ""
            declared = settings.get_bool(SETTING_SPAN_DECLARED, False)
        return resolve(
            self.capture.list_interfaces(),
            monitoring_device=str(monitoring),
            management_device=str(management),
            span_declared=declared,
        )

    def _register_jobs(self) -> None:
        """Register the periodic background jobs."""
        settings = self.settings_service
        health_interval = 15.0
        correlation_interval = 10.0
        retention_interval = 60.0
        if settings is not None:
            retention_interval = max(
                1, settings.get_int("retention.prune_interval_minutes", 60)
            )

        if self.health is not None:
            self.scheduler.add_job(
                "health-probe", health_interval, self._safe(self.health.probe_all),
                run_immediately=True,
            )
        if self.correlation is not None:
            self.scheduler.add_job(
                "correlation", correlation_interval,
                self._safe(self.correlation.correlate_recent),
            )
        if self.retention is not None:
            self.scheduler.add_job(
                "retention", retention_interval * 60.0, self._safe(self.retention.run)
            )
        if self.assessment_queue is not None:
            # Deliberately infrequent: the cycle only *selects* hosts, and each
            # selection may start a real Nmap process against a real machine.
            self.scheduler.add_job(
                "assessment-queue", 60.0,
                self._safe(self.assessment_queue.run_cycle),
            )
        if self.hosts is not None:
            # Capture cannot see a hostname, so an inventory it built has none
            # until something asks DNS. This is the something - when an
            # administrator has turned it on.
            resolve_interval = 5.0
            if settings is not None:
                resolve_interval = max(
                    1, settings.get_int("hosts.resolve_interval_minutes", 5)
                )
            self.scheduler.add_job(
                "hostname-resolve", resolve_interval * 60.0,
                self._safe(self._resolve_hostnames_if_enabled),
            )
            # A host that stops sending is marked OFFLINE after a configured
            # gap, without erasing its history or its assessments (§20). The
            # job runs every minute and the cutoff is read each time, so the
            # interval takes effect without re-registering the job.
            self.scheduler.add_job(
                "host-liveness", 60.0, self._safe(self._mark_stale_hosts_offline)
            )
        if self.backup is not None:
            # The job ticks every minute and the service decides whether a
            # backup is actually due, so changing the interval in Settings
            # takes effect without re-registering anything.
            self.scheduler.add_job(
                "database-backup", 60.0, self._safe(self.backup.run_scheduled)
            )
        if self.authentication is not None:
            self.scheduler.add_job(
                "session-purge", 60.0,
                self._safe(self.authentication.purge_expired_sessions),
            )
        if self.recovery is not None:
            # Approvals must stop working when their deadline passes, whether
            # or not an administrator has the queue open.
            self.scheduler.add_job(
                "recovery-expiry", 300.0, self._safe(self.recovery.expire_stale)
            )
        if self.settings_service is not None:
            self.scheduler.add_job(
                "settings-reload", 120.0, self._safe(self.settings_service.reload)
            )

    def _resolve_hostnames_if_enabled(self) -> None:
        """Resolve a batch of unnamed hosts, if the setting allows it."""
        if self.hosts is None or self.settings_service is None:
            return
        if not self.settings_service.get_bool("hosts.auto_resolve_hostnames", False):
            return
        self.hosts.resolve_pending()

    def _mark_stale_hosts_offline(self) -> None:
        """Mark hosts not seen within the configured window as OFFLINE (§20).

        History and assessments are retained; a host returns to UP the moment
        capture observes it transmitting again.
        """
        if self._db is None or self.settings_service is None:
            return
        from datetime import timedelta

        from aethra_sec.utils.timeutil import utcnow

        minutes = max(1, self.settings_service.get_int("hosts.offline_after_minutes", 15))
        cutoff = utcnow() - timedelta(minutes=minutes)
        host_repo = HostRepository(self.db)
        marked = host_repo.mark_stale_offline(cutoff)
        if marked:
            LOGGER.info("Marked %d host(s) OFFLINE (not seen in %d min).", marked, minutes)

    @staticmethod
    def _safe(action: Any) -> Any:
        """Wrap a job so its failure is logged rather than raised."""

        def runner() -> None:
            try:
                action()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Background job failed.")

        return runner

    def _on_database_status(self, connected: bool, detail: str) -> None:
        """Publish a database connectivity transition (§57)."""
        self.event_bus.publish(
            EventType.DATABASE_STATUS_CHANGED,
            ServiceStatusPayload(
                service="database",
                state=ServiceState.CONNECTED if connected else ServiceState.OFFLINE,
                detail=detail or ("Connected" if connected else "DATABASE OFFLINE"),
            ),
        )

    # ------------------------------------------------------------------
    # Session handling
    # ------------------------------------------------------------------
    def set_session(self, session: Session | None) -> None:
        """Record the signed-in session, and give automation its own.

        Automatic assessment runs *as somebody*: every scan it starts is
        audited against a session and refused without ``scan.run``. The queue
        stays idle until a session is attached, so this is where the loop from
        discovery to assessment is actually closed - without it the background
        cycle observes hosts, finds them due, and starts nothing.

        The queue gets a **separate** session rather than the operator's own.
        The operator's session idles out after ``security.session_timeout_minutes``
        (60 by default) while the reassessment cooldown is six hours, so by the
        time a host was due again the session had always expired: every scan
        was then refused with "Your session has expired" and the host was
        recorded as SKIPPED. Automation stopped roughly an hour after the
        operator stopped clicking, which is exactly the artificial timeout it
        must not have.

        The separate session keeps the interactive idle-logout intact - an
        unattended console still expires - while the background cycle refreshes
        only its own. It is still attributed to the operator who signed in, so
        nothing runs unattributed, and it is revoked below on sign-out.
        """
        previous = getattr(self, "_automation_session", None)
        if previous is not None and self.sessions is not None:
            # Never leave a live automation session behind for a user who has
            # gone: one operator's automation must not outlive their sign-in.
            self.sessions.invalidate(previous.token)
        self._automation_session = None

        self.current_session = session
        if self.assessment_queue is None:
            return
        if session is None or self.sessions is None:
            self.assessment_queue.attach_session(None)
            return
        self._automation_session = self.sessions.create(
            user_id=session.user_id,
            username=session.username,
            role=session.role,
            permissions=session.permissions,
            host_context="automatic-assessment",
        )
        self.assessment_queue.attach_session(self._automation_session)

    def sign_out(self, reason: str = "logout") -> None:
        """Sign the current session out."""
        if self.authentication and self.current_session:
            self.authentication.logout(self.current_session, reason)
        # Detach through set_session so the assessment queue stops attributing
        # automatic scans to a session that no longer exists.
        self.set_session(None)

    # ------------------------------------------------------------------
    # Shutdown (§74)
    # ------------------------------------------------------------------
    def _log_shutdown_origin(self, reason: str) -> None:
        """Record who asked for shutdown, from where, and what was still up."""
        caller = "unknown"
        try:
            # Skip this frame and shutdown() itself to name the real requester.
            stack = traceback.extract_stack()[:-2]
            trail = [
                f"{frame.filename.rsplit(chr(92), 1)[-1]}:{frame.lineno} {frame.name}"
                for frame in stack[-4:]
            ]
            caller = " <- ".join(reversed(trail))
        except Exception:  # noqa: BLE001 - diagnostics must not break shutdown
            pass

        capture_state = "no capture service"
        if self.capture is not None:
            try:
                capture_state = str(self.capture.state)
            except Exception:  # noqa: BLE001
                capture_state = "unreadable"

        LOGGER.info(
            "APPLICATION SHUTDOWN REQUEST reason=%s thread=%s capture=%s "
            "scheduler=%s source=%s",
            reason,
            threading.current_thread().name,
            capture_state,
            "running" if self.scheduler.is_running else "stopped",
            caller,
        )
        LOGGER.info("%s shutting down (%s).", APP_NAME, reason)

    def shutdown(self, reason: str = "normal shutdown") -> None:
        """Stop every subsystem safely and close the database pool.

        Shutdown is recorded with its origin, not just its reason. An
        application that closes on its own is only diagnosable if the log says
        who asked: a console interrupt, a worker, the operator's Exit button
        and the process-exit handler all arrive here, and they look identical
        once the subsystems start stopping.
        """
        with self._lock:
            if not self._started:
                return
            self._log_shutdown_origin(reason)

            for label, action in (
                ("capture", lambda: self.capture.shutdown() if self.capture else None),
                ("nmap", lambda: self.nmap.shutdown() if self.nmap else None),
                ("snort", lambda: self.snort.stop(reason) if self.snort else None),
                ("scheduler", self.scheduler.stop),
                (
                    "notifications",
                    lambda: self.notifications.close() if self.notifications else None,
                ),
                (
                    "audio alerts",
                    lambda: self.audio_alerts.close() if self.audio_alerts else None,
                ),
                ("email", self.email.close),
            ):
                try:
                    action()
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Error stopping %s during shutdown.", label)

            if self.audit is not None:
                try:
                    self.audit.record(
                        AuditAction.APPLICATION_STOPPED,
                        category=AuditCategory.SYSTEM,
                        detail=f"{APP_NAME} stopped ({reason}).",
                    )
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Could not write the shutdown audit record.")

            try:
                self.event_bus.clear()
            except Exception:  # noqa: BLE001
                pass

            if self._db is not None:
                try:
                    self._db.close()
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Error closing the database pool.")

            self._started = False
            LOGGER.info("Shutdown complete.")
