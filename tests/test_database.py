"""Database-backed tests: repositories, authentication, correlation, reports.

These run against a real MySQL-compatible server using an isolated test schema,
and are skipped when no server is reachable.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.core.errors import (
    AccountLockedError,
    AuthenticationError,
    PermissionDeniedError,
    ValidationFailedError,
)
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.session import SessionManager
from aethra_sec.database.connection import DatabaseManager
from aethra_sec.database.migrations import LATEST_VERSION, current_version, verify_schema
from aethra_sec.database.repositories import (
    AlertRepository,
    AuditRepository,
    HostRepository,
    IncidentRepository,
    MitigationRepository,
    ReportRepository,
    ScanRepository,
    SettingsRepository,
    TrafficRepository,
    UserRepository,
)
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import (
    AlertStatus,
    EvaluationLabel,
    EvidenceSource,
    ExportFormat,
    HostStatus,
    IncidentStatus,
    ReportType,
    RiskLevel,
    ScanStatus,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.scan import PortResult, Scan, ScanFinding, ScanHostResult
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.models.traffic import TrafficAggregate
from aethra_sec.reports.builder import ReportBuilder
from aethra_sec.security.audit import AuditService
from aethra_sec.security.authentication import (
    AuthenticationPolicy,
    AuthenticationService,
)
from aethra_sec.security.password import PasswordHashService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.correlation_service import CorrelationService, categorise_alert
from aethra_sec.services.mitigation_service import MitigationService
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.utils.timeutil import to_db, utcnow

pytestmark = pytest.mark.usefixtures("clean_db")


# ---------------------------------------------------------------------------
# Schema and seeding
# ---------------------------------------------------------------------------
class TestSchemaAndSeed:
    """Migrations create the schema; seeding adds configuration only (§102)."""

    def test_schema_is_current(self, db: DatabaseManager) -> None:
        """Every required table exists at the current version."""
        ok, detail = verify_schema(db)
        assert ok, detail
        assert current_version(db) == LATEST_VERSION

    def test_roles_and_permissions_are_seeded(self, db: DatabaseManager) -> None:
        """Both roles exist with their documented permission sets."""
        users = UserRepository(db)
        admin = users.get_role_by_name("ADMIN")
        analyst = users.get_role_by_name("USER")
        assert admin is not None and analyst is not None
        assert len(admin.permissions) > len(analyst.permissions)
        assert "user.manage" in admin.permissions
        assert "user.manage" not in analyst.permissions

    def test_mitigation_knowledge_is_seeded(self, db: DatabaseManager) -> None:
        """The knowledge base has an entry for every threat category."""
        repository = MitigationRepository(db)
        assert repository.count_active() > 0
        for category in ThreatCategory:
            assert repository.candidates_for_category(category), category

    def test_no_security_records_are_seeded(self, db: DatabaseManager) -> None:
        """A fresh installation contains no fabricated security data (§102)."""
        for table in (
            "hosts", "scans", "scan_findings", "snort_alerts",
            "traffic_anomalies", "incidents", "traffic_records",
            "traffic_aggregates", "notifications",
        ):
            count = db.query_value(f"SELECT COUNT(*) FROM `{table}`", default=0)
            assert int(count) == 0, f"{table} was seeded with data"

    def test_settings_are_seeded(self, db: DatabaseManager) -> None:
        """Tunable settings exist with their declared defaults."""
        settings = SettingsRepository(db).load_all()
        assert settings["detection.port_scan_distinct_ports"].typed_value() == 20
        assert settings["correlation.window_seconds"].typed_value() == 300
        assert settings["detection.enabled"].typed_value() is True


# ---------------------------------------------------------------------------
# Empty-state behaviour
# ---------------------------------------------------------------------------
class TestEmptyState:
    """Queries on an empty database return genuine zeros (§72)."""

    def test_every_counter_is_zero(self, db: DatabaseManager) -> None:
        """Nothing is invented to fill the dashboard."""
        assert HostRepository(db).count_all() == 0
        assert ScanRepository(db).count_scans() == 0
        assert ScanRepository(db).count_open_findings() == 0
        assert ScanRepository(db).count_open_ports() == 0
        assert AlertRepository(db).count_alerts() == 0
        assert IncidentRepository(db).count_open() == 0
        assert TrafficRepository(db).count_records() == 0
        assert TrafficRepository(db).total_packets_observed() == 0

    def test_searches_return_empty_lists(self, db: DatabaseManager) -> None:
        """Searches return nothing rather than sample rows."""
        since = utcnow() - timedelta(days=1)
        assert HostRepository(db).search() == []
        assert ScanRepository(db).search_scans() == []
        assert AlertRepository(db).search_alerts() == []
        assert AlertRepository(db).search_anomalies() == []
        assert IncidentRepository(db).search() == []
        assert TrafficRepository(db).top_sources(since) == []
        assert TrafficRepository(db).protocol_distribution(since) == []

    def test_timestamps_are_absent_not_invented(self, db: DatabaseManager) -> None:
        """"Last seen" style values stay ``None`` when nothing happened."""
        assert TrafficRepository(db).last_packet_time() is None
        assert AlertRepository(db).last_alert_time() is None
        assert ScanRepository(db).last_scan_time() is None
        assert AlertRepository(db).mean_detection_latency(utcnow() - timedelta(days=1)) is None


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------
class TestRepositories:
    """Round-trip persistence for each domain."""

    def test_host_upsert_and_observation(self, db: DatabaseManager) -> None:
        """Hosts are created once and updated on later observations."""
        hosts = HostRepository(db)
        now = utcnow()
        host_id = hosts.upsert_observed("192.168.1.25", observed_at=now, mac_address="aa:bb:cc:dd:ee:ff")
        assert host_id
        assert hosts.upsert_observed("192.168.1.25", observed_at=now) == host_id
        assert hosts.count_all() == 1

        hosts.update_identity(host_id, hostname="server.lab", os_name="Linux", status=HostStatus.UP)
        host = hosts.get(host_id)
        assert host is not None
        assert host.hostname == "server.lab"
        assert host.mac_address == "aa:bb:cc:dd:ee:ff"

        hosts.record_observation(
            host_id, interface="eth0", protocol="TCP", packets_sent=10,
            packets_received=4, bytes_sent=1000, bytes_received=400,
            first_seen=now, last_seen=now,
        )
        hosts.record_observation(
            host_id, interface="eth0", protocol="TCP", packets_sent=5,
            packets_received=1, bytes_sent=500, bytes_received=100,
            first_seen=now, last_seen=now,
        )
        observations = hosts.observations_for_host(host_id)
        assert len(observations) == 1
        assert observations[0].packets_sent == 15

    def test_trusted_hosts(self, db: DatabaseManager) -> None:
        """Trust is recorded and can be withdrawn."""
        hosts = HostRepository(db)
        hosts.upsert_observed("192.168.1.10", observed_at=utcnow())
        hosts.add_trusted("192.168.1.10", "Monitoring server", "Approved scanner", None)
        assert "192.168.1.10" in hosts.trusted_addresses()
        host = hosts.get_by_ip("192.168.1.10")
        assert host is not None and host.is_trusted
        hosts.remove_trusted("192.168.1.10")
        assert "192.168.1.10" not in hosts.trusted_addresses()

    def test_scan_results_round_trip(self, db: DatabaseManager) -> None:
        """A scan, its hosts, ports and findings persist and reload."""
        scans = ScanRepository(db)
        hosts = HostRepository(db)
        scan_id = scans.create_scan(
            Scan(target="192.168.1.25", profile="standard", status=ScanStatus.QUEUED,
                 created_at=utcnow())
        )
        scans.mark_running(scan_id, "nmap -sT -sV 192.168.1.25", "Nmap 7.94")
        host_id = hosts.upsert_observed("192.168.1.25", observed_at=utcnow())
        scan_host_id = scans.add_scan_host(
            scan_id,
            ScanHostResult(
                host_id=host_id, ip_address="192.168.1.25", hostname="server.lab",
                status=HostStatus.UP, os_name="Linux",
            ),
        )
        scans.add_ports(
            scan_host_id,
            [
                PortResult(port=22, protocol="tcp", state="open", service="ssh",
                           product="OpenSSH", version="8.9p1"),
                PortResult(port=80, protocol="tcp", state="closed", service="http"),
            ],
        )
        scans.add_findings(
            [
                ScanFinding(
                    scan_id=scan_id, scan_host_id=scan_host_id, host_id=host_id,
                    ip_address="192.168.1.25", port=22, protocol="tcp", service="ssh",
                    title="ssh exposed on 22/tcp", observation="Nmap reported 22/tcp OPEN",
                    concern="Review exposure.", risk_level=RiskLevel.MEDIUM,
                    risk_rationale="Risk MEDIUM (score 22).", evidence="state=open",
                )
            ]
        )
        scans.mark_completed(
            scan_id, hosts_total=1, hosts_up=1, open_ports=1, findings_count=1,
            duration_seconds=1.25,
        )

        loaded = scans.get_scan_with_results(scan_id)
        assert loaded is not None
        assert loaded.status is ScanStatus.COMPLETED
        assert loaded.duration_seconds == pytest.approx(1.25)
        assert len(loaded.hosts) == 1
        assert len(loaded.hosts[0].ports) == 2
        assert len(loaded.hosts[0].open_ports) == 1
        assert len(loaded.hosts[0].findings) == 1
        assert scans.count_open_findings() == 1
        assert scans.count_open_ports() == 1

    def test_scan_comparison(self, db: DatabaseManager) -> None:
        """Two scans of one target diff correctly (§45)."""
        scans = ScanRepository(db)

        def run(ports: list[tuple[int, str, str]]) -> int:
            scan_id = scans.create_scan(
                Scan(target="192.168.1.25", profile="standard", created_at=utcnow())
            )
            host_id = scans.add_scan_host(
                scan_id,
                ScanHostResult(ip_address="192.168.1.25", status=HostStatus.UP),
            )
            scans.add_ports(
                host_id,
                [
                    PortResult(port=port, protocol="tcp", state=state, service=service)
                    for port, state, service in ports
                ],
            )
            scans.mark_completed(
                scan_id, hosts_total=1, hosts_up=1, open_ports=len(ports),
                findings_count=0, duration_seconds=1.0,
            )
            return scan_id

        baseline = run([(22, "open", "ssh"), (80, "open", "http")])
        current = run([(22, "open", "ssh"), (80, "closed", "http"), (443, "open", "https")])

        comparison = scans.compare_scans(baseline, current)
        assert ("192.168.1.25", 443, "tcp") in comparison.newly_open_ports
        assert ("192.168.1.25", 80, "tcp") in comparison.closed_ports
        assert comparison.has_changes

    def test_alert_deduplication(self, db: DatabaseManager) -> None:
        """Repeat alerts fold into an occurrence count (§92)."""
        alerts = AlertRepository(db)
        now = utcnow()
        alert = SnortAlert(
            alert_time=now, received_at=now, generator_id=1, signature_id=2001219,
            revision=19, message="ET SCAN Potential SSH Scan", priority=2,
            severity=Severity.HIGH, protocol="TCP", src_ip="192.168.1.50",
            src_port=44321, dst_ip="192.168.1.25", dst_port=22,
            dedup_key="1:2001219:192.168.1.50:192.168.1.25:22", created_at=now,
        )
        alert_id = alerts.insert_alert(alert)
        duplicate = alerts.find_duplicate(alert.dedup_key, now - timedelta(minutes=5))
        assert duplicate == (alert_id, 1)
        alerts.increment_duplicate(alert_id, now)
        stored = alerts.get_alert(alert_id)
        assert stored is not None and stored.duplicate_count == 2
        assert alerts.count_alerts() == 1

    def test_alert_detection_latency_only_when_measurable(self, db: DatabaseManager) -> None:
        """Latency is computed only where the sensor supplied a timestamp (§81)."""
        alerts = AlertRepository(db)
        now = utcnow()
        alerts.insert_alert(
            SnortAlert(
                alert_time=now - timedelta(milliseconds=250), received_at=now,
                signature_id=1, message="timed", severity=Severity.MEDIUM,
                dedup_key="timed", created_at=now,
            )
        )
        alerts.insert_alert(
            SnortAlert(
                alert_time=None, received_at=now, time_source="aethra_receipt",
                signature_id=2, message="untimed", severity=Severity.MEDIUM,
                dedup_key="untimed", created_at=now,
            )
        )
        latency = alerts.mean_detection_latency(now - timedelta(hours=1))
        assert latency is not None
        assert 0.2 < latency < 0.3

    def test_anomaly_persistence(self, db: DatabaseManager) -> None:
        """Anomalies persist with their measured evidence."""
        alerts = AlertRepository(db)
        now = utcnow()
        anomaly = TrafficAnomaly(
            rule_id="RULE-PORT-SCAN", category=ThreatCategory.PORT_SCAN,
            title="Port scanning behaviour detected",
            observation="Contacted 25 ports in 10 seconds.",
            severity=Severity.MEDIUM, confidence=60, src_ip="192.168.1.50",
            dst_ip="192.168.1.25", protocol="TCP", observed_value=25.0,
            threshold_value=20.0, window_seconds=10, first_seen=now, last_seen=now,
            evidence={"distinct_ports": 25, "threshold_ports": 20},
            source=EvidenceSource.PYSHARK, created_at=now,
        )
        anomaly_id = alerts.insert_anomaly(anomaly)
        stored = alerts.get_anomaly(anomaly_id)
        assert stored is not None
        assert stored.observed_value == pytest.approx(25.0)
        assert stored.evidence["distinct_ports"] == 25
        assert stored.source is EvidenceSource.PYSHARK

    def test_traffic_batches_and_aggregates(self, db: DatabaseManager) -> None:
        """Batched packet rows and interval aggregates both persist."""
        traffic = TrafficRepository(db)
        now = utcnow()
        rows = [
            (
                to_db(now - timedelta(seconds=index)), "eth0", "192.168.1.50",
                "192.168.1.25", 40000 + index, 22, "TCP", "SSH", 74, 64, 2,
                "00:11:22:33:44:55", "66:77:88:99:aa:bb", "SYN",
            )
            for index in range(50)
        ]
        assert traffic.insert_batch(rows) == 50
        assert traffic.count_records() == 50

        traffic.insert_aggregate(
            TrafficAggregate(
                id=None, interval_start=now - timedelta(seconds=10), interval_end=now,
                interface="eth0", packet_count=50, byte_count=3700, tcp_packets=50,
                unique_sources=1, unique_destinations=1, packets_per_second=5.0,
                bytes_per_second=370.0,
            )
        )
        assert traffic.total_packets_observed() == 50
        distribution = traffic.protocol_distribution(now - timedelta(minutes=5))
        assert {p.protocol for p in distribution} == {"TCP"}
        assert traffic.top_sources(now - timedelta(minutes=5))[0].packets == 50

    def test_retention_pruning(self, db: DatabaseManager) -> None:
        """Aged packet metadata is pruned; recent rows are kept."""
        traffic = TrafficRepository(db)
        now = utcnow()
        old = [
            (to_db(now - timedelta(days=3)), "eth0", "10.0.0.1", "10.0.0.2",
             1, 2, "TCP", "", 60, 64, 2, "", "", "")
            for _ in range(10)
        ]
        recent = [
            (to_db(now), "eth0", "10.0.0.1", "10.0.0.2", 1, 2, "TCP", "",
             60, 64, 2, "", "", "")
            for _ in range(5)
        ]
        traffic.insert_batch(old + recent)
        removed = traffic.prune_records_before(now - timedelta(days=1))
        assert removed == 10
        assert traffic.count_records() == 5

    def test_sql_identifier_whitelist(self, db: DatabaseManager) -> None:
        """A non-whitelisted sort column falls back instead of injecting."""
        alerts = AlertRepository(db)
        assert alerts.search_alerts(sort_by="1; DROP TABLE users", limit=5) == []
        assert db.query_value("SELECT COUNT(*) FROM users", default=None) is not None


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
@pytest.fixture
def auth_stack(db: DatabaseManager):
    """Build the authentication stack against the test database."""
    users = UserRepository(db)
    audit = AuditService(AuditRepository(db))
    sessions = SessionManager(60)
    passwords = PasswordHashService(prefer_argon2=False)  # fast for tests
    policy = AuthenticationPolicy(max_failed_logins=3, lockout_minutes=15)
    service = AuthenticationService(users, sessions, passwords, audit, None, policy)
    access = AccessControl(sessions, audit)

    admin_role = users.get_role_by_name("ADMIN")
    user_role = users.get_role_by_name("USER")
    assert admin_role and user_role and admin_role.id and user_role.id

    admin_hash = passwords.hash("AdminPass!2026")
    users.create_user(
        username="admin", password_hash=admin_hash.hash,
        password_algorithm=admin_hash.algorithm, role_id=admin_role.id,
        full_name="Administrator",
    )
    analyst_hash = passwords.hash("AnalystPass!2026")
    users.create_user(
        username="analyst", password_hash=analyst_hash.hash,
        password_algorithm=analyst_hash.algorithm, role_id=user_role.id,
        full_name="Analyst",
    )
    return service, users, audit, access, sessions


class TestAuthentication:
    """Sign-in behaviour, including its failure modes (§6, §62)."""

    def test_successful_sign_in(self, auth_stack) -> None:
        """Correct credentials issue a session with resolved permissions."""
        service, _users, _audit, _access, _sessions = auth_stack
        result = service.login("admin", "AdminPass!2026")
        assert result.authenticated
        assert result.session is not None
        assert result.session.role == "ADMIN"
        assert result.session.has("user.manage")

    def test_wrong_password_and_unknown_user_are_indistinguishable(self, auth_stack) -> None:
        """Account existence is never disclosed (§62)."""
        service, *_ = auth_stack
        messages = set()
        for username, password in (("admin", "wrong"), ("nosuchuser", "wrong")):
            with pytest.raises(AuthenticationError) as exc:
                service.login(username, password)
            messages.add(exc.value.user_message)
        assert len(messages) == 1

    def test_lockout_after_repeated_failures(self, auth_stack) -> None:
        """Consecutive failures lock the account."""
        service, users, *_ = auth_stack
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                service.login("analyst", "wrong")
        with pytest.raises(AccountLockedError):
            service.login("analyst", "AnalystPass!2026")
        user = users.get_by_username("analyst")
        assert user is not None and user.is_locked

    def test_attempts_are_recorded(self, auth_stack) -> None:
        """Both successful and failed attempts are logged."""
        service, users, *_ = auth_stack
        service.login("admin", "AdminPass!2026")
        with pytest.raises(AuthenticationError):
            service.login("admin", "wrong")
        attempts = users.list_login_attempts(username="admin")
        assert len(attempts) == 2
        assert {a.successful for a in attempts} == {True, False}

    def test_sign_in_is_audited(self, auth_stack) -> None:
        """The audit trail records the sign-in and its chain stays valid."""
        service, _users, audit, *_ = auth_stack
        service.login("admin", "AdminPass!2026")
        records = audit.search(action="LOGIN_SUCCESS")
        assert records
        assert audit.verify().is_valid

    def test_logout_ends_the_session(self, auth_stack) -> None:
        """Signing out invalidates the session immediately."""
        service, _users, _audit, _access, sessions = auth_stack
        session = service.login("admin", "AdminPass!2026").session
        assert session is not None
        service.logout(session)
        assert sessions.get(session.token) is None

    def test_password_change_requires_the_current_password(self, auth_stack) -> None:
        """A password change verifies the existing credential first."""
        service, *_ = auth_stack
        session = service.login("admin", "AdminPass!2026").session
        assert session is not None
        with pytest.raises(AuthenticationError):
            service.change_own_password(session, "wrong", "BrandNewPass!2026")
        service.change_own_password(session, "AdminPass!2026", "BrandNewPass!2026")
        assert service.login("admin", "BrandNewPass!2026").authenticated

    def test_rbac_is_enforced_for_a_real_user(self, auth_stack) -> None:
        """An analyst session is refused an administrative permission."""
        service, _users, _audit, access, _sessions = auth_stack
        session = service.login("analyst", "AnalystPass!2026").session
        assert session is not None
        with pytest.raises(PermissionDeniedError):
            access.require(session, "user.manage")
        assert access.require(session, "dashboard.view")


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
@pytest.fixture
def correlation_stack(db: DatabaseManager):
    """Build the correlation stack against the test database."""
    audit = AuditService(AuditRepository(db))
    sessions = SessionManager(60)
    access = AccessControl(sessions, audit)
    settings = SettingsService(SettingsRepository(db), access, audit)
    mitigation = MitigationService(MitigationRepository(db), audit, access)
    bus = EventBus()
    service = CorrelationService(
        IncidentRepository(db), AlertRepository(db), ScanRepository(db),
        HostRepository(db), mitigation, settings, bus, audit, access, RiskEngine(),
    )
    return service, bus, mitigation


class TestCorrelation:
    """Incidents are built only from real evidence (§25, §78)."""

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("ET SCAN Potential SSH brute force login attempt", ThreatCategory.BRUTE_FORCE),
            ("ET TROJAN Command and Control activity", ThreatCategory.MALWARE_INDICATOR),
            ("SQL Injection attempt detected", ThreatCategory.SUSPICIOUS_PAYLOAD),
            ("ET SCAN Nmap portscan detected", ThreatCategory.PORT_SCAN),
            ("ICMP ping sweep detected", ThreatCategory.HOST_SWEEP),
            ("Something entirely unfamiliar", ThreatCategory.UNCLASSIFIED),
        ],
    )
    def test_alert_categorisation(self, message: str, expected: ThreatCategory) -> None:
        """Alerts are categorised from their own signature text."""
        alert = SnortAlert(message=message, severity=Severity.MEDIUM)
        assert categorise_alert(alert) is expected

    def test_single_source_incident_says_so(self, db: DatabaseManager, correlation_stack) -> None:
        """An incident with one contributing subsystem states that (§78)."""
        service, _bus, _mitigation = correlation_stack
        alerts = AlertRepository(db)
        now = utcnow()
        alerts.insert_alert(
            SnortAlert(
                alert_time=now, received_at=now, generator_id=1, signature_id=2001219,
                revision=19, message="ET SCAN Potential SSH brute force login attempt",
                priority=2, severity=Severity.HIGH, protocol="TCP",
                src_ip="192.168.1.50", src_port=44321, dst_ip="192.168.1.25",
                dst_port=22, dedup_key="one", created_at=now,
            )
        )
        assert service.correlate_recent() == 1
        incidents = IncidentRepository(db).search()
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.category is ThreatCategory.BRUTE_FORCE
        assert incident.source_label == "Snort only"
        assert not incident.is_multi_source
        assert "Evidence: Snort only." in incident.description

    def test_multi_source_incident(self, db: DatabaseManager, correlation_stack) -> None:
        """Nmap is credited only when a matching finding exists (§77)."""
        service, _bus, _mitigation = correlation_stack
        hosts = HostRepository(db)
        scans = ScanRepository(db)
        alerts = AlertRepository(db)
        now = utcnow()

        host_id = hosts.upsert_observed("192.168.1.25", observed_at=now, source=EvidenceSource.NMAP)
        scan_id = scans.create_scan(Scan(target="192.168.1.25", profile="standard", created_at=now))
        scan_host_id = scans.add_scan_host(
            scan_id, ScanHostResult(host_id=host_id, ip_address="192.168.1.25", status=HostStatus.UP)
        )
        scans.add_ports(scan_host_id, [PortResult(port=22, protocol="tcp", state="open", service="ssh")])
        scans.add_findings(
            [
                ScanFinding(
                    scan_id=scan_id, scan_host_id=scan_host_id, host_id=host_id,
                    ip_address="192.168.1.25", port=22, protocol="tcp", service="ssh",
                    title="ssh exposed on 22/tcp", observation="Nmap reported 22/tcp OPEN",
                    concern="Review.", risk_level=RiskLevel.MEDIUM,
                )
            ]
        )
        scans.mark_completed(scan_id, hosts_total=1, hosts_up=1, open_ports=1, findings_count=1, duration_seconds=1.0)

        alerts.insert_alert(
            SnortAlert(
                alert_time=now, received_at=now, generator_id=1, signature_id=2001219,
                revision=19, message="ET SCAN Potential SSH brute force login attempt",
                priority=2, severity=Severity.HIGH, protocol="TCP",
                src_ip="192.168.1.50", src_port=44321, dst_ip="192.168.1.25",
                dst_port=22, dedup_key="multi", created_at=now,
            )
        )
        alerts.insert_anomaly(
            TrafficAnomaly(
                rule_id="RULE-PORT-SCAN", category=ThreatCategory.BRUTE_FORCE,
                title="Repeated connection attempts",
                observation="Repeated attempts observed.", severity=Severity.MEDIUM,
                src_ip="192.168.1.50", dst_ip="192.168.1.25", dst_port=22,
                protocol="TCP", observed_value=30, threshold_value=20,
                window_seconds=10, first_seen=now, last_seen=now,
                evidence={"attempts": 30}, created_at=now,
            )
        )

        service.correlate_recent()
        incident = IncidentRepository(db).search()[0]
        assert incident.is_multi_source
        assert "Snort" in incident.source_label
        assert "PyShark" in incident.source_label
        assert "Nmap" in incident.source_label
        assert incident.finding_count >= 1
        assert incident.severity.rank >= Severity.HIGH.rank
        assert "Confirmed exposure" in incident.risk_rationale

    def test_related_evidence_is_grouped_not_duplicated(
        self, db: DatabaseManager, correlation_stack
    ) -> None:
        """Repeat evidence joins the existing incident (§26)."""
        service, _bus, _mitigation = correlation_stack
        alerts = AlertRepository(db)
        now = utcnow()
        for index in range(5):
            alerts.insert_alert(
                SnortAlert(
                    alert_time=now, received_at=now, generator_id=1,
                    signature_id=2001219, revision=19,
                    message="ET SCAN Potential SSH brute force login attempt",
                    priority=2, severity=Severity.HIGH, protocol="TCP",
                    src_ip="192.168.1.50", src_port=44000 + index,
                    dst_ip="192.168.1.25", dst_port=22,
                    dedup_key=f"group-{index}", created_at=now,
                )
            )
        service.correlate_recent()
        incidents = IncidentRepository(db).search()
        assert len(incidents) == 1
        assert incidents[0].snort_alert_count == 5

    def test_different_sources_create_separate_incidents(
        self, db: DatabaseManager, correlation_stack
    ) -> None:
        """Unrelated evidence is not merged."""
        service, _bus, _mitigation = correlation_stack
        alerts = AlertRepository(db)
        now = utcnow()
        for source in ("192.168.1.50", "192.168.1.51"):
            alerts.insert_alert(
                SnortAlert(
                    alert_time=now, received_at=now, generator_id=1,
                    signature_id=2001219, revision=19,
                    message="ET SCAN Potential SSH brute force login attempt",
                    priority=2, severity=Severity.HIGH, protocol="TCP",
                    src_ip=source, src_port=44321, dst_ip="192.168.1.25",
                    dst_port=22, dedup_key=source, created_at=now,
                )
            )
        service.correlate_recent()
        assert len(IncidentRepository(db).search()) == 2

    def test_mitigation_is_attached(self, db: DatabaseManager, correlation_stack) -> None:
        """A matching recommendation is bound to the incident (§29)."""
        service, _bus, mitigation = correlation_stack
        alerts = AlertRepository(db)
        now = utcnow()
        alerts.insert_alert(
            SnortAlert(
                alert_time=now, received_at=now, generator_id=1, signature_id=2001219,
                revision=19, message="ET SCAN Potential SSH brute force login attempt",
                priority=2, severity=Severity.HIGH, protocol="TCP",
                src_ip="192.168.1.50", dst_ip="192.168.1.25", dst_port=22,
                dedup_key="mit", created_at=now,
            )
        )
        service.correlate_recent()
        incident = IncidentRepository(db).search()[0]
        assert incident.mitigation_id is not None
        advice = mitigation.advice_for_incident(incident, ("evidence line",))
        assert advice is not None
        assert advice.recommendation.code == "MIT-BRUTE-FORCE"
        text = advice.as_text()
        assert "IMMEDIATE RECOMMENDED ACTION" in text
        assert "does not apply mitigations automatically" in text

    def test_incident_lifecycle(self, db: DatabaseManager, correlation_stack) -> None:
        """Status changes are recorded and close the incident (§94)."""
        service, _bus, _mitigation = correlation_stack
        alerts = AlertRepository(db)
        incidents = IncidentRepository(db)
        now = utcnow()
        alerts.insert_alert(
            SnortAlert(
                alert_time=now, received_at=now, signature_id=1, message="Test alert",
                severity=Severity.MEDIUM, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                dedup_key="life", created_at=now,
            )
        )
        service.correlate_recent()
        incident = incidents.search()[0]
        assert incident.id is not None
        assert incident.status is IncidentStatus.NEW
        assert incidents.count_open() == 1

        incidents.set_status(incident.id, IncidentStatus.RESOLVED, None)
        resolved = incidents.get(incident.id)
        assert resolved is not None
        assert resolved.status is IncidentStatus.RESOLVED
        assert resolved.resolved_at is not None
        assert incidents.count_open() == 0

    def test_evaluation_labels(self, db: DatabaseManager, correlation_stack) -> None:
        """Analyst classification is recorded, never assigned automatically."""
        service, _bus, _mitigation = correlation_stack
        alerts = AlertRepository(db)
        incidents = IncidentRepository(db)
        now = utcnow()
        alerts.insert_alert(
            SnortAlert(
                alert_time=now, received_at=now, signature_id=1, message="Test",
                severity=Severity.MEDIUM, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                dedup_key="eval", created_at=now,
            )
        )
        service.correlate_recent()
        incident = incidents.search()[0]
        assert incident.evaluation is EvaluationLabel.UNCLASSIFIED
        assert incident.id is not None
        incidents.set_evaluation(incident.id, EvaluationLabel.TRUE_POSITIVE, None)
        assert incidents.evaluation_counts().get("TRUE_POSITIVE") == 1


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
class TestReporting:
    """Reports contain stored records and nothing else (§115)."""

    @staticmethod
    def _builder(db: DatabaseManager) -> ReportBuilder:
        """Construct a report builder over the test database."""
        return ReportBuilder(
            ScanRepository(db), AlertRepository(db), IncidentRepository(db),
            HostRepository(db), TrafficRepository(db), AuditRepository(db),
        )

    def test_empty_report_says_so(self, db: DatabaseManager) -> None:
        """A report over an empty database reports zero records honestly."""
        document = self._builder(db).build(
            ReportType.SECURITY_ASSESSMENT, generated_by="tester"
        )
        assert document.total_records == 0
        assert not document.has_records
        assert "No records matched" in document.conclusion
        assert all(
            not section.has_rows
            for section in document.sections
            if not section.derived
        )

    def test_report_counts_match_stored_rows(self, db: DatabaseManager) -> None:
        """Section counts equal the number of rows actually stored."""
        alerts = AlertRepository(db)
        now = utcnow()
        for index in range(7):
            alerts.insert_alert(
                SnortAlert(
                    alert_time=now, received_at=now, signature_id=1000 + index,
                    message=f"Alert {index}", severity=Severity.HIGH,
                    priority=2, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                    dedup_key=f"report-{index}", created_at=now,
                )
            )
        document = self._builder(db).build(ReportType.IDS_ALERT, generated_by="tester")
        section = next(s for s in document.sections if s.title == "IDS alerts")
        assert section.row_count == 7
        assert document.record_counts["IDS alerts"] == 7

    @pytest.mark.parametrize("export_format", list(ExportFormat))
    def test_every_format_writes_a_file(
        self, db: DatabaseManager, tmp_path, export_format: ExportFormat
    ) -> None:
        """CSV, Excel and PDF all produce a non-trivial file."""
        from aethra_sec.reports.writers import write_csv, write_excel, write_pdf

        alerts = AlertRepository(db)
        now = utcnow()
        alerts.insert_alert(
            SnortAlert(
                alert_time=now, received_at=now, signature_id=1, message="Alert",
                severity=Severity.HIGH, priority=2, src_ip="10.0.0.1",
                dst_ip="10.0.0.2", dedup_key="fmt", created_at=now,
            )
        )
        document = self._builder(db).build(ReportType.IDS_ALERT, generated_by="tester")
        writer = {
            ExportFormat.CSV: write_csv,
            ExportFormat.XLSX: write_excel,
            ExportFormat.PDF: write_pdf,
        }[export_format]
        target = tmp_path / f"report{export_format.extension}"
        writer(document, target)
        assert target.exists()
        assert target.stat().st_size > 500

    def test_report_metadata_is_auditable(self, db: DatabaseManager) -> None:
        """A report names who generated it, when, and over what range (§95)."""
        document = self._builder(db).build(
            ReportType.EXECUTIVE_SUMMARY, generated_by="analyst",
            scope="Lab subnet 192.168.1.0/24",
        )
        metadata = dict(document.metadata_rows())
        assert metadata["Generated by"] == "analyst"
        assert metadata["Scope"] == "Lab subnet 192.168.1.0/24"
        assert metadata["Period start"] and metadata["Period end"]

    def test_report_record_is_stored(self, db: DatabaseManager) -> None:
        """Generated reports are recorded for later audit."""
        from aethra_sec.models.system import ReportRecord

        repository = ReportRepository(db)
        repository.record(
            ReportRecord(
                report_type=ReportType.IDS_ALERT, title="IDS Alert Report",
                export_format=ExportFormat.CSV, file_path="/tmp/report.csv",
                period_start=utcnow() - timedelta(days=1), period_end=utcnow(),
                scope="All", record_counts={"IDS alerts": 3},
                generated_at=utcnow(), file_size_bytes=1024,
            )
        )
        stored = repository.list_recent()
        assert len(stored) == 1
        assert stored[0].record_counts == {"IDS alerts": 3}
        assert stored[0].has_records


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class TestSettingsService:
    """Threshold changes are validated, persisted and audited (§91)."""

    @staticmethod
    def _service(db: DatabaseManager):
        """Build a settings service with an admin session backed by a real user.

        The session carries a real ``users`` row because a stored setting
        records who changed it; a session for an account that does not exist
        could never occur in the application.
        """
        audit = AuditService(AuditRepository(db))
        sessions = SessionManager(60)
        access = AccessControl(sessions, audit)
        service = SettingsService(SettingsRepository(db), access, audit)
        from aethra_sec.core.permissions import PermissionSet

        users = UserRepository(db)
        passwords = PasswordHashService(prefer_argon2=False)
        admin_role = users.get_role_by_name("ADMIN")
        assert admin_role and admin_role.id
        hashed = passwords.hash("AdminPass!2026")
        user_id = users.create_user(
            username="admin", password_hash=hashed.hash,
            password_algorithm=hashed.algorithm, role_id=admin_role.id,
            full_name="Administrator",
        )
        session = sessions.create(
            user_id=user_id, username="admin", role="ADMIN",
            permissions=PermissionSet.for_role("ADMIN"),
        )
        return service, session, audit

    def test_change_is_persisted_and_audited(self, db: DatabaseManager) -> None:
        """A valid change is stored and recorded in the audit trail."""
        service, session, audit = self._service(db)
        service.set(session, "detection.port_scan_distinct_ports", 42)
        assert service.get_int("detection.port_scan_distinct_ports") == 42
        assert SettingsService(SettingsRepository(db)).get_int(
            "detection.port_scan_distinct_ports"
        ) == 42
        assert audit.search(action="SETTING_CHANGED")

    def test_range_is_enforced(self, db: DatabaseManager) -> None:
        """Out-of-range values are refused."""
        service, session, _audit = self._service(db)
        with pytest.raises(ValidationFailedError):
            service.set(session, "detection.port_scan_distinct_ports", 0)
        with pytest.raises(ValidationFailedError):
            service.set(session, "detection.port_scan_distinct_ports", 99999)

    def test_unknown_setting_refused(self, db: DatabaseManager) -> None:
        """Only declared settings can be written."""
        service, session, _audit = self._service(db)
        with pytest.raises(ValidationFailedError):
            service.set(session, "detection.not_a_real_setting", 1)

    def test_non_admin_is_refused(self, db: DatabaseManager) -> None:
        """A normal user cannot change settings."""
        from aethra_sec.core.permissions import PermissionSet

        audit = AuditService(AuditRepository(db))
        sessions = SessionManager(60)
        access = AccessControl(sessions, audit)
        service = SettingsService(SettingsRepository(db), access, audit)
        analyst = sessions.create(
            user_id=2, username="analyst", role="USER",
            permissions=PermissionSet.for_role("USER"),
        )
        with pytest.raises(PermissionDeniedError):
            service.set(analyst, "detection.port_scan_distinct_ports", 30)
