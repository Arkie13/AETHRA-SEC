"""The Threat Incidents screen is gone; IDS Alerts is the security event view.

Threat Incidents was a second view of the same security events the Alerts
screen already shows - a correlated group of the alerts and anomalies an
operator can already open, review and classify one by one. It was removed
rather than hidden, and these tests hold both halves of that:

* nothing in the interface leads to it - no sidebar entry, no badge, no
  palette result, no button, no dashboard tile, no report type - and an old
  link lands on Alerts instead of a broken page;
* everything Alerts does still works, and the one backend mechanism that
  genuinely needs incident records - the correlation engine binding
  detections to mitigation guidance - keeps running.

Historical incidents are kept. No migration drops or empties the table.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"


# ---------------------------------------------------------------------------
# The screen and every way into it
# ---------------------------------------------------------------------------
class TestTheScreenIsRemoved:
    def test_the_module_no_longer_exists(self) -> None:
        assert not (PACKAGE / "ui" / "screens" / "incidents.py").exists()

    def test_the_screens_package_does_not_export_it(self) -> None:
        import aethra_sec.ui.screens as screens

        assert "IncidentsScreen" not in screens.__all__
        assert not hasattr(screens, "IncidentsScreen")

    def test_the_security_section_is_alerts_and_mitigation(self) -> None:
        from aethra_sec.ui.app import NAV_GROUPS

        assert dict(NAV_GROUPS)["SECURITY"] == ("alerts", "mitigation")

    def test_no_navigation_entry_names_incidents(self) -> None:
        from aethra_sec.ui.app import NAVIGATION

        keys = [key for key, _label, _perm in NAVIGATION]
        labels = [label for _key, label, _perm in NAVIGATION]
        assert "incidents" not in keys
        assert not any("ncident" in label for label in labels)

    def test_every_navigation_entry_has_a_screen(self) -> None:
        """No sidebar item may lead to a screen that is not registered."""
        from aethra_sec.ui.app import NAV_GROUPS, NAVIGATION

        declared = {key for key, _label, _perm in NAVIGATION}
        grouped = {key for _title, keys in NAV_GROUPS for key in keys}
        assert grouped <= declared, f"orphaned group entries: {grouped - declared}"
        from aethra_sec.ui.app import MainWindow

        registry = MainWindow._screen_factories()
        assert "incidents" not in registry
        missing = declared - set(registry)
        assert not missing, f"in the sidebar with no screen: {sorted(missing)}"

    def test_the_sidebar_badge_is_not_computed(self) -> None:
        from aethra_sec.ui.app import BADGE_SOURCES

        assert "incidents" not in BADGE_SOURCES

    def test_search_does_not_advertise_incidents(self) -> None:
        from aethra_sec.ui.app import SEARCH_PLACEHOLDER

        assert "incident" not in SEARCH_PLACEHOLDER.lower()
        assert "alerts" in SEARCH_PLACEHOLDER.lower()


class TestOldLinksLandOnAlerts:
    """A stale link, a saved last screen or a bookmark must not break."""

    def test_the_retired_routes_redirect_to_alerts(self) -> None:
        """Both incident routes land on Alerts.

        Asserted on those two entries rather than on the whole map. The map
        is shared by every retired screen - Evaluation Runs was later added to
        it, pointing at Reports - and an equality check here would fail for a
        change that has nothing to do with incidents.
        """
        from aethra_sec.ui.app import RETIRED_SCREENS

        assert RETIRED_SCREENS["incidents"] == "alerts"
        assert RETIRED_SCREENS["incident_detail"] == "alerts"

    def test_navigate_applies_the_redirect_before_permission(self) -> None:
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow.navigate)
        redirect = source.index("RETIRED_SCREENS")
        permission = source.index("not in self._nav_buttons")
        assert redirect < permission, (
            "the redirect runs after the permission check, so an old link is "
            "refused instead of landing on Alerts"
        )

    def test_only_a_search_carries_over(self) -> None:
        """focus_incident means nothing on Alerts; a search still does."""
        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow.navigate)
        assert 'k == "search"' in source

    def test_alerts_accepts_the_search_it_is_handed(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        assert callable(getattr(AlertsScreen, "set_search", None))

    def test_no_screen_navigates_to_incidents(self) -> None:
        for path in (PACKAGE / "ui").rglob("*.py"):
            if "__pycache__" in path.parts or path.name == "app.py":
                continue
            code = path.read_text(encoding="utf-8")
            assert 'navigate("incidents"' not in code, path.name
            assert "navigate('incidents'" not in code, path.name


class TestNoIncidentSurfaceRemains:
    def test_alerts_has_no_open_incident_action(self) -> None:
        from aethra_sec.ui.screens.alerts import AlertsScreen

        assert not hasattr(AlertsScreen, "_open_incident")
        assert not hasattr(AlertsScreen, "_go_to_incident")
        source = (PACKAGE / "ui" / "screens" / "alerts.py").read_text(encoding="utf-8")
        assert "Open incident" not in source

    def test_the_mitigation_panel_offers_no_incident_link(self) -> None:
        source = (PACKAGE / "ui" / "widgets" / "mitigation_panel.py").read_text(
            encoding="utf-8"
        )
        assert "View incident" not in source
        assert "on_open_incident" not in source

    def test_hosts_offers_alerts_not_incidents(self) -> None:
        source = (PACKAGE / "ui" / "screens" / "hosts.py").read_text(encoding="utf-8")
        assert "Show incidents" not in source
        assert '"Show alerts"' in source

    def test_the_dashboard_has_no_incident_tile(self) -> None:
        from aethra_sec.ui.screens.dashboard import PERIOD_KPIS

        assert "incidents_new" not in PERIOD_KPIS
        source = (PACKAGE / "ui" / "screens" / "dashboard.py").read_text(
            encoding="utf-8"
        )
        assert '"Open incidents"' not in source
        assert '"Incidents created"' not in source

    def test_the_dashboard_timeline_plots_alerts(self) -> None:
        from aethra_sec.services.dashboard_service import DashboardService

        source = inspect.getsource(DashboardService)
        assert "self._incidents" not in source
        assert "search_alerts(start=start, end=end" in source

    def test_the_threat_incident_report_type_is_gone(self) -> None:
        from aethra_sec.models.enums import ReportType

        assert "THREAT_INCIDENT" not in {r.name for r in ReportType}
        assert not any("ncident" in r.label for r in ReportType)

    def test_no_incident_notification_is_raised(self) -> None:
        """The alert already notified; a second notice for its group duplicated it."""
        from aethra_sec.services import correlation_service, notification_service

        assert not hasattr(correlation_service.CorrelationService, "_notify")
        assert not hasattr(
            notification_service.NotificationService, "_from_incident"
        )

    def test_no_user_visible_string_mentions_incidents(self) -> None:
        """Docstrings and identifiers aside, nothing shown says "incident"."""
        import ast

        allowed = {"incidents", "incident_detail"}  # the redirect map keys
        offenders = []
        for path in sorted((PACKAGE / "ui").rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                    body = getattr(node, "body", [])
                    if body and isinstance(body[0], ast.Expr) and isinstance(
                        body[0].value, ast.Constant
                    ):
                        docstrings.add(id(body[0].value))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and id(node) not in docstrings
                    and "ncident" in node.value
                    and node.value not in allowed
                ):
                    offenders.append(f"{path.name}:{node.lineno}: {node.value[:60]!r}")
        # The System Health screen reports the correlation engine's own
        # counters by name; that engine still runs, so those are accurate.
        offenders = [o for o in offenders if not o.startswith("health.py")]
        assert not offenders, "\n".join(offenders)


# ---------------------------------------------------------------------------
# What must keep working
# ---------------------------------------------------------------------------
class TestAlertsRemainsTheSecurityEventView:
    def test_every_analyst_action_is_still_offered(self) -> None:
        """Removing the Incidents screen took no analyst action with it.

        The list is shorter than it was, because Acknowledge, Escalate and
        Benign/expected were later removed as unused - a separate, deliberate
        change. What this guards is unchanged: whatever the Alerts screen
        offers, it did not lose it to the Incidents removal.
        """
        source = (PACKAGE / "ui" / "screens" / "alerts.py").read_text(encoding="utf-8")
        for label in (
            "Details", "Mark reviewed", "True positive", "False positive",
            "Export",
        ):
            assert f'"{label}"' in source, f"{label} is no longer offered"

    def test_no_alert_action_creates_an_incident(self) -> None:
        """The invariant Escalate used to carry, now stated for every action.

        Escalate was the action that might plausibly have reached for an
        incident record, and this test used to pin it to a plain status
        change. The action is gone; the rule it stood for applies to all of
        them and is worth keeping.
        """
        source = (PACKAGE / "ui" / "screens" / "alerts.py").read_text(encoding="utf-8")
        for reach in ("IncidentRepository", "incidents.create", "Incident("):
            assert reach not in source, (
                f"an Alerts action reaches for {reach}"
            )

    def test_alerts_still_shows_mitigation_guidance(self) -> None:
        """Guidance reaches the analyst from Alerts, without the removed screen.

        The call moved from ``recommendation_for`` to ``match_for_alert``,
        which resolves the same knowledge base but also reports how it got
        there and keeps a lookup failure distinct from an unconfigured
        category. What this test guards is unchanged: Alerts is where the
        guidance is read.
        """
        source = (PACKAGE / "ui" / "screens" / "alerts.py").read_text(encoding="utf-8")
        assert "mitigation.match_for_alert" in source
        assert "MITIGATION RECOMMENDATION" in source

    def test_the_categoriser_alerts_rely_on_is_still_available(self) -> None:
        from aethra_sec.services.correlation_service import categorise_alert

        assert callable(categorise_alert)


class TestTheCorrelationBackendIsKept:
    """It binds detections to mitigation guidance; the Mitigation screen needs it."""

    def test_the_correlation_job_is_still_scheduled(self) -> None:
        source = (PACKAGE / "core" / "application.py").read_text(encoding="utf-8")
        assert '"correlation", correlation_interval' in source

    def test_mitigation_evidence_still_reads_the_bound_records(self) -> None:
        from aethra_sec.services.mitigation_service import MitigationService

        assert "for_mitigation" in inspect.getsource(MitigationService.evidence_for)

    def test_the_firewall_safety_guard_is_unchanged(self) -> None:
        """It refuses to propose a rule blocking the monitored host itself."""
        from aethra_sec.ui.widgets.mitigation_panel import build_firewall_proposal

        source = inspect.getsource(build_firewall_proposal)
        assert "affected_host_ip" in source
        assert "protected == source" in source

    def test_correlation_is_still_audited(self) -> None:
        from aethra_sec.services.correlation_service import CorrelationService

        source = inspect.getsource(CorrelationService)
        assert "AuditAction.INCIDENT_CREATED" in source


class TestHistoryIsPreserved:
    def test_no_migration_drops_or_empties_incidents(self) -> None:
        source = (PACKAGE / "database" / "migrations.py").read_text(encoding="utf-8")
        for statement in ("DROP TABLE incidents", "DROP TABLE IF EXISTS incidents",
                          "TRUNCATE incidents", "DELETE FROM incidents"):
            assert statement not in source

    def test_the_schema_still_declares_the_tables(self) -> None:
        from aethra_sec.database import schema

        text = " ".join(
            value for value in vars(schema).values() if isinstance(value, str)
        )
        for table in ("incidents", "incident_events", "incident_notes"):
            assert f"CREATE TABLE IF NOT EXISTS {table}" in text or (
                f"CREATE TABLE {table}" in text
            ), f"{table} is no longer created"


# ---------------------------------------------------------------------------
# Reports built from alerts, against the isolated test database
# ---------------------------------------------------------------------------
class TestReportsReadAlerts:
    def _builder(self, db):
        from aethra_sec.database.repositories import (
            AlertRepository, AuditRepository, HostRepository, IncidentRepository,
            MitigationRepository, ScanRepository, TrafficRepository,
        )
        from aethra_sec.reports.builder import ReportBuilder
        from aethra_sec.services.mitigation_service import MitigationService

        class _AllowAll:
            def require(self, *_a, **_k):
                return None

        class _Audit:
            def record(self, *_a, **_k):
                return None

        mitigation = MitigationService(
            MitigationRepository(db), _Audit(), _AllowAll()
        )
        return ReportBuilder(
            ScanRepository(db), AlertRepository(db), IncidentRepository(db),
            HostRepository(db), TrafficRepository(db), AuditRepository(db),
            mitigation=mitigation,
        ), AlertRepository(db)

    def test_the_mitigation_report_maps_real_alerts(self, clean_db) -> None:
        from datetime import timedelta

        from aethra_sec.models.alert import SnortAlert
        from aethra_sec.models.enums import ReportType, Severity
        from aethra_sec.utils.timeutil import utcnow

        builder, alerts = self._builder(clean_db)
        alerts.insert_alert(SnortAlert(
            alert_time=utcnow(), signature_id=2001219,
            message="ET SCAN Potential SSH Scan", severity=Severity.HIGH,
            priority=2, src_ip="192.168.1.50", dst_ip="192.168.1.10",
            dst_port=22, protocol="TCP",
        ))
        doc = builder.build(
            ReportType.MITIGATION,
            period_start=utcnow() - timedelta(hours=1), period_end=utcnow(),
        )
        titles = [section.title for section in doc.sections]
        assert "Alerts with mitigation guidance" in titles
        assert not any("ncident" in title for title in titles)
        highlights = dict(doc.highlights)
        mapped = int(highlights["Alerts with guidance"])
        unmapped = int(highlights["Alerts with no mapped guidance"])
        assert mapped + unmapped == 1, "the one stored alert was not accounted for"

    def test_an_empty_period_reports_nothing_rather_than_inventing(
        self, clean_db
    ) -> None:
        from datetime import timedelta

        from aethra_sec.models.enums import ReportType
        from aethra_sec.utils.timeutil import utcnow

        builder, _alerts = self._builder(clean_db)
        doc = builder.build(
            ReportType.MITIGATION,
            period_start=utcnow() - timedelta(hours=1), period_end=utcnow(),
        )
        assert dict(doc.highlights)["Alerts with guidance"] == "0"

    @pytest.mark.parametrize("report", ["EXECUTIVE_SUMMARY", "SECURITY_ASSESSMENT"])
    def test_summary_reports_carry_no_incident_section(self, clean_db, report) -> None:
        from datetime import timedelta

        from aethra_sec.models.enums import ReportType
        from aethra_sec.utils.timeutil import utcnow

        builder, _alerts = self._builder(clean_db)
        doc = builder.build(
            ReportType[report],
            period_start=utcnow() - timedelta(days=1), period_end=utcnow(),
        )
        assert not any("ncident" in section.title for section in doc.sections)
        assert not any("ncident" in label for label, _value in doc.highlights)


# ---------------------------------------------------------------------------
# The Alerts workflow, end to end through the real service, on the isolated
# test schema. Production alerts are never touched.
# ---------------------------------------------------------------------------
class TestTheAlertsWorkflowStillWorks:
    """Review, acknowledge, escalate and evaluate - each persisted and audited."""

    def _stack(self, db, app_settings):
        from aethra_sec.core.event_bus import EventBus
        from aethra_sec.core.session import PermissionSet, SessionManager
        from aethra_sec.database.repositories import (
            AlertRepository, AuditRepository, HostRepository, SettingsRepository,
        )
        from aethra_sec.security.audit import AuditService
        from aethra_sec.security.rbac import AccessControl
        from aethra_sec.services.settings_service import SettingsService
        from aethra_sec.services.snort_service import SnortService

        audit = AuditService(AuditRepository(db))
        sessions = SessionManager(60)
        access = AccessControl(sessions, audit)
        settings = SettingsService(SettingsRepository(db), access, audit)
        service = SnortService(
            AlertRepository(db), HostRepository(db), settings, EventBus(),
            audit, access, app_settings.snort, app_settings.tools,
        )
        # A real account, so the audit rows can reference it: the clean test
        # schema has roles but no users, and audit_logs.user_id is a foreign key.
        from aethra_sec.database.repositories import UserRepository
        from aethra_sec.security.password import PasswordHashService

        users = UserRepository(db)
        hashed = PasswordHashService().hash("test-fixture-not-a-real-password")
        user_id = users.create_user(
            username="alerts-workflow-analyst",
            password_hash=hashed.hash, password_algorithm=hashed.algorithm,
            role_id=users.get_role_by_name("USER").id,
        )
        session = sessions.create(
            user_id=user_id, username="alerts-workflow-analyst",
            role="USER",
            permissions=PermissionSet(
                {"alert.view", "alert.manage", "evaluation.classify"}
            ),
            host_context="test",
        )
        return service, AlertRepository(db), session

    def _alert(self, alerts):
        from aethra_sec.models.alert import SnortAlert
        from aethra_sec.models.enums import Severity
        from aethra_sec.utils.timeutil import utcnow

        return alerts.insert_alert(SnortAlert(
            alert_time=utcnow(), signature_id=2001219,
            message="test fixture: ET SCAN Potential SSH Scan",
            severity=Severity.HIGH, priority=2,
            src_ip="192.168.1.50", dst_ip="192.168.1.10", dst_port=22,
            protocol="TCP",
        ))

    def _audited(self, db, alert_id, action):
        return db.query_value(
            "SELECT COUNT(*) FROM audit_logs WHERE target_type = %s "
            "AND target_id = %s AND action = %s",
            ("alert", str(alert_id), action), default=0,
        )

    @pytest.mark.parametrize(
        "status", ["REVIEWED", "ACKNOWLEDGED", "ESCALATED"]
    )
    def test_a_status_change_is_stored_and_audited(
        self, clean_db, app_settings, status
    ) -> None:
        from aethra_sec.models.enums import AlertStatus

        service, alerts, session = self._stack(clean_db, app_settings)
        alert_id = self._alert(alerts)
        service.set_status(session, alert_id, AlertStatus[status])

        stored = clean_db.query_value(
            "SELECT status FROM snort_alerts WHERE id = %s", (alert_id,)
        )
        assert stored == status, f"{status} was not stored"
        assert self._audited(clean_db, alert_id, "ALERT_UPDATED") == 1, (
            f"setting {status} left no audit record"
        )

    def test_escalating_creates_no_incident(self, clean_db, app_settings) -> None:
        """Escalation is a status on the alert, never a second record."""
        from aethra_sec.models.enums import AlertStatus

        service, alerts, session = self._stack(clean_db, app_settings)
        alert_id = self._alert(alerts)
        before = clean_db.query_value("SELECT COUNT(*) FROM incidents", default=0)
        service.set_status(session, alert_id, AlertStatus.ESCALATED)
        after = clean_db.query_value("SELECT COUNT(*) FROM incidents", default=0)
        assert after == before

    @pytest.mark.parametrize(
        "label", ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_EXPECTED"]
    )
    def test_an_evaluation_is_stored_and_audited(
        self, clean_db, app_settings, label
    ) -> None:
        from aethra_sec.models.enums import EvaluationLabel

        service, alerts, session = self._stack(clean_db, app_settings)
        alert_id = self._alert(alerts)
        service.classify(session, alert_id, EvaluationLabel[label])

        stored = clean_db.query_value(
            "SELECT evaluation FROM snort_alerts WHERE id = %s", (alert_id,)
        )
        assert stored == label
        assert self._audited(clean_db, alert_id, "EVALUATION_RECORDED") == 1

    def test_the_alert_appears_in_the_alert_search(
        self, clean_db, app_settings
    ) -> None:
        """What the Alerts table loads is the stored row, unchanged."""
        service, alerts, session = self._stack(clean_db, app_settings)
        alert_id = self._alert(alerts)
        found = [a for a in service.search(session) if a.id == alert_id]
        assert len(found) == 1
        assert str(found[0].severity) == "HIGH"
        assert found[0].dst_port == 22
