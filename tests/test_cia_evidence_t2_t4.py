"""Evidence for manuscript §3.8.2: checklist items T2, T3 and T4.

T2  Confidentiality - who can open dashboards, alerts, scan results, logs,
    user management and settings: signed out, with a forged or ended or
    expired session, as a standard USER, and as an ADMIN.
T3  Integrity - protection of scan results from modification.
T4  Integrity - protection of alert records from modification.

Everything runs through the real service layer (``AccessControl.require`` is
the control the screens rely on) against the isolated TEST database
``aethra_sec_test``. Accounts and records are created for the test and
removed with it. Nothing touches the production database or the network.

Design guarantees are asserted. Behaviour the manuscript asks about but the
design does not guarantee - for example whether a change made outside the
application is noticed - is measured and written to the evidence files
without being asserted, so the result is recorded as it is.

Evidence: evaluation/test_plan/T2_T4_access_integrity/
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.core.errors import PermissionDeniedError, SessionExpiredError
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.permissions import USER_PERMISSIONS, Permission
from aethra_sec.core.session import SessionManager
from aethra_sec.database.repositories import (
    AlertRepository,
    AuditRepository,
    ErrorRepository,
    HostRepository,
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
    Severity,
    ThreatCategory,
)
from aethra_sec.models.scan import Scan, ScanFinding
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.security.audit import AuditService
from aethra_sec.security.authentication import AuthenticationService
from aethra_sec.security.password import PasswordHashService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.services.dashboard_service import DashboardService
from aethra_sec.services.log_service import LogService
from aethra_sec.services.nmap_service import NmapService
from aethra_sec.services.settings_service import SettingsService
from aethra_sec.services.snort_service import SnortService
from aethra_sec.services.user_service import UserService

OUT = Path(__file__).resolve().parents[1] / "evaluation" / "test_plan" / "T2_T4_access_integrity"
NOW = datetime.now(UTC)
PASSWORD = "T2-Evidence-Pass!2026"


# ---------------------------------------------------------------------------
# The application's services, wired as core/application.py wires them
# ---------------------------------------------------------------------------
@pytest.fixture
def system(clean_db, app_settings, tmp_path):  # noqa: ANN001, ANN201
    users = UserRepository(clean_db)
    sessions = SessionManager(60)
    passwords = PasswordHashService(prefer_argon2=False)
    audit = AuditService(AuditRepository(clean_db))
    access = AccessControl(sessions, audit)
    settings = SettingsService(SettingsRepository(clean_db), access, audit)
    auth = AuthenticationService(users, sessions, passwords, audit)
    alerts, scans, hosts = AlertRepository(clean_db), ScanRepository(clean_db), HostRepository(clean_db)
    s = type("System", (), {})()
    s.db, s.sessions, s.audit, s.access, s.settings = clean_db, sessions, audit, access, settings
    s.alerts, s.scans = alerts, scans
    s.users = UserService(users, passwords, auth, audit, access)
    s.snort = SnortService(alerts, hosts, settings, EventBus(), audit, access,
                           app_settings.snort, app_settings.tools, RiskEngine())
    s.nmap = NmapService(scans, hosts, EventBus(), audit, access, app_settings.tools,
                         app_settings.authorization, RiskEngine(), timeout_provider=lambda: 1800)
    s.dashboard = DashboardService(TrafficRepository(clean_db), alerts, scans, hosts,
                                   AuditRepository(clean_db), access)
    s.logs = LogService(AuditRepository(clean_db), ErrorRepository(clean_db), audit, access, tmp_path)

    # Two real accounts, signed in through the real authentication service.
    s.account = {}
    for name, role in (("t2_evidence_admin", "ADMIN"), ("t2_evidence_user", "USER")):
        role_row = users.get_role_by_name(role)
        hashed = passwords.hash(PASSWORD)
        user_id = users.create_user(username=name, password_hash=hashed.hash,
                                    password_algorithm=hashed.algorithm, role_id=role_row.id,
                                    full_name=f"T2 evidence {role}")
        s.account[role] = (user_id, auth.login(name, PASSWORD).session)

    # Records to read and to try to change. Labelled as test fixtures.
    s.alert_id = alerts.insert_alert(SnortAlert(
        alert_time=NOW, received_at=NOW, generator_id=1, signature_id=1000001, revision=1,
        message="TEST FIXTURE - not a real alert", priority=3, severity=Severity.LOW,
        protocol="ICMP", src_ip="10.98.20.1", dst_ip="10.98.20.2",
        dedup_key="1:1000001:10.98.20.1:10.98.20.2:", created_at=NOW))
    s.anomaly_id = alerts.insert_anomaly(TrafficAnomaly(
        rule_id="RULE-ICMP-RATE", category=ThreatCategory.ICMP_FLOOD,
        title="TEST FIXTURE - not a real detection", observation="fixture",
        why_it_matters="fixture", what_to_check="fixture", severity=Severity.LOW,
        confidence=60, src_ip="10.98.20.1", dst_ip="10.98.20.2", protocol="ICMP",
        observed_value=200.0, threshold_value=120.0, window_seconds=5,
        detected_at=NOW, first_seen=NOW - timedelta(seconds=5), last_seen=NOW,
        source=EvidenceSource.PYSHARK, created_at=NOW, evidence={"fixture": True}))
    s.scan_id = scans.create_scan(Scan(target="10.98.20.2", target_kind="host",
                                       profile="fixture", created_at=NOW))
    scans.add_findings([ScanFinding(scan_id=s.scan_id, ip_address="10.98.20.2", port=22,
                                    protocol="tcp", service="ssh",
                                    title="TEST FIXTURE - SSH service exposed",
                                    observation="22/tcp open ssh", evidence="fixture evidence")])
    s.finding_id = int(clean_db.query_value(
        "SELECT id FROM scan_findings WHERE scan_id = %s", (s.scan_id,)))
    return s


def _outcome(call) -> str:  # noqa: ANN001
    try:
        call()
    except SessionExpiredError:
        return "REFUSED - no valid session"
    except PermissionDeniedError:
        return "REFUSED - permission"
    except Exception as exc:  # noqa: BLE001 - recorded, then asserted against
        return f"ERROR - {type(exc).__name__}: {exc}"
    return "ALLOWED"


def _row(db, table: str, row_id: int) -> dict:  # noqa: ANN001
    return dict(db.query_one(f"SELECT * FROM {table} WHERE id = %s", (row_id,)))


def _audit_rows(db, **where) -> list[dict]:  # noqa: ANN001, ANN003
    clauses = " AND ".join(f"{k} = %s" for k in where) or "1=1"
    return db.query(f"SELECT * FROM audit_logs WHERE {clauses} ORDER BY id", tuple(where.values()))


def _write(name: str, payload) -> None:  # noqa: ANN001
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")


# ===========================================================================
# T2 - access to dashboards, alerts, scan results, logs and admin screens
# ===========================================================================
def test_t2_access_matrix(system) -> None:  # noqa: ANN001
    s = system
    actions = [
        ("Dashboard", "Open the dashboard", Permission.DASHBOARD_VIEW, lambda x: s.dashboard.snapshot(x)),
        ("Alerts", "List Snort alerts", Permission.ALERT_VIEW, lambda x: s.snort.search(x)),
        ("Alerts", "List AETHRA-SEC detections", Permission.ALERT_VIEW, lambda x: s.snort.search_anomalies(x)),
        ("Alerts", "Open an alert's detail", Permission.ALERT_VIEW, lambda x: s.snort.get(x, s.alert_id)),
        ("Assessments", "View scan history", Permission.SCAN_VIEW, lambda x: s.nmap.scan_history(x)),
        ("Assessments", "Open a scan", Permission.SCAN_VIEW, lambda x: s.nmap.get_scan(x, s.scan_id)),
        ("Assessments", "View findings", Permission.SCAN_VIEW, lambda x: s.nmap.findings(x)),
        ("Logs & Audit", "View the audit trail", Permission.LOG_VIEW, lambda x: s.logs.search(x)),
        ("Logs & Audit", "Verify log integrity", Permission.LOG_VERIFY, lambda x: s.logs.verify_integrity(x)),
        ("User Management", "List user accounts", Permission.USER_MANAGE, lambda x: s.users.list_users(x)),
        ("Settings", "Change a setting", Permission.SETTINGS_MANAGE,
         lambda x: s.settings.set(x, "notifications.min_severity", "MEDIUM")),
    ]
    admin_id, admin = s.account["ADMIN"]
    user_id, user = s.account["USER"]
    ended = s.sessions.create(user_id=admin_id, username="t2_evidence_admin", role="ADMIN",
                              permissions=admin.permissions)
    s.sessions.invalidate(ended.token)  # as after signing out
    expired = s.sessions.create(user_id=user_id, username="t2_evidence_user", role="USER",
                                permissions=user.permissions)
    expired.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    who = [
        ("Signed out (no session)", None, "none"),
        ("Forged session token", "forged-token-not-issued-by-aethra-sec", "none"),
        ("Session after sign-out", ended, "none"),
        ("Expired session", expired, "none"),
        ("Standard USER", user, "USER"),
        ("Administrator", admin, "ADMIN"),
    ]
    denied_before = len(_audit_rows(s.db, action="PERMISSION_DENIED", user_id=user_id))
    rows, mismatches = [], []
    for screen, action, permission, call in actions:
        for label, session, role in who:
            if role == "none":
                expected = "REFUSED - no valid session"
            elif role == "USER":
                expected = "ALLOWED" if permission in USER_PERMISSIONS else "REFUSED - permission"
            else:
                expected = "ALLOWED"
            actual = _outcome(lambda c=call, x=session: c(x))
            rows.append({"screen": screen, "action": action, "permission": permission,
                         "who": label, "expected": expected, "actual": actual,
                         "match": actual == expected})
            if actual != expected:
                mismatches.append(rows[-1])

    user_refusals = [r for r in rows if r["who"] == "Standard USER" and r["actual"] == "REFUSED - permission"]
    denied = _audit_rows(s.db, action="PERMISSION_DENIED", user_id=user_id)[denied_before:]
    audited = sorted({r["target_id"] for r in denied})
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "T2_access_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    _write("T2_summary.json", {
        "checked_on": datetime.now(UTC).isoformat(), "database": "aethra_sec_test (isolated)",
        "checks": len(rows), "matching_expected": len(rows) - len(mismatches),
        "mismatches": mismatches,
        "user_refusals": len(user_refusals),
        "user_refusals_written_to_audit_log": len(denied),
        "audited_permissions": audited,
        "refused_screens_for_USER": sorted({f"{r['screen']}: {r['action']}" for r in user_refusals}),
    })
    assert not mismatches, mismatches
    assert len(denied) == len(user_refusals)
    assert set(audited) == {r["permission"] for r in user_refusals}


# ===========================================================================
# T4 - alert records
# ===========================================================================
def test_t4_alert_records(system) -> None:  # noqa: ANN001
    s = system
    admin_id, admin = s.account["ADMIN"]
    _uid, user = s.account["USER"]
    attempts = [
        ("Change a Snort alert's status", Permission.ALERT_MANAGE,
         lambda x: s.snort.set_status(x, s.alert_id, AlertStatus.REVIEWED)),
        ("Classify a Snort alert", Permission.EVALUATION_CLASSIFY,
         lambda x: s.snort.classify(x, s.alert_id, EvaluationLabel.TRUE_POSITIVE)),
        ("Classify an AETHRA-SEC detection", Permission.EVALUATION_CLASSIFY,
         lambda x: s.snort.classify_anomaly(x, s.anomaly_id, EvaluationLabel.TRUE_POSITIVE)),
        ("Mark a detection reviewed", Permission.ALERT_MANAGE,
         lambda x: s.snort.review_anomaly(x, s.anomaly_id)),
    ]
    alert_before = _row(s.db, "snort_alerts", s.alert_id)
    anomaly_before = _row(s.db, "traffic_anomalies", s.anomaly_id)
    by_user = [{"action": a, "permission": p, "actual": _outcome(lambda c=c: c(user))}
               for a, p, c in attempts]
    unchanged_after_user = (_row(s.db, "snort_alerts", s.alert_id) == alert_before
                            and _row(s.db, "traffic_anomalies", s.anomaly_id) == anomaly_before)

    audit_before = len(_audit_rows(s.db, user_id=admin_id))
    review_state = {"before_admin": {k: _row(s.db, "traffic_anomalies", s.anomaly_id)[k]
                                     for k in ("reviewed_at", "reviewed_by", "evaluation")}}
    by_admin = []
    for a, p, c in attempts:
        by_admin.append({"action": a, "permission": p, "actual": _outcome(lambda c=c: c(admin))})
        by_admin[-1]["review_state_after"] = {
            k: _row(s.db, "traffic_anomalies", s.anomaly_id)[k]
            for k in ("reviewed_at", "reviewed_by", "evaluation")}
    admin_audit = _audit_rows(s.db, user_id=admin_id)[audit_before:]
    chain_after_admin = s.logs.verify_integrity(admin)
    alert_after = _row(s.db, "snort_alerts", s.alert_id)
    anomaly_after = _row(s.db, "traffic_anomalies", s.anomaly_id)
    evidence_fields = ("signature_id", "message", "src_ip", "dst_ip", "alert_time", "raw_alert")
    detection_fields = ("rule_id", "observed_value", "threshold_value", "first_seen", "last_seen", "evidence")

    # A change made OUTSIDE the application, straight in the (test) database.
    s.db.execute("UPDATE traffic_anomalies SET observed_value = 1.0 WHERE id = %s", (s.anomaly_id,))
    s.db.execute("UPDATE snort_alerts SET message = 'changed outside the application' WHERE id = %s",
                 (s.alert_id,))
    after_outside = s.logs.verify_integrity(admin)
    # Positive control: the same kind of change to an AUDIT record.
    target = _audit_rows(s.db, user_id=admin_id)[-1]
    s.db.execute("UPDATE audit_logs SET detail = 'changed outside the application' WHERE id = %s",
                 (target["id"],))
    after_audit_change = s.logs.verify_integrity(admin)

    _write("T4_summary.json", {
        "checked_on": datetime.now(UTC).isoformat(), "database": "aethra_sec_test (isolated)",
        "standard_user_attempts": by_user,
        "records_unchanged_after_user_attempts": unchanged_after_user,
        "detection_review_state_before_administrator": review_state["before_admin"],
        "administrator_actions": by_admin,
        "administrator_actions_written_to_audit_log": [
            {"action": r["action"], "target_type": r["target_type"], "target_id": r["target_id"],
             "result": r["result"]} for r in admin_audit],
        "audit_chain_after_administrator_changes": {"checked": chain_after_admin.checked,
                                                    "issues": len(chain_after_admin.issues)},
        "evidence_fields_unchanged_by_administrator_actions": {
            "snort_alert": all(alert_after[f] == alert_before[f] for f in evidence_fields),
            "detection": all(anomaly_after[f] == anomaly_before[f] for f in detection_fields)},
        "change_made_outside_the_application": {
            "what": "observed_value of the detection and message of the Snort alert edited directly in the test database",
            "issues_reported_by_log_verification": len(after_outside.issues),
            "detected": bool(after_outside.issues)},
        "positive_control_audit_record_changed_outside_the_application": {
            "issues_reported_by_log_verification": len(after_audit_change.issues),
            "detected": bool(after_audit_change.issues)},
    })
    assert all(r["actual"] == "REFUSED - permission" for r in by_user), by_user
    assert unchanged_after_user
    assert all(r["actual"] == "ALLOWED" for r in by_admin), by_admin
    assert admin_audit, "administrator changes must be written to the audit log"
    assert not chain_after_admin.issues
    assert after_audit_change.issues, "a changed audit record must be detected"


# ===========================================================================
# T3 - scan results
# ===========================================================================
def test_t3_scan_records(system) -> None:  # noqa: ANN001
    s = system
    admin_id, admin = s.account["ADMIN"]
    user_id, user = s.account["USER"]
    finding_fields = ("scan_id", "ip_address", "port", "protocol", "service", "title",
                      "observation", "evidence", "risk_level")
    before = _row(s.db, "scan_findings", s.finding_id)
    view = _outcome(lambda: s.nmap.findings(user))
    resolve = _outcome(lambda: s.nmap.resolve_finding(user, s.finding_id))
    after = _row(s.db, "scan_findings", s.finding_id)
    resolved_audit = [r for r in _audit_rows(s.db, user_id=user_id) if r["action"] == "FINDING_RESOLVED"]

    s.db.execute("UPDATE scan_findings SET evidence = 'changed outside the application' WHERE id = %s",
                 (s.finding_id,))
    after_outside = s.logs.verify_integrity(admin)

    _write("T3_summary.json", {
        "checked_on": datetime.now(UTC).isoformat(), "database": "aethra_sec_test (isolated)",
        "standard_user_view_findings": view,
        "standard_user_mark_finding_resolved": resolve,
        "permission_required_to_mark_resolved": "scan.view (held by the standard USER role)",
        "finding_evidence_fields_unchanged_by_resolve": all(after[f] == before[f] for f in finding_fields),
        "resolved_at_set": after["resolved_at"] is not None,
        "resolve_written_to_audit_log": [{"action": r["action"], "target_id": r["target_id"],
                                          "result": r["result"]} for r in resolved_audit],
        "application_paths_that_edit_finding_content": (
            "none - every write to scan_findings in the code either inserts a finding "
            "(scan worker) or sets/clears resolved_at (a newer scan superseding it, a user "
            "marking it resolved or reopened, or a one-time schema migration)"),
        "change_made_outside_the_application": {
            "what": "evidence of the finding edited directly in the test database",
            "issues_reported_by_log_verification": len(after_outside.issues),
            "detected": bool(after_outside.issues)},
    })
    assert view == "ALLOWED"
    assert all(after[f] == before[f] for f in finding_fields)
