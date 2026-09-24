"""IDS: parsing, severity mapping, persistence and review state.

These assert behaviour, not structure. A professor who changes

    if priority <= 2:  ->  if priority <= 0:

leaves every function in place and the application still starts; only an
assertion about the *result* catches it.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools.coverage import covers  # noqa: E402

RISK = "aethra_sec/analytics/risk_engine.py"
PARSER = "aethra_sec/integrations/snort/parser.py"
SERVICE = "aethra_sec/services/snort_service.py"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
@covers(RISK, "RiskEngine.severity_for_snort_priority",
        feature="IDS Alerts", action="Severity mapping")
def test_priority_one_is_high() -> None:
    """Snort priority 1 is its most severe; it must not read as anything less."""
    from aethra_sec.analytics.risk_engine import RiskEngine
    from aethra_sec.models.enums import Severity

    assert RiskEngine.severity_for_snort_priority(1) is Severity.HIGH


@covers(RISK, "RiskEngine.severity_for_snort_priority",
        feature="IDS Alerts", action="Severity mapping")
def test_the_whole_priority_band_maps_correctly() -> None:
    from aethra_sec.analytics.risk_engine import RiskEngine
    from aethra_sec.models.enums import Severity

    expected = {
        1: Severity.HIGH, 2: Severity.HIGH,
        3: Severity.MEDIUM,
        4: Severity.LOW, 9: Severity.LOW,
    }
    actual = {p: RiskEngine.severity_for_snort_priority(p) for p in expected}
    assert actual == expected


@covers(RISK, "RiskEngine.severity_for_snort_priority",
        feature="IDS Alerts", action="Severity mapping")
def test_a_missing_priority_is_not_guessed_as_high() -> None:
    """No priority means unknown, which is MEDIUM - never invented as HIGH."""
    from aethra_sec.analytics.risk_engine import RiskEngine
    from aethra_sec.models.enums import Severity

    assert RiskEngine.severity_for_snort_priority(None) is Severity.MEDIUM


# ---------------------------------------------------------------------------
# Alert parsing
# ---------------------------------------------------------------------------
FAST = (
    "09/16-01:23:45.123456  [**] [1:2001219:5] ET SCAN Potential SSH Scan [**] "
    "[Classification: Attempted Information Leak] [Priority: 2] "
    "{TCP} 192.168.1.50:4321 -> 192.168.1.10:22"
)


@covers(PARSER, "parse_fast", feature="IDS Alerts", action="Fast-format parsing")
def test_a_fast_alert_is_parsed_into_its_fields() -> None:
    from aethra_sec.integrations.snort.parser import parse_fast

    alert = parse_fast(FAST)
    assert alert is not None, "a well-formed fast alert was not parsed at all"
    assert alert.signature_id == 2001219
    assert alert.src_ip == "192.168.1.50"
    assert alert.dst_ip == "192.168.1.10"
    assert alert.dst_port == 22
    assert alert.priority == 2
    assert "SSH Scan" in alert.message


@covers(PARSER, "parse_fast", feature="IDS Alerts", action="Fast-format parsing")
def test_a_line_that_is_not_an_alert_is_rejected() -> None:
    """Returning a half-built alert for noise would fabricate detections."""
    from aethra_sec.integrations.snort.parser import parse_fast

    for junk in ("", "   ", "Snort started", "not an alert at all"):
        assert parse_fast(junk) is None, f"{junk!r} was accepted as an alert"


@covers(PARSER, "parse_alert_line", feature="IDS Alerts", action="Alert parsing")
def test_the_dispatcher_recognises_the_fast_format() -> None:
    from aethra_sec.integrations.snort.parser import parse_alert_line

    alert = parse_alert_line(FAST)
    assert alert is not None and alert.signature_id == 2001219


@covers(PARSER, "parse_json", feature="IDS Alerts", action="JSON parsing")
def test_a_json_alert_is_parsed() -> None:
    import json

    from aethra_sec.integrations.snort.parser import parse_json

    line = json.dumps({
        "timestamp": "2026-09-16T01:23:45.123456+00:00",
        "sid": 2001219, "gid": 1, "rev": 5,
        "msg": "ET SCAN Potential SSH Scan", "priority": 2,
        "src_addr": "192.168.1.50", "src_port": 4321,
        "dst_addr": "192.168.1.10", "dst_port": 22, "proto": "TCP",
    })
    alert = parse_json(line)
    assert alert is not None
    assert alert.signature_id == 2001219 and alert.dst_port == 22


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
@covers(PARSER, "_parse_fast_timestamp",
        feature="IDS Alerts", action="Alert timestamp")
def test_the_alert_timestamp_is_read_not_invented() -> None:
    """Detection time is measured from this; a wrong value corrupts the metric."""
    from aethra_sec.integrations.snort.parser import _parse_fast_timestamp

    reference = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    stamp = _parse_fast_timestamp("09/16-01:23:45.123456", reference)
    assert stamp is not None, "a valid Snort timestamp was not parsed"
    # Snort writes local time; the parser stores UTC. Compare the instant,
    # not the wall clock, so this holds in any timezone.
    local = datetime(2026, 9, 16, 1, 23, 45, 123456).astimezone()
    assert abs((stamp - local).total_seconds()) < 1.0, (
        f"parsed {stamp} does not match the alert instant {local}"
    )
    assert stamp.tzinfo is not None, "the timestamp lost its timezone"


# ---------------------------------------------------------------------------
# Persistence and review state
# ---------------------------------------------------------------------------
@covers("aethra_sec/database/repositories/alerts.py", "AlertRepository.insert_alert",
        feature="IDS Alerts", action="Alert persistence")
def test_an_alert_is_written_to_the_database(clean_db) -> None:
    from aethra_sec.database.repositories import AlertRepository
    from aethra_sec.models.alert import SnortAlert
    from aethra_sec.models.enums import Severity
    from aethra_sec.utils.timeutil import utcnow

    repository = AlertRepository(clean_db)
    alert_id = repository.insert_alert(SnortAlert(
        alert_time=utcnow(), signature_id=2001219, revision=5,
        message="ET SCAN Potential SSH Scan", severity=Severity.HIGH,
        priority=2, src_ip="192.168.1.50", dst_ip="192.168.1.10",
        src_port=4321, dst_port=22, protocol="TCP",
    ))
    assert alert_id, "insert_alert did not return an id"
    stored = clean_db.query_one(
        "SELECT signature_id, severity, dst_port FROM snort_alerts WHERE id = %s",
        (alert_id,),
    )
    assert stored is not None, "the alert was not persisted"
    assert stored["signature_id"] == 2001219
    assert stored["severity"] == "HIGH"
    assert stored["dst_port"] == 22


def _fixture_alert(repository, **kwargs):
    """One isolated test alert. Never production data."""
    from aethra_sec.models.alert import SnortAlert
    from aethra_sec.models.enums import Severity
    from aethra_sec.utils.timeutil import utcnow

    fields = dict(
        alert_time=utcnow(), signature_id=1, message="skills-test fixture alert",
        severity=Severity.MEDIUM, src_ip="192.168.1.50", dst_ip="192.168.1.10",
    )
    fields.update(kwargs)
    return repository.insert_alert(SnortAlert(**fields))


@covers("aethra_sec/database/repositories/alerts.py",
        "AlertRepository.mark_all_reviewed",
        feature="IDS Alerts", action="Mark reviewed")
def test_marking_alerts_reviewed_persists(clean_db) -> None:
    """The button must change stored state, not just the row on screen."""
    from aethra_sec.database.repositories import AlertRepository, UserRepository
    from aethra_sec.models.enums import AlertStatus

    repository = AlertRepository(clean_db)
    alert_id = _fixture_alert(repository)
    user = UserRepository(clean_db).get_by_username("admin")
    moved = repository.mark_all_reviewed(user.id if user else None)

    assert moved >= 1, "no alert moved - the persistence call did nothing"
    stored = clean_db.query_one(
        "SELECT status, evaluated_at FROM snort_alerts WHERE id = %s", (alert_id,)
    )
    assert stored["status"] == str(AlertStatus.REVIEWED), (
        "the alert status did not change to REVIEWED"
    )
    assert stored["evaluated_at"] is not None, "no review timestamp was recorded"


@covers("aethra_sec/database/repositories/alerts.py",
        "AlertRepository.mark_all_reviewed",
        feature="IDS Alerts", action="Mark reviewed")
def test_a_decision_already_made_is_not_overwritten(clean_db) -> None:
    """A bulk review must not quietly undo an escalation."""
    from aethra_sec.database.repositories import AlertRepository
    from aethra_sec.models.enums import AlertStatus

    repository = AlertRepository(clean_db)
    escalated = _fixture_alert(repository, signature_id=2)
    repository.set_alert_status(escalated, AlertStatus.ESCALATED)
    repository.mark_all_reviewed(None)

    stored = clean_db.query_one(
        "SELECT status FROM snort_alerts WHERE id = %s", (escalated,)
    )
    assert stored["status"] == str(AlertStatus.ESCALATED), (
        "a bulk review overwrote an analyst's escalation"
    )


@covers("aethra_sec/database/repositories/alerts.py",
        "AlertRepository.set_alert_evaluation",
        feature="IDS Alerts", action="True/false positive")
def test_an_evaluation_is_recorded(clean_db) -> None:
    from aethra_sec.database.repositories import AlertRepository
    from aethra_sec.models.enums import EvaluationLabel

    repository = AlertRepository(clean_db)
    alert_id = _fixture_alert(repository, signature_id=3)
    repository.set_alert_evaluation(alert_id, EvaluationLabel.TRUE_POSITIVE, None)

    stored = clean_db.query_one(
        "SELECT evaluation, evaluated_at FROM snort_alerts WHERE id = %s",
        (alert_id,),
    )
    assert stored["evaluation"] == str(EvaluationLabel.TRUE_POSITIVE)
    assert stored["evaluated_at"] is not None


@covers("aethra_sec/database/repositories/alerts.py",
        "AlertRepository.find_duplicate",
        feature="IDS Alerts", action="Duplicate prevention")
def test_a_repeat_alert_is_recognised_as_a_duplicate(clean_db) -> None:
    """Without this, one flood writes a row per packet."""
    from datetime import timedelta

    from aethra_sec.database.repositories import AlertRepository
    from aethra_sec.utils.timeutil import utcnow

    repository = AlertRepository(clean_db)
    alert_id = _fixture_alert(repository, signature_id=4)
    clean_db.execute(
        "UPDATE snort_alerts SET dedup_key = %s WHERE id = %s",
        ("skills-test-key", alert_id),
    )
    found = repository.find_duplicate("skills-test-key", utcnow() - timedelta(minutes=5))
    assert found is not None, "an identical alert inside the window was not matched"
