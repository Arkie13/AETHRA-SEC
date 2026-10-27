"""The stored pps and grade of a detection only ever rise - on real MariaDB.

Runs against the test database, never production. Every row is a labelled
test fixture, not a real detection.
"""

from __future__ import annotations

from datetime import datetime

from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.alert import SnortAlert
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import TrafficAnomaly

BASE = datetime(2026, 10, 14, 12, 0, 0)


def _sweep(pps: float) -> TrafficAnomaly:
    return TrafficAnomaly(
        rule_id="RULE-HOST-SWEEP", category=ThreatCategory.HOST_SWEEP,
        title="TEST FIXTURE - not a real detection", severity=Severity.LOW,
        src_ip="10.98.0.10", observed_value=15.0, threshold_value=15.0,
        window_seconds=10, detected_at=BASE, first_seen=BASE, last_seen=BASE,
        evidence={"packets_per_second": pps,
                  "severity_basis": "pps legend (§3.9.8)"},
        source=EvidenceSource.PYSHARK, created_at=BASE,
    )


def _snort(pps: float | None) -> SnortAlert:
    return SnortAlert(
        alert_time=BASE, received_at=BASE, message="TEST FIXTURE",
        signature_id=1000002, generator_id=1, priority=2,
        severity=Severity.LOW, protocol="TCP", src_ip="10.98.0.28",
        dst_ip="10.98.0.26", raw_alert="TEST FIXTURE raw", dedup_key="t",
        peak_pps=pps, created_at=BASE,
    )


def test_anomaly_pps_rises_and_never_falls(clean_db) -> None:  # noqa: ANN001
    repo = AlertRepository(clean_db)
    anomaly_id = repo.insert_anomaly(_sweep(1.5))
    repo.raise_anomaly_pps(anomaly_id, 640.2)
    assert repo.get_anomaly(anomaly_id).evidence["packets_per_second"] == 640.2
    repo.raise_anomaly_pps(anomaly_id, 3.0)
    stored = repo.get_anomaly(anomaly_id).evidence
    assert stored["packets_per_second"] == 640.2, "a slower repeat cannot lower it"
    assert stored["severity_basis"], "the rest of the evidence is kept"


def test_snort_peak_pps_is_stored_and_read_back(clean_db) -> None:  # noqa: ANN001
    repo = AlertRepository(clean_db)
    graded = repo.insert_alert(_snort(389.6))
    ungraded = repo.insert_alert(_snort(None))
    assert repo.get_alert(graded).peak_pps == 389.6
    assert repo.get_alert(ungraded).peak_pps is None, "no rate is not zero"


def test_snort_grade_rises_and_never_falls(clean_db) -> None:  # noqa: ANN001
    repo = AlertRepository(clean_db)
    alert_id = repo.insert_alert(_snort(389.6))
    repo.raise_alert_grade(alert_id, 1250.0, Severity.HIGH)
    after = repo.get_alert(alert_id)
    assert after.peak_pps == 1250.0 and after.severity is Severity.HIGH
    repo.raise_alert_grade(alert_id, 40.0, Severity.LOW)
    after = repo.get_alert(alert_id)
    assert after.peak_pps == 1250.0 and after.severity is Severity.HIGH
