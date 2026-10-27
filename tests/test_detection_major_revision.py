"""Regression tests for the 15 Oct 2026 detection major revision.

Each class names the scenario from the revision brief it covers (TEST A-L).
The two screenshot scenarios are reproduced as fixtures with the values the
stored records 2860 and 2817 actually held; no production logic reads them.

Every packet here is synthetic, bounded and processed offline - nothing is
sent on a network. Database tests run against the isolated test schema.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aethra_sec.analytics import anomaly_rules
from aethra_sec.analytics.anomaly_rules import (
    RULE_ICMP_FLOOD,
    AnomalyRuleEngine,
    DetectionThresholds,
    _SlidingSet,
    flood_severity,
)
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.diagnostics.ui_watchdog import UiStallWatchdog
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.packet_capture import PacketCaptureService
from aethra_sec.ui.screens.alerts import (
    ORIGIN_AETHRA,
    ORIGIN_SNORT,
    _anomaly_detail_sections,
    _capture_statement,
    one_row_per_attack,
)

BASE = datetime(2026, 10, 15, 13, 1, 17, tzinfo=UTC)

_SCOPE_OLD = (
    "ICMP packets sent BY this source, over the stated window. Not the "
    "interface total: a ping flood is counted once from the attacker and again "
    "from the replying host, so the Traffic Rate graph - which sums every "
    "packet in both directions - reads about twice this value."
)


def _trigger_evidence(**extra) -> dict:
    evidence = {
        "icmp_packets_in_window": 600,
        "rate_scope": _SCOPE_OLD,
        "window_seconds": 5,
        "observed_rate_pps": 120.0,
        "threshold_pps": 120,
        "severity_band": "Low (< 500 pps)",
    }
    evidence.update(extra)
    return evidence


def record_2860() -> TrafficAnomaly:
    """The values detection 2860 held when screenshot A was taken."""
    return TrafficAnomaly(
        id=2860, rule_id=RULE_ICMP_FLOOD, category=ThreatCategory.ICMP_FLOOD,
        title="Excessive ICMP traffic",
        observation=(
            "192.168.1.26 sent 600 ICMP packet(s) in 5 second(s) (120.0 "
            "packets/second), which is at or above the configured threshold of "
            "120 per second. Severity band: Low (< 500 pps)."
        ),
        severity=Severity.HIGH, peak_severity=Severity.HIGH,
        src_ip="192.168.1.26", dst_ip="192.168.1.21", protocol="ICMP",
        observed_value=1040.2, latest_value=1040.2,
        latest_measured_at=datetime(2026, 10, 15, 13, 2, 1, tzinfo=UTC),
        threshold_value=120.0, window_seconds=5, event_count=134,
        detected_at=datetime(2026, 10, 15, 13, 1, 27, tzinfo=UTC),
        first_seen=BASE, last_seen=datetime(2026, 10, 15, 13, 1, 33, tzinfo=UTC),
        evidence=_trigger_evidence(
            capture_packets_seen=433252, capture_packets_dropped=88270,
            capture_loss_rate=0.169255,
            adapter_packets_since_capture_start=516762,
            capture_completeness=0.859,
            measured_rate_is_a_floor="(stored text)",
        ),
        source=EvidenceSource.PYSHARK,
    )


def record_2817() -> TrafficAnomaly:
    """The values detection 2817 held when screenshot B was taken."""
    return TrafficAnomaly(
        id=2817, rule_id=RULE_ICMP_FLOOD, category=ThreatCategory.ICMP_FLOOD,
        title="Excessive ICMP traffic",
        observation=(
            "192.168.100.31 sent 600 ICMP packet(s) in 5 second(s) (120.0 "
            "packets/second), which is at or above the configured threshold of "
            "120 per second. Severity band: Low (< 500 pps)."
        ),
        severity=Severity.LOW, peak_severity=Severity.LOW,
        src_ip="192.168.100.31", dst_ip="192.168.100.132", protocol="ICMP",
        observed_value=330.2, latest_value=299.0,
        latest_measured_at=datetime(2026, 10, 15, 9, 55, 29, tzinfo=UTC),
        threshold_value=120.0, window_seconds=5, event_count=154,
        detected_at=datetime(2026, 10, 15, 9, 55, 1, tzinfo=UTC),
        first_seen=datetime(2026, 10, 15, 9, 54, 51, tzinfo=UTC),
        last_seen=datetime(2026, 10, 15, 9, 55, 29, tzinfo=UTC),
        evidence=_trigger_evidence(
            capture_packets_seen=185168, capture_packets_dropped=0,
            capture_loss_rate=0.0, adapter_packets_since_capture_start=187794,
            capture_completeness=1.0005,
        ),
        source=EvidenceSource.PYSHARK,
    )


def _sections(anomaly: TrafficAnomaly) -> dict[str, dict]:
    episode = anomaly.episode(inactivity_seconds=300,
                              now=(anomaly.last_seen or BASE) + timedelta(hours=1))
    built = _anomaly_detail_sections(anomaly, anomaly.detected_at, episode)
    return {
        section.heading: {"rows": dict(section.rows), "body": section.body}
        for section in built
    }


def _all_text(anomaly: TrafficAnomaly) -> str:
    out = []
    for section in _sections(anomaly).values():
        out += [f"{k}: {v}" for k, v in section["rows"].items()]
        out.append(section["body"] or "")
    return "\n".join(out)


def _icmp(seconds: float, src: str, dst: str, icmp_type: int | None) -> CapturedPacket:
    return CapturedPacket(
        captured_at=BASE + timedelta(seconds=seconds),
        src_ip=src, dst_ip=dst, protocol="ICMP", icmp_type=icmp_type,
    )


# ---------------------------------------------------------------------------
# TEST A - high ICMP rate (screenshot A)
# ---------------------------------------------------------------------------
class TestA_HighIcmpRate:
    def test_current_and_peak_severity_follow_the_measured_rate(self) -> None:
        anomaly = record_2860()
        assert anomaly.current_severity is Severity.HIGH
        assert anomaly.highest_severity is Severity.HIGH
        info = _sections(anomaly)["DETECTION INFORMATION"]["rows"]
        assert info["Current severity"].startswith("HIGH - from the latest measurement, 1,040.2")
        assert info["Peak severity"].startswith("HIGH - from the peak, 1,040.2")

    def test_the_observation_does_not_present_120_pps_as_the_latest(self) -> None:
        body = _sections(record_2860())["EVIDENCE"]["body"]
        observation = body.split("\n\n")[0]
        assert "Latest measurement: 1,040.2 pps" in observation
        assert "Peak measurement: 1,040.2 pps" in observation
        assert "High (1,000 pps and above)" in observation
        # 120 pps appears only as the trigger, labelled as such.
        assert "threshold of 120 pps over 5 s was crossed" in observation
        assert "Trigger observation (recorded when the threshold was first crossed" in body

    def test_incomplete_capture_is_stated_not_hidden(self) -> None:
        evidence = _sections(record_2860())["EVIDENCE"]["rows"]
        assert evidence["Capture at trigger"].startswith("INCOMPLETE - only 85.9%")
        assert "lower bound" in evidence["Capture at trigger"]
        assert "complete measurement" not in _all_text(record_2860())


# ---------------------------------------------------------------------------
# TEST B - low ICMP rate (screenshot B)
# ---------------------------------------------------------------------------
class TestB_LowIcmpRate:
    def test_current_and_peak_are_both_low(self) -> None:
        anomaly = record_2817()
        assert anomaly.current_severity is Severity.LOW
        assert anomaly.highest_severity is Severity.LOW
        info = _sections(anomaly)["DETECTION INFORMATION"]["rows"]
        assert info["Current severity"] == "LOW - from the latest measurement, 299 pps"
        assert info["Peak severity"] == "LOW - from the peak, 330.2 pps"

    def test_the_observation_reports_299_latest_and_330_2_peak(self) -> None:
        observation = _sections(record_2817())["EVIDENCE"]["body"].split("\n\n")[0]
        assert "Latest measurement: 299 pps" in observation
        assert "Peak measurement: 330.2 pps" in observation
        lines = observation.splitlines()
        assert not any(line.startswith("Latest") and "120" in line for line in lines)

    def test_zero_drops_is_not_called_a_complete_measurement(self) -> None:
        statement = _sections(record_2817())["EVIDENCE"]["rows"]["Capture at trigger"]
        assert "does not prove every packet on the network was seen" in statement
        assert "complete measurement" not in statement
        # 1.0005 is two counters sampled a moment apart - never shown above 100%.
        assert "100.0%" in statement


# ---------------------------------------------------------------------------
# TEST C - trigger threshold versus severity bands
# ---------------------------------------------------------------------------
class TestC_ThresholdVersusSeverity:
    @pytest.mark.parametrize(
        ("rate", "expected"),
        [
            (120.0, Severity.LOW), (499.9, Severity.LOW), (499.999, Severity.LOW),
            (500.0, Severity.MEDIUM), (500.1, Severity.MEDIUM),
            (999.9, Severity.MEDIUM), (999.999, Severity.MEDIUM),
            (1000.0, Severity.HIGH), (1000.1, Severity.HIGH),
        ],
    )
    def test_band_boundaries(self, rate: float, expected: Severity) -> None:
        assert flood_severity(rate)[0] is expected

    def test_120_pps_raises_a_detection_that_stays_low(self) -> None:
        engine = AnomalyRuleEngine(DetectionThresholds())
        fired = []
        # Exactly 120 pps for 5 s: 600 echo requests, 1/120 s apart.
        for index in range(600):
            fired += engine.evaluate(
                _icmp(index / 120.0, "10.97.0.10", "10.97.0.20", 8)
            )
        icmp = [a for a in fired if a.rule_id == RULE_ICMP_FLOOD]
        assert icmp, "reaching the trigger threshold raises a detection"
        assert icmp[0].observed_value == pytest.approx(120.0)
        assert icmp[0].severity is Severity.LOW


# ---------------------------------------------------------------------------
# TEST D - detail isolation between records
# ---------------------------------------------------------------------------
class TestD_DetailIsolation:
    def test_each_dialog_shows_only_its_own_record(self) -> None:
        for _round in range(2):  # 2860 then 2817, then again
            text_a = _all_text(record_2860())
            text_b = _all_text(record_2817())
            assert "192.168.1.26" in text_a and "192.168.100.31" not in text_a
            assert "192.168.100.31" in text_b and "192.168.1.26" not in text_b
            assert "traffic_anomalies #2860" in text_a
            assert "traffic_anomalies #2817" in text_b
            assert "330.2" not in text_a and "1,040.2" not in text_b
            # Legacy rows: stored count minus the trigger rate plus one.
            assert "15 - derived exactly from the stored count 134" in text_a
            assert "35 - derived exactly from the stored count 154" in text_b

    def test_icmp_ports_are_not_applicable_not_missing(self) -> None:
        network = _sections(record_2817())["NETWORK DETAILS"]["rows"]
        assert network["Source port"].startswith("Not applicable")
        assert network["Destination port"].startswith("Not applicable")

    def test_event_count_is_defined_and_not_called_packets(self) -> None:
        episode = _sections(record_2860())["OBSERVED EPISODE"]["rows"]
        assert "Not a packet count" in episode["Measurements in episode"]
        assert episode["Measurements in episode"].startswith("15 - derived")
        assert episode["Total packets in episode"].startswith("Not recorded")
        assert episode["Average rate"].startswith("Not calculated")


# ---------------------------------------------------------------------------
# Root cause of the reversed duplicate (detection 2860): echo replies
# ---------------------------------------------------------------------------
class TestEchoRepliesAreNotAnAttack:
    def _flood(self, engine: AnomalyRuleEngine, reply_type: int | None = 0) -> list:
        fired = []
        for index in range(2500):  # 500 pps for 5 s, each answered
            at = index / 500.0
            fired += engine.evaluate(_icmp(at, "192.168.1.21", "192.168.1.26", 8))
            fired += engine.evaluate(
                _icmp(at + 0.0001, "192.168.1.26", "192.168.1.21", reply_type)
            )
        return [a for a in fired if a.rule_id == RULE_ICMP_FLOOD]

    def test_only_the_requester_is_reported(self) -> None:
        engine = AnomalyRuleEngine()
        sources = {a.src_ip for a in self._flood(engine)}
        assert sources == {"192.168.1.21"}
        assert engine.statistics["icmp_echo_answers_excluded"] == 2500

    def test_an_unsolicited_reply_flood_is_still_reported(self) -> None:
        engine = AnomalyRuleEngine()
        fired = []
        for index in range(2500):
            fired += engine.evaluate(_icmp(index / 500.0, "10.97.0.66", "10.97.0.20", 0))
        assert {a.src_ip for a in fired if a.rule_id == RULE_ICMP_FLOOD} == {"10.97.0.66"}

    def test_an_undecoded_type_is_never_assumed_to_be_a_reply(self) -> None:
        sources = {a.src_ip for a in self._flood(AnomalyRuleEngine(), reply_type=None)}
        assert sources == {"192.168.1.21", "192.168.1.26"}

    def test_new_icmp_evidence_states_its_scope(self) -> None:
        detection = self._flood(AnomalyRuleEngine())[0]
        assert detection.evidence["measurement_scope"] == "per-source, one direction"
        assert "excluding echo replies" in detection.evidence["rate_scope"]


# ---------------------------------------------------------------------------
# TEST E / F / G - one attack, one primary result; distinct attacks; polling
# ---------------------------------------------------------------------------
def _row(origin: str, ident: int, attack, severity: str, sort: int, **extra) -> dict:
    row = {
        "_origin": origin, "_id": ident, "_attack": attack, "_sort": sort,
        "severity": severity, "message": f"{origin}-{ident}", "signature": "S",
        "time": str(sort), "origin": origin, "source": "a", "destination": "b",
        "count": 1,
    }
    row.update(extra)
    return row


class TestE_OneAttackOnePrimaryResult:
    def test_three_detections_of_one_attack_become_one_row(self) -> None:
        rows = [
            _row(ORIGIN_AETHRA, 2859, 1874, "HIGH", 3),
            _row(ORIGIN_SNORT, 9001, 1874, "LOW", 2),
            _row(ORIGIN_SNORT, 9002, 1874, "LOW", 1),
        ]
        primaries, members = one_row_per_attack(rows)
        assert len(primaries) == 1
        primary = primaries[0]
        assert (primary["_origin"], primary["_id"]) == (ORIGIN_AETHRA, 2859)
        assert "+2 related (2 Snort)" in primary["message"]
        assert len(members[(ORIGIN_AETHRA, 2859)]) == 3, "supporting evidence kept"
        assert len(rows) == 3 and rows[0]["message"] == "AETHRA-2859", "inputs untouched"


class TestF_DistinctAttacksStaySeparate:
    def test_different_correlated_attacks_are_not_merged(self) -> None:
        rows = [
            _row(ORIGIN_AETHRA, 1, 10, "HIGH", 3),
            _row(ORIGIN_AETHRA, 2, 11, "LOW", 2),
            _row(ORIGIN_SNORT, 3, None, "LOW", 1),  # not yet correlated
        ]
        primaries, _members = one_row_per_attack(rows)
        assert sorted(r["_id"] for r in primaries) == [1, 2, 3]

    def test_two_sources_flooding_give_two_detections(self) -> None:
        engine = AnomalyRuleEngine()
        fired = []
        for index in range(1500):
            at = index / 300.0
            fired += engine.evaluate(_icmp(at, "10.97.0.10", "10.97.0.20", 8))
            fired += engine.evaluate(_icmp(at, "10.97.0.11", "10.97.0.20", 8))
        assert {a.src_ip for a in fired if a.rule_id == RULE_ICMP_FLOOD} == {
            "10.97.0.10", "10.97.0.11"
        }


class TestG_RepeatedProcessing:
    def test_grouping_is_idempotent(self) -> None:
        rows = [_row(ORIGIN_AETHRA, 1, 7, "HIGH", 2), _row(ORIGIN_SNORT, 2, 7, "LOW", 1)]
        first, _ = one_row_per_attack(rows)
        second, _ = one_row_per_attack(rows)
        assert first == second and len(first) == 1


# ---------------------------------------------------------------------------
# Correlation: generic Snort alerts join the flood they belong to (DB)
# ---------------------------------------------------------------------------
@pytest.fixture
def correlation_stack(clean_db):
    from aethra_sec.analytics.risk_engine import RiskEngine
    from aethra_sec.core.event_bus import EventBus
    from aethra_sec.core.session import SessionManager
    from aethra_sec.database.repositories.audit import AuditRepository
    from aethra_sec.database.repositories.hosts import HostRepository
    from aethra_sec.database.repositories.incidents import IncidentRepository
    from aethra_sec.database.repositories.mitigation import MitigationRepository
    from aethra_sec.database.repositories.scans import ScanRepository
    from aethra_sec.database.repositories.settings import SettingsRepository
    from aethra_sec.security.audit import AuditService
    from aethra_sec.security.rbac import AccessControl
    from aethra_sec.services.correlation_service import CorrelationService
    from aethra_sec.services.mitigation_service import MitigationService
    from aethra_sec.services.settings_service import SettingsService

    audit = AuditService(AuditRepository(clean_db))
    access = AccessControl(SessionManager(60), audit)
    settings = SettingsService(SettingsRepository(clean_db), access, audit)
    mitigation = MitigationService(MitigationRepository(clean_db), audit, access)
    service = CorrelationService(
        IncidentRepository(clean_db), AlertRepository(clean_db),
        ScanRepository(clean_db), HostRepository(clean_db), mitigation,
        settings, EventBus(), audit, access, RiskEngine(),
    )
    return service, IncidentRepository(clean_db), AlertRepository(clean_db)


def _snort(message: str, *, src: str, dst: str, duplicates: int, at: datetime):
    from aethra_sec.models.alert import SnortAlert

    return SnortAlert(
        alert_time=at, received_at=at, generator_id=1, signature_id=1000001,
        revision=2, message=message, priority=3, severity=Severity.LOW,
        protocol="ICMP", src_ip=src, dst_ip=dst,
        dedup_key=f"TEST-{message}-{src}-{dst}", created_at=at,
        duplicate_count=duplicates,
    )


def _flood_anomaly(src: str, dst: str, at: datetime) -> TrafficAnomaly:
    return TrafficAnomaly(
        rule_id=RULE_ICMP_FLOOD, category=ThreatCategory.ICMP_FLOOD,
        title="TEST FIXTURE - not a real detection", severity=Severity.HIGH,
        src_ip=src, dst_ip=dst, protocol="ICMP", observed_value=1040.2,
        threshold_value=120.0, window_seconds=5, detected_at=at,
        first_seen=at, last_seen=at, source=EvidenceSource.PYSHARK, created_at=at,
    )


class TestCorrelationOneAttack:
    def test_flood_and_its_generic_snort_alerts_form_one_attack(
        self, correlation_stack
    ) -> None:
        service, incidents, alerts = correlation_stack
        now = datetime.now(UTC)
        alerts.insert_alert(_snort("ICMP echo request", src="10.97.0.21",
                                   dst="10.97.0.26", duplicates=8475, at=now))
        alerts.insert_alert(_snort("ICMP flood - possible ping flood/DoS",
                                   src="10.97.0.21", dst="10.97.0.26",
                                   duplicates=23, at=now))
        alerts.insert_anomaly(_flood_anomaly("10.97.0.21", "10.97.0.26", now))
        service.correlate_recent()
        found = incidents.search()
        assert len(found) == 1, [i.correlation_key for i in found]
        events = incidents.events_for(found[0].id)
        assert len(events) == 3, "every detection kept as linked evidence"

    def test_repeated_cycles_add_nothing(self, correlation_stack) -> None:
        service, incidents, alerts = correlation_stack
        now = datetime.now(UTC)
        alerts.insert_alert(_snort("ICMP echo request", src="10.97.0.21",
                                   dst="10.97.0.26", duplicates=50, at=now))
        alerts.insert_anomaly(_flood_anomaly("10.97.0.21", "10.97.0.26", now))
        service.correlate_recent()
        before = [(i.id, len(incidents.events_for(i.id))) for i in incidents.search()]
        for _ in range(3):
            service.correlate_recent()
        after = [(i.id, len(incidents.events_for(i.id))) for i in incidents.search()]
        assert before == after == [(before[0][0], 2)]

    def test_a_different_target_is_a_different_attack(self, correlation_stack) -> None:
        service, incidents, alerts = correlation_stack
        now = datetime.now(UTC)
        alerts.insert_anomaly(_flood_anomaly("10.97.0.21", "10.97.0.26", now))
        alerts.insert_alert(_snort("ICMP echo request", src="10.97.0.21",
                                   dst="10.97.0.99", duplicates=1, at=now))
        service.correlate_recent()
        assert len(incidents.search()) == 2

    def test_a_repeating_generic_alert_waits_then_is_filed(
        self, correlation_stack
    ) -> None:
        service, incidents, alerts = correlation_stack
        now = datetime.now(UTC)
        alerts.insert_alert(_snort("ICMP echo request", src="10.97.0.40",
                                   dst="10.97.0.41", duplicates=40, at=now))
        assert service.correlate_recent() == 0, "waits for a flood to claim it"
        assert incidents.search() == []
        old = now - timedelta(seconds=120)
        alerts.insert_alert(_snort("ICMP echo request", src="10.97.0.50",
                                   dst="10.97.0.51", duplicates=40, at=old))
        service.correlate_recent()
        assert len(incidents.search()) == 1, "after the grace period it is filed"


# ---------------------------------------------------------------------------
# Latest measurements are recorded with their own facts (DB)
# ---------------------------------------------------------------------------
def _capture_service(db) -> PacketCaptureService:
    from types import SimpleNamespace

    class _Bus:
        def __init__(self) -> None:
            self.published = []

        def publish(self, event_type, payload) -> None:  # noqa: ANN001
            self.published.append((event_type, payload))

    service = object.__new__(PacketCaptureService)
    service._alerts = AlertRepository(db)  # noqa: SLF001
    service._bus = _Bus()  # noqa: SLF001
    # The fidelity probe reads capture statistics; these are fixture counters.
    counters = iter([(1000, 0, 1100), (6000, 0, 7000)])

    def statistics():
        seen, dropped, _offered = next(counters)
        service._last_offered = _offered  # noqa: SLF001
        return SimpleNamespace(total_packets=seen, dropped=dropped)

    service.statistics = statistics  # type: ignore[method-assign]
    service._capture_completeness = (  # type: ignore[method-assign]  # noqa: SLF001
        lambda: (service._last_offered, None)  # noqa: SLF001
    )
    return service


def _icmp_record(rate: float, *, at: datetime, analysed: datetime, count: int):
    return TrafficAnomaly(
        rule_id=RULE_ICMP_FLOOD, category=ThreatCategory.ICMP_FLOOD,
        title="TEST FIXTURE - not a real detection",
        severity=flood_severity(rate)[0], src_ip="10.97.0.10", dst_ip="10.97.0.20",
        protocol="ICMP", observed_value=rate, threshold_value=120.0,
        window_seconds=5, detected_at=analysed, first_seen=at - timedelta(seconds=5),
        last_seen=at, source=EvidenceSource.PYSHARK, created_at=analysed,
        evidence={"icmp_packets_in_window": count, "observed_rate_pps": rate,
                  "window_seconds": 5, "measurement_scope": "per-source, one direction"},
    )


class TestLatestMeasurementEvidence:
    def test_a_fold_records_its_own_count_time_lag_and_peak(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        service = _capture_service(clean_db)
        trigger = _icmp_record(120.0, at=BASE, analysed=BASE, count=600)
        anomaly_id = repo.insert_anomaly(trigger)

        packet_time = BASE + timedelta(seconds=20)
        analysed = packet_time + timedelta(seconds=27)
        service._fold_into_episode(  # noqa: SLF001
            repo.get_anomaly(anomaly_id),
            _icmp_record(1040.2, at=packet_time, analysed=analysed, count=5201),
        )
        row = repo.get_anomaly(anomaly_id)
        latest = row.evidence["latest_measurement"]
        assert latest["rate_pps"] == 1040.2
        assert latest["packets_in_window"] == 5201
        assert latest["analysis_lag_seconds"] == pytest.approx(27.0)
        assert row.evidence["peak_measurement"]["rate_pps"] == 1040.2
        assert row.evidence["observed_rate_pps"] == 120.0, "trigger evidence kept"
        assert row.latest_measured_at.replace(tzinfo=UTC) == packet_time

        # A lower measurement replaces the latest, never the peak.
        service._fold_into_episode(  # noqa: SLF001
            repo.get_anomaly(anomaly_id),
            _icmp_record(299.0, at=packet_time + timedelta(seconds=5),
                         analysed=analysed + timedelta(seconds=5), count=1495),
        )
        row = repo.get_anomaly(anomaly_id)
        assert row.evidence["latest_measurement"]["rate_pps"] == 299.0
        assert row.evidence["peak_measurement"]["rate_pps"] == 1040.2
        assert row.current_severity is Severity.LOW
        assert row.highest_severity is Severity.HIGH
        assert row.episode_severity is Severity.HIGH

    def test_a_failing_evidence_write_does_not_stop_the_fold(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        service = _capture_service(clean_db)
        anomaly_id = repo.insert_anomaly(_icmp_record(120.0, at=BASE, analysed=BASE, count=600))

        def broken(*_a, **_k):
            raise RuntimeError("injected failure")

        service._alerts.record_episode_measurement = broken  # noqa: SLF001
        service._fold_into_episode(  # noqa: SLF001
            repo.get_anomaly(anomaly_id),
            _icmp_record(600.0, at=BASE + timedelta(seconds=5),
                         analysed=BASE + timedelta(seconds=5), count=3000),
        )
        row = repo.get_anomaly(anomaly_id)
        assert row.latest_rate == 600.0 and row.event_count == 2


# ---------------------------------------------------------------------------
# TEST H - bounded high-severity burst through the engine
# ---------------------------------------------------------------------------
class TestH_BurstHandling:
    def test_a_2000_pps_flood_is_analysed_faster_than_it_arrives(self) -> None:
        engine = AnomalyRuleEngine()
        packets = []
        for index in range(20_000):  # 20 s of a 1,000 pps flood + its replies
            at = index / 1000.0
            packets.append(_icmp(at, "192.168.1.21", "192.168.1.26", 8))
            packets.append(_icmp(at + 0.00009, "192.168.1.26", "192.168.1.21", 0))
        started = time.perf_counter()
        fired = []
        for packet in packets:
            fired += engine.evaluate(packet)
        elapsed = time.perf_counter() - started
        # 20 s of traffic (40,000 packets). The unrevised engine needed
        # 17.3-47.2 s for this on the test machine (EVIDENCE/
        # offline_engine_benchmark.txt); anything under 20 s keeps up. 5 s
        # leaves margin for a slow host while still failing the old O(n) code.
        assert elapsed < 5.0, f"{elapsed:.1f}s to analyse 20 s of flood"
        new = [a for a in fired if not a.measurement_only and a.rule_id == RULE_ICMP_FLOOD]
        assert len(new) <= 3, "one detection, re-reported only on band escalation"
        updates = [a for a in fired if a.measurement_only]
        # One per second per source (measurement_interval = 1.0) - the same
        # cadence the unrevised engine produced for this stream.
        assert len(updates) <= 21, "measurement updates bounded by the cadence"

    def test_sliding_set_counts_match_a_full_recount(self) -> None:
        import random

        rng = random.Random(7)
        tracker = _SlidingSet()
        events = []
        for index in range(4000):
            at = index * 0.01 + rng.random() * 0.001
            key = rng.randrange(40)
            events.append((at, key))
            got = tracker.add(at, key, 3.0)
            expected = len({k for t, k in events if t >= at - 3.0})
            assert got == expected

    def test_idle_state_is_pruned_and_decisions_are_unchanged(self, monkeypatch) -> None:
        def stream():
            for index in range(30_000):
                at = index * 0.02
                yield CapturedPacket(
                    captured_at=BASE + timedelta(seconds=at), src_ip="8.8.8.8",
                    dst_ip="192.168.1.26", protocol="UDP", src_port=53,
                    dst_port=1024 + index,
                )
            for index in range(2000):  # then a real UDP flood on one port
                yield CapturedPacket(
                    captured_at=BASE + timedelta(seconds=700 + index / 400.0),
                    src_ip="10.97.0.10", dst_ip="10.97.0.20", protocol="UDP",
                    src_port=4000, dst_port=9999,
                )

        pruned, unpruned = AnomalyRuleEngine(), AnomalyRuleEngine()
        out_pruned = [(a.rule_id, a.src_ip, a.observed_value)
                      for p in stream() for a in pruned.evaluate(p)]
        monkeypatch.setattr(anomaly_rules, "PRUNE_INTERVAL_SECONDS", 10 ** 9)
        out_unpruned = [(a.rule_id, a.src_ip, a.observed_value)
                        for p in stream() for a in unpruned.evaluate(p)]
        assert out_pruned == out_unpruned
        assert len(pruned._udp) < 1000 < len(unpruned._udp)  # noqa: SLF001
        assert pruned.statistics["pruned_keys"] > 0


# ---------------------------------------------------------------------------
# TEST I - a frozen interface is recorded, not hidden
# ---------------------------------------------------------------------------
class TestI_StallWatchdog:
    def test_a_stall_writes_every_threads_stack_and_recovery_is_logged(
        self, tmp_path: Path, caplog
    ) -> None:
        clock = {"now": 100.0}
        dog = UiStallWatchdog(tmp_path, threshold=5.0, clock=lambda: clock["now"],
                              context=lambda: "main-window: pending=4000 dropped=6221")
        dog.beat()
        clock["now"] += 2.0
        assert dog.check() is None
        clock["now"] += 4.0  # 6 s without a beat
        report = dog.check()
        assert report is not None and report.exists()
        text = report.read_text(encoding="utf-8")
        assert "MainThread" in text and "has not run for 6.0 s" in text
        assert "pending=4000" in text
        clock["now"] += 1.0
        assert dog.check() is None, "one report per threshold step, not per poll"
        clock["now"] += 9.0  # 16 s: past 3x threshold
        assert dog.check() is not None
        dog.beat()
        with caplog.at_level("WARNING"):
            dog.check()
        assert any("responded again" in r.message for r in caplog.records)
        assert dog.stalls == 1

    def test_a_context_that_blocks_cannot_stop_the_report(self, tmp_path: Path) -> None:
        import threading

        never = threading.Event()
        clock = {"now": 0.0}
        dog = UiStallWatchdog(tmp_path, threshold=1.0, clock=lambda: clock["now"],
                              context=lambda: never.wait(30) or "x")
        dog.beat()
        clock["now"] = 2.0
        started = time.perf_counter()
        report = dog.check()
        assert report is not None
        assert time.perf_counter() - started < 5.0
        assert "a lock is held" in report.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# TEST J - episode duration and status
# ---------------------------------------------------------------------------
class TestJ_EpisodeDuration:
    def test_duration_and_status_come_from_the_records_timestamps(self) -> None:
        anomaly = record_2817()
        ended = anomaly.episode(inactivity_seconds=120,
                                now=anomaly.last_seen + timedelta(seconds=600))
        assert ended.duration == timedelta(seconds=38)
        assert str(ended.status.label).lower().startswith("ended")
        ongoing = anomaly.episode(inactivity_seconds=120,
                                  now=anomaly.last_seen + timedelta(seconds=30))
        assert str(ongoing.status.label).lower() != str(ended.status.label).lower()


# ---------------------------------------------------------------------------
# TEST K - incomplete capture metadata
# ---------------------------------------------------------------------------
class TestK_IncompleteCapture:
    def test_statements(self) -> None:
        assert _capture_statement({"capture_completeness": 0.5}).startswith("INCOMPLETE")
        assert _capture_statement({"capture_loss_rate": 0.2}).startswith("INCOMPLETE")
        assert "not proof" in _capture_statement({"capture_loss_rate": 0.0})
        assert _capture_statement({}) == "Capture state not recorded with this measurement"
        assert _capture_statement(None) == "Capture state not recorded with this measurement"


# ---------------------------------------------------------------------------
# TEST L - no schema migration; records written before the revision still read
# ---------------------------------------------------------------------------
class TestL_ExistingRecordsStillRead:
    def test_an_old_row_renders_and_is_described_as_recorded(self) -> None:
        anomaly = record_2860()  # no latest_measurement, no measurement_scope
        text = _all_text(anomaly)
        assert "Recorded before the 15 Oct 2026 revision" in text
        assert "analysis time - recorded before measurement times used the packet clock" in text
        rows = _sections(anomaly)["EVIDENCE"]["rows"]
        assert rows["Capture at latest measurement"] == "Not recorded for this measurement"

    def test_a_record_with_almost_nothing_does_not_crash(self) -> None:
        bare = TrafficAnomaly(rule_id=RULE_ICMP_FLOOD, protocol="")
        _all_text(bare)


# ---------------------------------------------------------------------------
# A burst of detections does not queue one full reload per detection
# ---------------------------------------------------------------------------
class TestAlertsReloadIsSingleFlight:
    def _screen(self):
        from types import SimpleNamespace

        from aethra_sec.ui.screens.alerts import AlertsScreen

        class Harness(AlertsScreen):
            session = object()
            is_alive = True

        screen = object.__new__(Harness)
        screen.context = SimpleNamespace(snort=object(), dashboard=None)
        screen._update_snort_status = lambda: None  # noqa: SLF001
        var = SimpleNamespace(get=lambda: "All")
        screen._search_var = SimpleNamespace(get=lambda: "")  # noqa: SLF001
        screen._severity_var = var  # noqa: SLF001
        screen._status_var = var  # noqa: SLF001
        screen._source_var = SimpleNamespace(get=lambda: "AETHRA-SEC detections")  # noqa: SLF001
        screen._selected_period = lambda: None  # noqa: SLF001
        screen.status = lambda _message: None
        screen.started = []

        def run_async(work, on_success=None, on_error=None, *, name=""):
            screen.started.append((on_success, on_error))

        screen.run_async = run_async
        screen._apply = lambda _loaded: None  # noqa: SLF001
        return screen

    def test_a_burst_starts_one_load_and_one_follow_up(self) -> None:
        screen = self._screen()
        for _ in range(50):
            screen.refresh()
        assert len(screen.started) == 1, "loads already running are not duplicated"
        on_success, _on_error = screen.started[0]
        on_success(None)  # the first load finishes
        assert len(screen.started) == 2, "exactly one more load shows the newest data"
        screen.started[1][0](None)
        assert len(screen.started) == 2, "nothing pending, nothing more started"

    def test_a_failed_load_does_not_wedge_the_screen(self) -> None:
        screen = self._screen()
        screen.show_error_message = lambda _m: None
        screen.refresh()
        screen.started[0][1]("database unavailable")
        screen.refresh()
        assert len(screen.started) == 2


class TestI_StallWatchdogOnARealTkLoop:
    def test_a_blocked_tk_loop_is_caught_with_the_blocking_call(
        self, tk_root, tmp_path: Path
    ) -> None:
        from aethra_sec.diagnostics.ui_watchdog import install_on_tk

        dog = UiStallWatchdog(tmp_path, threshold=0.6, poll=0.1)
        cancel = install_on_tk(tk_root, dog, interval_ms=100)
        try:
            def block_the_interface() -> None:
                time.sleep(1.5)  # stands in for any long call on the Tk thread

            tk_root.after(150, block_the_interface)
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                tk_root.update()
                time.sleep(0.02)
        finally:
            cancel()
        assert dog.stalls == 1
        assert dog.reports, "the stall was recorded"
        text = dog.reports[0].read_text(encoding="utf-8")
        assert "block_the_interface" in text, "the report names the blocking call"
