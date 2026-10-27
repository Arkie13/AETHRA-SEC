"""The escalation decision as the capture service actually makes it.

``_fold_into_episode`` is the one place that decides whether a new observation
reclassifies a running episode, writes a transition, and announces it. These
exercise that method directly against the real repository, with a stub bus and
stub settings, so the decision is tested rather than a reimplementation of it.

Every rate is a fixture written by the test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from aethra_sec.core.events import EventType
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.services.packet_capture import PacketCaptureService

BASE = datetime(2026, 10, 13, 16, 0, 0, tzinfo=UTC)


class _Bus:
    """Collects published events instead of delivering them."""

    def __init__(self) -> None:
        self.published: list[tuple] = []

    def publish(self, event_type, payload) -> None:  # noqa: ANN001
        self.published.append((event_type, payload))


def _service(db) -> PacketCaptureService:  # noqa: ANN001
    """A capture service with only the collaborators the fold path touches.

    Built without __init__ on purpose: constructing the real service starts
    threads and opens a capture handle, neither of which the fold decision
    needs or should be allowed to do inside a test.
    """
    service = object.__new__(PacketCaptureService)
    service._alerts = AlertRepository(db)  # noqa: SLF001
    service._bus = _Bus()  # noqa: SLF001
    return service


def _anomaly(rate: float, **overrides) -> TrafficAnomaly:
    fields = {
        "rule_id": "RULE-TCP-SYN-RATE",
        "category": ThreatCategory.UNCLASSIFIED,
        "title": "TEST FIXTURE - not a real detection",
        "severity": Severity.MEDIUM,
        "src_ip": "10.97.0.10",
        "dst_ip": "10.97.0.20",
        "protocol": "TCP",
        "observed_value": rate,
        "threshold_value": 200.0,
        "window_seconds": 5,
        "detected_at": BASE,
        "first_seen": BASE,
        "last_seen": BASE,
        "source": EvidenceSource.PYSHARK,
        "created_at": BASE,
    }
    fields.update(overrides)
    return TrafficAnomaly(**fields)


class TestTheServiceReclassifies:
    def test_an_escalation_updates_logs_and_announces(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(500.0))
        existing = repo.get_anomaly(anomaly_id)
        assert existing is not None and existing.severity is Severity.MEDIUM

        at = BASE + timedelta(seconds=10)
        service._fold_into_episode(  # noqa: SLF001
            existing, _anomaly(1200.0, last_seen=at, detected_at=at)
        )

        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.severity is Severity.HIGH
        assert row.highest_severity is Severity.HIGH
        assert row.latest_rate == 1200.0
        assert row.event_count == 2

        history = repo.severity_transitions(anomaly_id)
        assert len(history) == 1
        assert history[0]["previous_severity"] == "MEDIUM"
        assert history[0]["new_severity"] == "HIGH"
        assert float(history[0]["observed_value"]) == 1200.0
        assert history[0]["window_seconds"] == 5

        published = service._bus.published  # noqa: SLF001
        assert len(published) == 1, "an escalation is announced once"
        assert published[0][0] is EventType.TRAFFIC_ANOMALY_DETECTED

    def test_a_fallback_updates_and_logs_but_does_not_announce(
        self, clean_db
    ) -> None:
        """A rate dropping is recorded, not news worth interrupting for."""
        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        anomaly_id = repo.insert_anomaly(
            _anomaly(1200.0, severity=Severity.HIGH)
        )
        existing = repo.get_anomaly(anomaly_id)
        assert existing is not None

        at = BASE + timedelta(seconds=10)
        service._fold_into_episode(  # noqa: SLF001
            existing, _anomaly(800.0, last_seen=at, detected_at=at)
        )

        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        # The episode measured 1,200 pps, so 800 pps arriving later records
        # the new rate without un-reporting what the attack reached. The
        # drop is still in the transition history and still announced to
        # nobody, which is what this test is here to protect.
        assert row.severity is Severity.HIGH, "severity was lowered by a drop"
        assert row.highest_severity is Severity.HIGH, "the peak holds"
        assert row.latest_rate == 800.0, "the falling rate was not recorded"
        assert len(repo.severity_transitions(anomaly_id)) == 1
        assert service._bus.published == []  # noqa: SLF001

    def test_a_steady_flood_logs_and_announces_nothing(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        anomaly_id = repo.insert_anomaly(
            _anomaly(1200.0, severity=Severity.HIGH)
        )
        for offset in range(1, 25):
            at = BASE + timedelta(seconds=offset)
            existing = repo.get_anomaly(anomaly_id)
            assert existing is not None
            service._fold_into_episode(  # noqa: SLF001
                existing, _anomaly(1210.0, last_seen=at, detected_at=at)
            )

        assert repo.severity_transitions(anomaly_id) == []
        assert service._bus.published == []  # noqa: SLF001
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.event_count == 25
        assert row.severity is Severity.HIGH

    def test_the_full_sequence_from_the_brief(self, clean_db) -> None:
        """500 -> 750 -> 1,000 -> 1,200 -> 800, through the service."""
        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        anomaly_id = repo.insert_anomaly(_anomaly(500.0))

        observed: list[tuple[float, str, str]] = []
        for step, rate in enumerate([750.0, 1000.0, 1200.0, 800.0], start=1):
            at = BASE + timedelta(seconds=10 * step)
            existing = repo.get_anomaly(anomaly_id)
            assert existing is not None
            service._fold_into_episode(  # noqa: SLF001
                existing, _anomaly(rate, last_seen=at, detected_at=at)
            )
            row = repo.get_anomaly(anomaly_id)
            assert row is not None
            observed.append(
                (rate, str(row.severity), str(row.highest_severity))
            )

        assert observed == [
            (750.0, "MEDIUM", "MEDIUM"),
            (1000.0, "HIGH", "HIGH"),
            (1200.0, "HIGH", "HIGH"),
            # 800 pps classifies MEDIUM on its own, but this episode has
            # already measured 1,200 - the attack's severity is the worst
            # rate it validly reached, and the live 800 is in latest_value.
            (800.0, "HIGH", "HIGH"),
        ]
        history = repo.severity_transitions(anomaly_id)
        assert [(h["previous_severity"], h["new_severity"]) for h in history] == [
            ("MEDIUM", "HIGH"), ("HIGH", "MEDIUM"),
        ]
        # Escalations only: MEDIUM -> HIGH announced, HIGH -> MEDIUM not.
        assert len(service._bus.published) == 1  # noqa: SLF001


class TestTheServiceRefusesToClassifyWithoutAMeasurement:
    def test_a_non_flood_rule_keeps_its_severity(self, clean_db) -> None:
        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        anomaly_id = repo.insert_anomaly(
            _anomaly(300.0, rule_id="RULE-PORT-SCAN",
                     severity=Severity.MEDIUM)
        )
        existing = repo.get_anomaly(anomaly_id)
        assert existing is not None
        at = BASE + timedelta(seconds=10)
        service._fold_into_episode(  # noqa: SLF001
            existing,
            _anomaly(14.0, rule_id="RULE-PORT-SCAN", last_seen=at,
                     detected_at=at),
        )
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.severity is Severity.MEDIUM, "ports are not packets/second"
        assert row.event_count == 2, "the observation still counts"
        assert repo.severity_transitions(anomaly_id) == []

    def test_a_zero_rate_does_not_move_the_severity(self, clean_db) -> None:
        """A rate of zero is an absent measurement, not a quiet attack."""
        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        anomaly_id = repo.insert_anomaly(
            _anomaly(1200.0, severity=Severity.HIGH)
        )
        existing = repo.get_anomaly(anomaly_id)
        assert existing is not None
        at = BASE + timedelta(seconds=10)
        service._fold_into_episode(  # noqa: SLF001
            existing, _anomaly(0.0, last_seen=at, detected_at=at)
        )
        row = repo.get_anomaly(anomaly_id)
        assert row is not None
        assert row.severity is Severity.HIGH, "unchanged by a missing rate"
        assert row.event_count == 2
        assert repo.severity_transitions(anomaly_id) == []


class TestARampingFloodReachesHigh:
    """The reported symptom: an attack that escalates stays MEDIUM.

    The engine used to discard every observation it suppressed, so an
    episode's rate froze at whatever it was when its band was entered. A flood
    first reported at 500 pps that went on past 1,000 kept reporting 500.
    """

    def _ramp(self, rates_per_second: list[int], seconds_each: int = 6):
        """Drive the rule engine with SYN packets at a given rate schedule.

        Fixture traffic: timestamps are computed, not captured. Nothing here
        is presented as a real network observation.
        """
        from dataclasses import replace
        from datetime import timedelta

        from aethra_sec.analytics.anomaly_rules import (
            RULE_SYN_FLOOD,
            AnomalyRuleEngine,
            DetectionThresholds,
        )
        from tests.conftest import make_packet

        engine = AnomalyRuleEngine(DetectionThresholds(syn_per_second=200))
        base = make_packet(tcp_flags=0x02)
        raised = []
        elapsed = 0.0
        for rate in rates_per_second:
            step = 1.0 / rate
            for _ in range(rate * seconds_each):
                packet = replace(
                    base,
                    captured_at=base.captured_at + timedelta(seconds=elapsed),
                )
                raised.extend(engine.evaluate(packet))
                elapsed += step
        return [a for a in raised if a.rule_id == RULE_SYN_FLOOD]

    def test_a_flood_ramping_past_1000_is_measured_above_1000(self) -> None:
        from aethra_sec.models.enums import Severity

        emitted = self._ramp([300, 600, 1400])
        assert emitted, "the flood was not detected"

        peak_rate = max(a.observed_value for a in emitted)
        assert peak_rate >= 1000, (
            f"the highest rate the engine ever measured was {peak_rate:.1f} "
            "pps; a flood ramped to 1,400 pps must be measured above 1,000"
        )
        assert any(a.severity is Severity.HIGH for a in emitted), (
            "no observation reached HIGH"
        )

    def test_a_steady_flood_keeps_reporting_its_real_rate(self) -> None:
        """Not just at band entry: the rate stays current while it runs."""
        emitted = self._ramp([1400], seconds_each=12)
        updates = [a for a in emitted if a.measurement_only]
        assert updates, "a running flood must keep being measured"
        # Every update measures the flood as it is, not as it was when first
        # reported, so none of them sits at the detection threshold.
        assert min(a.observed_value for a in updates) > 200

    def test_escalation_survives_the_episode_in_the_database(
        self, clean_db
    ) -> None:
        """End to end: ramp the engine, fold each observation, read it back."""
        from aethra_sec.models.enums import Severity

        repo = AlertRepository(clean_db)
        service = _service(clean_db)
        emitted = self._ramp([300, 600, 1400])

        anomaly_id = None
        for observation in emitted:
            observation.first_seen = observation.first_seen or BASE
            observation.last_seen = observation.last_seen or BASE
            if anomaly_id is None:
                if observation.measurement_only:
                    continue
                anomaly_id = repo.insert_anomaly(observation)
                continue
            existing = repo.get_anomaly(anomaly_id)
            assert existing is not None
            service._fold_into_episode(existing, observation)  # noqa: SLF001

        assert anomaly_id is not None
        final = repo.get_anomaly(anomaly_id)
        assert final is not None
        assert final.highest_severity is Severity.HIGH, (
            f"episode peaked at {final.highest_severity} with a measured "
            f"peak of {final.observed_value} pps"
        )
        assert final.observed_value >= 1000
        history = repo.severity_transitions(anomaly_id)
        assert any(h["new_severity"] == "HIGH" for h in history), (
            "no transition into HIGH was recorded"
        )
