"""AETHRA-SEC's own detections must reach the notification pipeline.

The defect: ``NotificationService._handle`` routed ten event types and
``TRAFFIC_ANOMALY_DETECTED`` was not among them, so every detection raised by
AETHRA-SEC's own rules produced an alerts-table row and nothing else - no
notification, therefore no NOTIFICATION_STORED event, therefore no popup and
no sound. Snort alerts were unaffected, which is why the pipeline looked
partly alive.

Each detection here is a fixture built by the test. None is a real network
observation, and no test asserts that a sound was audible - only that playback
was requested or refused according to the configured policy.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aethra_sec.core.events import AnomalyPayload, Event, EventType
from aethra_sec.models.enums import (
    EvidenceSource,
    NotificationLevel,
    Severity,
    ThreatCategory,
)
from aethra_sec.models.threat import TrafficAnomaly
from aethra_sec.services.audio_alert_service import _ORDER
from aethra_sec.services.notification_service import (
    level_for_severity,
    ANOMALY_REFERENCE,
    NotificationService,
)

BASE = datetime(2026, 10, 13, 9, 0, 0, tzinfo=UTC)


def _anomaly(anomaly_id: int = 1, severity: Severity = Severity.HIGH,
             **overrides) -> TrafficAnomaly:
    fields = {
        "id": anomaly_id,
        "rule_id": "RULE-TCP-SYN-RATE",
        "category": ThreatCategory.UNCLASSIFIED,
        "title": "TEST FIXTURE - not a real detection",
        "severity": severity,
        "src_ip": "10.95.0.10",
        "dst_ip": "10.95.0.20",
        "protocol": "TCP",
        "observed_value": 1200.0,
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


def _service(clean_db, bus, settings_service) -> NotificationService:
    from aethra_sec.database.repositories.settings import (
        ErrorRepository,
        NotificationRepository,
    )

    return NotificationService(
        NotificationRepository(clean_db),
        ErrorRepository(clean_db),
        settings_service,
        bus,
    )


class _Bus:
    """Records published events; never delivers them."""

    def __init__(self) -> None:
        self.published: list[tuple] = []

    def publish(self, event_type, payload) -> None:  # noqa: ANN001
        self.published.append((event_type, payload))

    def subscribe(self, *_a, **_k):  # noqa: ANN001, ANN201
        return None

    def unsubscribe(self, *_a, **_k) -> None:  # noqa: ANN001
        return None


class _Settings:
    """The notification settings a test wants, without a session or a write.

    SettingsService.set() takes an authenticated session and persists; these
    tests are about how the service READS a policy, so the policy is supplied
    directly.
    """

    def __init__(self, **values) -> None:
        self._values = {
            "notifications.enabled": True,
            "notifications.min_severity": "MEDIUM",
            "notifications.sound_enabled": True,
            "notifications.sound_min_level": "WARNING",
            "notifications.sound_dedup_seconds": 30,
        }
        self._values.update(values)

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self._values.get(key, default))

    def get_str(self, key: str, default: str = "") -> str:
        return str(self._values.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self._values.get(key, default))


@pytest.fixture
def bus() -> _Bus:
    return _Bus()


@pytest.fixture
def settings_service(clean_db):  # noqa: ANN001, ANN201
    from aethra_sec.services.settings_service import SettingsService
    from aethra_sec.database.repositories.settings import SettingsRepository

    return SettingsService(SettingsRepository(clean_db))


def _fire(service: NotificationService, anomaly: TrafficAnomaly) -> None:
    """Deliver the detection exactly as the event bus would."""
    service._handle(  # noqa: SLF001
        Event(
            type=EventType.TRAFFIC_ANOMALY_DETECTED,
            payload=AnomalyPayload(
                anomaly=anomaly, source=EvidenceSource.PYSHARK
            ),
        )
    )


class TestTheEventIsRoutedAtAll:
    """The defect itself."""

    def test_traffic_anomaly_detected_is_handled(self) -> None:
        """It was absent from the handler map, which was the whole bug."""
        import inspect

        source = inspect.getsource(NotificationService._handle)
        assert "TRAFFIC_ANOMALY_DETECTED" in source, (
            "detections raised by AETHRA-SEC's own rules are not routed to "
            "the notification service"
        )

    def test_a_high_detection_produces_a_notification(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(101, Severity.HIGH))

        rows = clean_db.query(
            "SELECT level, title, message, reference_type, reference_id "
            "FROM notifications WHERE reference_type = %s",
            (ANOMALY_REFERENCE,),
        )
        assert len(rows) == 1, "a HIGH detection raised no notification"
        assert rows[0]["reference_id"] == 101
        # The level comes from the one severity-to-level mapping, and must be
        # loud enough to pass a WARNING sound floor. Asserting the literal
        # label instead would re-pin the collapse that made a MEDIUM
        # detection inaudible.
        assert rows[0]["level"] == str(level_for_severity(Severity.HIGH))
        assert _ORDER.index(rows[0]["level"]) >= _ORDER.index("WARNING"), (
            "a HIGH detection is not audible at the default sound floor"
        )
        assert "HIGH" in rows[0]["title"]

    def test_the_stored_event_is_announced(
        self, clean_db, bus, settings_service
    ) -> None:
        """Without the announcement there is no popup and no sound."""
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(102, Severity.HIGH))
        kinds = [e[0] for e in bus.published]
        assert EventType.NOTIFICATION_STORED in kinds


class TestNotificationContentIsReal:
    def test_the_message_carries_the_detection_not_invented_values(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(103, Severity.HIGH))
        row = clean_db.query_one(
            "SELECT message FROM notifications WHERE reference_id = 103")
        assert "RULE-TCP-SYN-RATE" in row["message"]
        assert "10.95.0.10" in row["message"]
        assert "10.95.0.20" in row["message"]

    def test_a_missing_source_is_not_invented(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(104, Severity.HIGH, src_ip="", dst_ip=""))
        row = clean_db.query_one(
            "SELECT message FROM notifications WHERE reference_id = 104")
        assert "source not recorded" in row["message"]

    def test_an_unsaved_detection_raises_nothing(
        self, clean_db, bus, settings_service
    ) -> None:
        """There would be no record for the operator to open."""
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(1, Severity.HIGH, id=None))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_type = %s",
            (ANOMALY_REFERENCE,)) == 0


class TestSeverityEligibility:
    def test_medium_qualifies_at_the_default_minimum(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(201, Severity.MEDIUM))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_id = 201") == 1

    def test_low_is_below_the_default_minimum(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(202, Severity.LOW))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_id = 202") == 0

    def test_the_minimum_is_honoured_when_raised(
        self, clean_db, bus
    ) -> None:
        service = _service(
            clean_db, bus, _Settings(**{"notifications.min_severity": "HIGH"})
        )
        _fire(service, _anomaly(203, Severity.MEDIUM))
        _fire(service, _anomaly(204, Severity.HIGH))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_id = 203") == 0
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_id = 204") == 1

    def test_severity_is_compared_by_rank_not_alphabetically(self) -> None:
        """"HIGH" < "LOW" < "MEDIUM" as strings; the ranks say otherwise."""
        assert Severity.HIGH.at_least(Severity.MEDIUM)
        assert Severity.MEDIUM.at_least(Severity.MEDIUM)
        assert not Severity.LOW.at_least(Severity.MEDIUM)
        assert sorted(["HIGH", "LOW", "MEDIUM"]) == ["HIGH", "LOW", "MEDIUM"]


class TestNotificationsDisabled:
    def test_nothing_is_raised_when_disabled(
        self, clean_db, bus
    ) -> None:
        service = _service(
            clean_db, bus, _Settings(**{"notifications.enabled": False})
        )
        _fire(service, _anomaly(301, Severity.HIGH))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_type = %s",
            (ANOMALY_REFERENCE,)) == 0


class TestDeduplicationAndEscalation:
    def test_a_repeat_at_the_same_severity_is_suppressed(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        for _ in range(5):
            _fire(service, _anomaly(401, Severity.HIGH))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_id = 401") == 1

    def test_an_escalation_is_announced_separately(
        self, clean_db, bus, settings_service
    ) -> None:
        """The case the brief calls out: MEDIUM then HIGH must both land."""
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(402, Severity.MEDIUM))
        _fire(service, _anomaly(402, Severity.HIGH))
        rows = clean_db.query(
            "SELECT level, title FROM notifications WHERE reference_id = 402 "
            "ORDER BY id")
        assert len(rows) == 2, "the escalation to HIGH was suppressed"
        assert "MEDIUM" in rows[0]["title"]
        assert "HIGH" in rows[1]["title"]
        assert rows[1]["level"] == str(level_for_severity(Severity.HIGH))
        assert _ORDER.index(rows[1]["level"]) >= _ORDER.index("WARNING"), (
            "the escalation to HIGH is not audible"
        )
        # And the MEDIUM that preceded it must be audible too, which is the
        # half of the bug that made a real attack pop up in silence.
        assert _ORDER.index(rows[0]["level"]) >= _ORDER.index("WARNING"), (
            "a MEDIUM detection is still inaudible"
        )

    def test_one_detections_dedup_does_not_suppress_another(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        _fire(service, _anomaly(403, Severity.HIGH))
        _fire(service, _anomaly(404, Severity.HIGH))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_type = %s",
            (ANOMALY_REFERENCE,)) == 2


class TestABurstStaysBounded:
    def test_many_distinct_detections_each_notify_once(
        self, clean_db, bus, settings_service
    ) -> None:
        """Distinct events are not lost, and repeats do not multiply."""
        service = _service(clean_db, bus, settings_service)
        for anomaly_id in range(500, 530):
            for _ in range(4):          # each one repeats four times
                _fire(service, _anomaly(anomaly_id, Severity.HIGH))
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_type = %s",
            (ANOMALY_REFERENCE,)) == 30, (
            "30 distinct detections repeated four times each must produce "
            "30 notifications, not 120 and not fewer"
        )


class TestFailuresAreNotSilent:
    def test_a_broken_payload_does_not_raise(
        self, clean_db, bus, settings_service
    ) -> None:
        """A notification failure must never break detection."""
        service = _service(clean_db, bus, settings_service)
        service._handle(  # noqa: SLF001
            Event(type=EventType.TRAFFIC_ANOMALY_DETECTED, payload=None)
        )
        service._handle(  # noqa: SLF001
            Event(
                type=EventType.TRAFFIC_ANOMALY_DETECTED,
                payload=AnomalyPayload(anomaly=None),
            )
        )
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_type = %s",
            (ANOMALY_REFERENCE,)) == 0

    def test_a_detection_without_a_severity_is_refused_not_guessed(
        self, clean_db, bus, settings_service
    ) -> None:
        service = _service(clean_db, bus, settings_service)
        # A plain string where a Severity belongs.
        broken = _anomaly(601, Severity.HIGH)
        broken.severity = "HIGH"
        _fire(service, broken)
        assert clean_db.query_value(
            "SELECT COUNT(*) FROM notifications WHERE reference_id = 601"
        ) == 0, "a non-Severity value must not be coerced into one"
