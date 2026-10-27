"""Repeated attacks of the same type are each detected (TEST 1-12).

The defect: a second attack of the same type that began less than 120 s after
the previous one's last packet was folded into it - one record, one
notification - and each fold moved the episode's end forward, so back-to-back
test runs chained into a single detection for as long as they kept coming.
Detection 2825 (15 Oct 2026) is one record covering six separate bursts.

These tests drive the real pipeline - the rule engine, the capture service's
``_store_anomaly``, Snort's ``_on_alert`` and the correlation service - against
the isolated test database. Every packet is synthetic and never leaves the
process; no network traffic is generated.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from aethra_sec.analytics.anomaly_rules import (
    RULE_HTTP_FLOOD,
    RULE_ICMP_FLOOD,
    RULE_SYN_FLOOD,
    RULE_UDP_FLOOD,
    AnomalyRuleEngine,
    DetectionThresholds,
)
from aethra_sec.core.events import EventType
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.models.enums import Severity
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.packet_capture import PacketCaptureService, PipelineCounters

GAP = 15  # detection.episode_gap_seconds default


class _Settings:
    """Settings as the services read them; values are the shipped defaults."""

    def __init__(self, **overrides) -> None:
        self.values = {
            "detection.episode_gap_seconds": GAP,
            "detection.suppression_window_seconds": 120,
            "correlation.window_seconds": 3600,  # lookback for a long test
            "correlation.enabled": True,
            "correlation.flood_grace_seconds": 30,
            "correlation.reopen_resolved": False,
        }
        self.values.update(overrides)

    def get_int(self, key, default=0):  # noqa: ANN001
        return int(self.values.get(key, default))

    def get_bool(self, key, default=False):  # noqa: ANN001
        return bool(self.values.get(key, default))

    def get_str(self, key, default=""):  # noqa: ANN001
        return str(self.values.get(key, default))

    def get_float(self, key, default=0.0):  # noqa: ANN001
        return float(self.values.get(key, default))


class _Bus:
    def __init__(self) -> None:
        self.published: list[tuple] = []

    def publish(self, event_type, payload) -> None:  # noqa: ANN001
        self.published.append((event_type, payload))


def _capture(db) -> PacketCaptureService:  # noqa: ANN001
    """The capture service's storage path, without starting a capture."""
    service = object.__new__(PacketCaptureService)
    service._alerts = AlertRepository(db)  # noqa: SLF001
    service._bus = _Bus()  # noqa: SLF001
    service._settings = _Settings()  # noqa: SLF001
    service._hosts = SimpleNamespace(find_id_by_ip=lambda _ip: None)  # noqa: SLF001
    service.counters = PipelineCounters()

    def no_statistics():
        raise RuntimeError("no live capture in this test")

    service.statistics = no_statistics  # type: ignore[method-assign]
    return service


class Pipeline:
    """Packets -> rule engine -> storage, exactly as the capture worker does."""

    def __init__(self, db, thresholds: DetectionThresholds | None = None) -> None:  # noqa: ANN001
        self.engine = AnomalyRuleEngine(thresholds or DetectionThresholds())
        self.service = _capture(db)
        self.repo = AlertRepository(db)
        self.emitted: list = []

    def feed(self, packets) -> None:  # noqa: ANN001
        for packet in packets:
            for anomaly in self.engine.evaluate(packet):
                self.emitted.append(anomaly)
                self.service._store_anomaly(anomaly)  # noqa: SLF001

    def rows(self, rule_id: str, src: str | None = None) -> list:
        clauses, params = ["rule_id = %s"], [rule_id]
        if src:
            clauses.append("src_ip = %s")
            params.append(src)
        found = self.repo.db.query(
            f"SELECT id FROM traffic_anomalies WHERE {' AND '.join(clauses)} "
            "ORDER BY first_seen", tuple(params),
        )
        return [self.repo.get_anomaly(int(r["id"])) for r in found]


def icmp_burst(start: datetime, seconds: float, pps: float, *, src="10.97.1.21",
               dst="10.97.1.26", replies=True):
    """Echo requests at ``pps`` for ``seconds``, each answered by the target."""
    step = 1.0 / pps
    for index in range(int(seconds * pps)):
        at = start + timedelta(seconds=index * step)
        yield CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst,
                             protocol="ICMP", icmp_type=8)
        if replies:
            yield CapturedPacket(captured_at=at + timedelta(microseconds=80),
                                 src_ip=dst, dst_ip=src, protocol="ICMP", icmp_type=0)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _correlation(db, settings: _Settings | None = None):  # noqa: ANN001
    from aethra_sec.analytics.risk_engine import RiskEngine
    from aethra_sec.core.event_bus import EventBus
    from aethra_sec.core.session import SessionManager
    from aethra_sec.database.repositories.audit import AuditRepository
    from aethra_sec.database.repositories.hosts import HostRepository
    from aethra_sec.database.repositories.incidents import IncidentRepository
    from aethra_sec.database.repositories.mitigation import MitigationRepository
    from aethra_sec.database.repositories.scans import ScanRepository
    from aethra_sec.security.audit import AuditService
    from aethra_sec.security.rbac import AccessControl
    from aethra_sec.services.correlation_service import CorrelationService
    from aethra_sec.services.mitigation_service import MitigationService

    audit = AuditService(AuditRepository(db))
    access = AccessControl(SessionManager(60), audit)
    mitigation = MitigationService(MitigationRepository(db), audit, access)
    service = CorrelationService(
        IncidentRepository(db), AlertRepository(db), ScanRepository(db),
        HostRepository(db), mitigation, settings or _Settings(), EventBus(),
        audit, access, RiskEngine(),
    )
    return service, IncidentRepository(db)


# ---------------------------------------------------------------------------
# TEST 1 - 100 distinct ICMP episodes
# ---------------------------------------------------------------------------
class Test1_HundredRepeatedEpisodes:
    def test_every_episode_is_detected_recorded_and_grouped_once(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        burst, pause = 6.0, 20.0  # 20 s quiet > the 15 s episode gap
        start = datetime.now(UTC) - timedelta(seconds=100 * (burst + pause) + 60)
        starts = []
        for number in range(100):
            begin = start + timedelta(seconds=number * (burst + pause))
            starts.append(begin)
            pipeline.feed(icmp_burst(begin, burst, 200))

        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 100, "every run is its own detection"
        assert len({row.id for row in rows}) == 100
        assert {row.src_ip for row in rows} == {"10.97.1.21"}, "replies never counted"
        for begin, row in zip(starts, rows):
            first = _utc(row.first_seen)
            last = _utc(row.last_seen)
            # first_seen is the triggering packet's time minus the 5 s rate
            # window (the start of the window that crossed the threshold).
            assert begin - timedelta(seconds=5) <= first <= begin + timedelta(seconds=burst)
            assert last <= begin + timedelta(seconds=burst + 1)
            assert row.event_count >= 1
            assert row.observed_value >= 120.0

        published = [p for p in pipeline.service._bus.published  # noqa: SLF001
                     if p[0] is EventType.TRAFFIC_ANOMALY_DETECTED]
        assert len(published) == 100, "each new episode is announced to the app once"

        # One primary attack result per episode.
        correlation, incidents = _correlation(clean_db)
        correlation.correlate_recent()
        assert len(incidents.search(limit=1000)) == 100

        # Reprocessing: the same detections and the same polling change nothing.
        for anomaly in [a for a in pipeline.emitted if a.starts_episode]:
            pipeline.service._store_anomaly(anomaly)  # noqa: SLF001
        for _ in range(3):
            correlation.correlate_recent()
        assert len(pipeline.rows(RULE_ICMP_FLOOD)) == 100
        assert len(incidents.search(limit=1000)) == 100


# ---------------------------------------------------------------------------
# TEST 2 - one continuous episode
# ---------------------------------------------------------------------------
class Test2_OneContinuousEpisode:
    def test_one_long_flood_is_one_detection_with_updated_measurements(
        self, clean_db
    ) -> None:
        pipeline = Pipeline(clean_db)
        begin = datetime.now(UTC) - timedelta(minutes=10)
        # 150 s: longer than the 120 s suppression window, which re-fires the
        # rule mid-flood - that must extend the episode, not start another.
        packets = list(icmp_burst(begin, 60, 300))
        packets += list(icmp_burst(begin + timedelta(seconds=60), 30, 800))
        packets += list(icmp_burst(begin + timedelta(seconds=90), 60, 300))
        pipeline.feed(packets)

        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 1
        row = rows[0]
        assert row.latest_rate == pytest.approx(300.0, abs=1.0)
        assert row.observed_value == pytest.approx(800.0, abs=1.0)
        assert row.current_severity is Severity.LOW
        assert row.highest_severity is Severity.MEDIUM
        # The first detection plus one measurement per second for 149 s.
        assert 145 <= row.event_count <= 151, row.event_count
        assert row.observation_count() == (row.event_count, "counted")
        assert _utc(row.first_seen) <= begin + timedelta(seconds=5)
        assert _utc(row.last_seen) >= begin + timedelta(seconds=149)
        # 300 pps over a 5 s window whose two ends are both inclusive.
        assert abs(row.evidence["latest_measurement"]["packets_in_window"] - 1500) <= 1


# ---------------------------------------------------------------------------
# TEST 3 - end, then repeat (same protocol, signature, source, destination)
# ---------------------------------------------------------------------------
class Test3_EndThenRepeat:
    def test_a_pause_longer_than_the_gap_gives_two_detections(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        begin = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(begin, 10, 300))
        pipeline.feed(icmp_burst(begin + timedelta(seconds=10 + 30), 10, 300))
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 2
        assert _utc(rows[0].last_seen) < _utc(rows[1].first_seen)

    def test_a_pause_shorter_than_the_gap_stays_one_episode(self, clean_db) -> None:
        """The documented policy: under 15 s quiet cannot be told apart from
        a stall in one run, so it is one episode (ATTACK_EPISODE_LIFECYCLE.md)."""
        pipeline = Pipeline(clean_db)
        begin = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(begin, 10, 300))
        pipeline.feed(icmp_burst(begin + timedelta(seconds=10 + 8), 10, 300))
        assert len(pipeline.rows(RULE_ICMP_FLOOD)) == 1

    def test_the_old_two_minute_chaining_no_longer_happens(self, clean_db) -> None:
        """Six bursts with the gaps measured inside detection 2825."""
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=10)
        lengths = [15, 14, 20, 5, 6, 7]
        gaps = [0, 5, 47, 12, 88, 64]
        for length, gap in zip(lengths, gaps):
            t += timedelta(seconds=gap)
            pipeline.feed(icmp_burst(t, length, 300))
            t += timedelta(seconds=length)
        # Gaps over 15 s (47, 88, 64) separate runs; 5 and 12 s do not.
        assert len(pipeline.rows(RULE_ICMP_FLOOD)) == 4


# ---------------------------------------------------------------------------
# TEST 4 - different sources
# ---------------------------------------------------------------------------
class Test4_DifferentSources:
    def test_two_sources_are_independent(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        begin = datetime.now(UTC) - timedelta(minutes=5)
        a = list(icmp_burst(begin, 10, 300, src="10.97.1.21", replies=False))
        b = list(icmp_burst(begin + timedelta(seconds=3), 10, 300, src="10.97.1.22",
                            replies=False))
        pipeline.feed(sorted(a + b, key=lambda p: p.captured_at))
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert sorted(r.src_ip for r in rows) == ["10.97.1.21", "10.97.1.22"]
        by_src = {r.src_ip: r for r in rows}
        assert _utc(by_src["10.97.1.22"].first_seen) > _utc(by_src["10.97.1.21"].first_seen)

    def test_one_source_attacking_a_second_target_is_not_lost(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        begin = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(begin, 10, 300, dst="10.97.1.26", replies=False))
        pipeline.feed(icmp_burst(begin + timedelta(seconds=40), 10, 300,
                                 dst="10.97.1.27", replies=False))
        assert sorted(r.dst_ip for r in pipeline.rows(RULE_ICMP_FLOOD)) == [
            "10.97.1.26", "10.97.1.27"
        ]


# ---------------------------------------------------------------------------
# TEST 5 - threshold reset; severity bands do not control the boundary
# ---------------------------------------------------------------------------
class Test5_ThresholdReset:
    def test_below_trigger_long_enough_ends_the_episode(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(t, 10, 50))  # below the 120 pps trigger
        pipeline.feed(icmp_burst(t + timedelta(seconds=10), 10, 300))
        # Traffic CONTINUES but below the trigger for 25 s: the episode ends.
        pipeline.feed(icmp_burst(t + timedelta(seconds=20), 25, 50))
        pipeline.feed(icmp_burst(t + timedelta(seconds=45), 10, 300))
        assert len(pipeline.rows(RULE_ICMP_FLOOD)) == 2

    def test_falling_below_a_severity_band_does_not_reset(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(t, 10, 1100, replies=False))           # HIGH
        pipeline.feed(icmp_burst(t + timedelta(seconds=10), 20, 300,    # LOW, still
                                 replies=False))                        # above trigger
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 1
        assert rows[0].highest_severity is Severity.HIGH
        assert rows[0].current_severity is Severity.LOW


# ---------------------------------------------------------------------------
# TEST 6 - notification policy does not erase detections
# ---------------------------------------------------------------------------
class Test6_NotificationCooldown:
    def test_episodes_inside_the_old_cooldown_are_each_recorded_and_announced(
        self, clean_db
    ) -> None:
        from aethra_sec.services.notification_service import NotificationService

        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        for number in range(4):  # 4 runs inside 120 s (the notification window)
            pipeline.feed(icmp_burst(t + timedelta(seconds=number * 28), 8, 700,
                                     replies=False))
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 4
        events = [p for p in pipeline.service._bus.published  # noqa: SLF001
                  if p[0] is EventType.TRAFFIC_ANOMALY_DETECTED]
        # Each run is announced when it opens, and once more when it
        # escalates (LOW at the 120 pps trigger -> MEDIUM at 700 pps).
        announced = {p[1].anomaly.id for p in events}
        assert announced == {row.id for row in rows}
        assert len(events) <= 8
        # The notification de-duplication reference is per detection id, so
        # four detections cannot share one cooldown slot.
        assert NotificationService.ANOMALY_DEDUP_SECONDS == 120
        assert len({row.id for row in rows}) == 4

    def test_a_low_episode_is_recorded_even_though_it_is_not_announced(
        self, clean_db
    ) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(t, 8, 200, replies=False))  # LOW
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 1 and rows[0].severity is Severity.LOW


# ---------------------------------------------------------------------------
# TEST 7 - repeated processing and polling
# ---------------------------------------------------------------------------
class Test7_RepeatedPolling:
    def test_the_same_saved_events_create_nothing_new(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(t, 8, 300, replies=False))
        pipeline.feed(icmp_burst(t + timedelta(seconds=40), 8, 300, replies=False))
        before = [(r.id, r.event_count, r.observed_value)
                  for r in pipeline.rows(RULE_ICMP_FLOOD)]
        starts = [a for a in pipeline.emitted if a.starts_episode]
        assert len(starts) == 2
        for _ in range(5):
            for anomaly in starts:
                pipeline.service._store_anomaly(anomaly)  # noqa: SLF001
        after = [(r.id, r.event_count, r.observed_value)
                 for r in pipeline.rows(RULE_ICMP_FLOOD)]
        assert before == after

        correlation, incidents = _correlation(clean_db)
        for _ in range(5):
            correlation.correlate_recent()
        assert len(incidents.search()) == 2


# ---------------------------------------------------------------------------
# TEST 8 - sensor restart
# ---------------------------------------------------------------------------
class Test8_SensorRestart:
    def test_restart_mid_flood_continues_and_a_later_run_is_new(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        pipeline.feed(icmp_burst(t, 10, 300, replies=False))
        pipeline.engine.reset()  # capture restarted: all in-memory state gone
        pipeline.feed(icmp_burst(t + timedelta(seconds=11), 10, 300, replies=False))
        assert len(pipeline.rows(RULE_ICMP_FLOOD)) == 1, "same flood, continued"
        pipeline.engine.reset()
        pipeline.feed(icmp_burst(t + timedelta(seconds=60), 10, 300, replies=False))
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 2, "a new run after the restart is detected"
        assert rows[0].event_count > 1, "the earlier record is retained"


# ---------------------------------------------------------------------------
# TEST 9 - bounded high-severity burst
# ---------------------------------------------------------------------------
class Test9_HighSeverityBurst:
    def test_twenty_high_episodes_are_each_recorded_with_bounded_work(
        self, clean_db
    ) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=15)
        started = time.perf_counter()
        for number in range(20):
            pipeline.feed(icmp_burst(t + timedelta(seconds=number * 25), 6, 1500,
                                     replies=False))
        elapsed = time.perf_counter() - started
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 20
        assert all(row.highest_severity is Severity.HIGH for row in rows)
        new = [p for p in pipeline.service._bus.published  # noqa: SLF001
               if p[0] is EventType.TRAFFIC_ANOMALY_DETECTED]
        # One per episode, plus at most two escalation announcements each.
        assert 20 <= len(new) <= 60
        assert pipeline.engine.statistics["tracked_keys"] < 200
        assert elapsed < 60, f"{elapsed:.1f}s for 180,000 packets and their writes"


# ---------------------------------------------------------------------------
# TEST 10 - cross-protocol independence
# ---------------------------------------------------------------------------
class Test10_CrossProtocol:
    def test_icmp_udp_syn_and_http_floods_are_each_detected(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        src, dst = "10.97.2.10", "10.97.2.20"
        packets = list(icmp_burst(t, 10, 300, src=src, dst=dst, replies=False))
        for index in range(4000):  # 400 pps UDP to one port, 10 s
            packets.append(CapturedPacket(
                captured_at=t + timedelta(seconds=index / 400.0), src_ip=src,
                dst_ip=dst, protocol="UDP", src_port=40000, dst_port=9999))
        for index in range(3000):  # 300 pps unanswered SYNs, 10 s
            packets.append(CapturedPacket(
                captured_at=t + timedelta(seconds=index / 300.0), src_ip=src,
                dst_ip=dst, protocol="TCP", src_port=1024 + index, dst_port=80,
                tcp_flags=0x02))
        for index in range(300):  # 30 HTTP requests/s, 10 s
            packets.append(CapturedPacket(
                captured_at=t + timedelta(seconds=index / 30.0), src_ip=src,
                dst_ip=dst, protocol="TCP", src_port=50000, dst_port=80,
                tcp_flags=0x18, app_protocol="HTTP"))
        pipeline.feed(sorted(packets, key=lambda p: p.captured_at))
        found = {rule: len(pipeline.rows(rule, src)) for rule in (
            RULE_ICMP_FLOOD, RULE_UDP_FLOOD, RULE_SYN_FLOOD, RULE_HTTP_FLOOD)}
        assert found == {RULE_ICMP_FLOOD: 1, RULE_UDP_FLOOD: 1,
                         RULE_SYN_FLOOD: 1, RULE_HTTP_FLOOD: 1}, found

    def test_a_running_icmp_episode_does_not_hide_a_new_udp_episode(
        self, clean_db
    ) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        src, dst = "10.97.2.11", "10.97.2.21"
        packets = list(icmp_burst(t, 60, 300, src=src, dst=dst, replies=False))
        for burst in (10, 40):  # two UDP runs while ICMP never stops
            for index in range(2000):
                packets.append(CapturedPacket(
                    captured_at=t + timedelta(seconds=burst + index / 400.0),
                    src_ip=src, dst_ip=dst, protocol="UDP", src_port=40000,
                    dst_port=9999))
        pipeline.feed(sorted(packets, key=lambda p: p.captured_at))
        assert len(pipeline.rows(RULE_ICMP_FLOOD, src)) == 1
        assert len(pipeline.rows(RULE_UDP_FLOOD, src)) == 2


# ---------------------------------------------------------------------------
# TEST 11 - missing or incomplete data
# ---------------------------------------------------------------------------
class Test11_MissingData:
    def test_undecoded_types_and_missing_times_are_handled(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        packets = [CapturedPacket(captured_at=t + timedelta(seconds=i / 300.0),
                                  src_ip="10.97.3.1", dst_ip="10.97.3.2",
                                  protocol="ICMP", icmp_type=None)
                   for i in range(3000)]
        pipeline.feed(packets)
        rows = pipeline.rows(RULE_ICMP_FLOOD)
        assert len(rows) == 1
        assert "capture_completeness" not in rows[0].evidence, "nothing invented"

        # A detection record with no packet times at all still stores safely.
        from aethra_sec.models.enums import EvidenceSource, ThreatCategory
        from aethra_sec.models.threat import TrafficAnomaly

        bare = TrafficAnomaly(
            rule_id=RULE_ICMP_FLOOD, category=ThreatCategory.ICMP_FLOOD,
            title="TEST FIXTURE - not a real detection", src_ip="10.97.3.9",
            dst_ip="10.97.3.8", protocol="ICMP", observed_value=0.0,
            threshold_value=120.0, window_seconds=5, source=EvidenceSource.PYSHARK,
            starts_episode=True,
        )
        pipeline.service._store_anomaly(bare)  # noqa: SLF001
        stored = pipeline.rows(RULE_ICMP_FLOOD, "10.97.3.9")
        assert len(stored) == 1
        assert stored[0].latest_value == 0.0


# ---------------------------------------------------------------------------
# Snort: repeats extend an episode; a later run is a new alert
# ---------------------------------------------------------------------------
def _snort_service(db):  # noqa: ANN001
    from aethra_sec.analytics.risk_engine import RiskEngine
    from aethra_sec.services.snort_service import SnortService

    service = SnortService.__new__(SnortService)
    service._alerts = AlertRepository(db)  # noqa: SLF001
    service._bus = _Bus()  # noqa: SLF001
    service._settings = _Settings()  # noqa: SLF001
    service._risk = RiskEngine()  # noqa: SLF001
    service._rate_probe = None  # noqa: SLF001
    service._resolve_host = lambda _ip: None  # noqa: SLF001
    service._stored = service._duplicates = service._store_failures = 0  # noqa: SLF001
    return service


def _snort_line(at: datetime, sid: int = 1000006,
                message: str = "ICMP flood - possible ping flood/DoS"):
    from aethra_sec.integrations.snort.parser import ParsedAlert

    stamp = at.strftime("%m/%d-%H:%M:%S.%f")
    return ParsedAlert(
        message=message, timestamp=at, generator_id=1, signature_id=sid,
        revision=2, classification="Attempted Denial of Service", priority=2,
        protocol="ICMP", src_ip="10.97.4.21", dst_ip="10.97.4.26",
        raw=f"{stamp} [**] [1:{sid}:2] {message} [**] {{ICMP}} 10.97.4.21 -> 10.97.4.26",
        format="fast",
    )


class TestSnortEpisodes:
    def test_repeats_fold_and_a_later_run_opens_a_new_alert(self, clean_db) -> None:
        service = _snort_service(clean_db)
        repo = AlertRepository(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        for second in range(0, 20, 5):  # one run: an alert every 5 s for 20 s
            service._on_alert(_snort_line(t + timedelta(seconds=second)), "file")  # noqa: SLF001
        for second in range(60, 80, 5):  # a second run after 45 s quiet
            service._on_alert(_snort_line(t + timedelta(seconds=second)), "file")  # noqa: SLF001
        rows = repo.db.query(
            "SELECT id, duplicate_count FROM snort_alerts ORDER BY id"
        )
        assert [int(r["duplicate_count"]) for r in rows] == [4, 4]

    def test_rereading_the_same_lines_is_idempotent(self, clean_db) -> None:
        service = _snort_service(clean_db)
        repo = AlertRepository(clean_db)
        t = datetime.now(UTC) - timedelta(minutes=5)
        lines = [_snort_line(t + timedelta(seconds=s)) for s in (0, 5, 60)]
        for line in lines:
            service._on_alert(line, "file")  # noqa: SLF001
        before = repo.db.query("SELECT id FROM snort_alerts ORDER BY id")
        for line in lines:
            service._on_alert(line, "file")  # noqa: SLF001
        after = repo.db.query("SELECT id FROM snort_alerts ORDER BY id")
        assert len(before) == len(after) == 2
