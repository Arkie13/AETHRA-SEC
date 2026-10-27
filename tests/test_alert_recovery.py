"""Alert recovery: attacks that crossed a trigger must reach the Alerts table.

The defect (16 Oct 2026): a TCP SYN flood aimed at a LISTENING port raised no
detection. The SYN rule counted the target's SYN/ACK replies as completed
connections, so a server that answered every SYN made the flood look like a
busy, healthy client - and the rule discarded it without a log line. That
day's test runs produced 142 ICMP and 125 UDP detections but one TCP-SYN, and
every SYN burst was aimed at XAMPP's Apache on port 80.

A second, diagnostic defect hid the cause: the near-miss log line is written
when the rising rate first crosses 60% of a trigger, so every flood "measured"
exactly 60% of its trigger and read as capture loss. The engine now keeps the
PEAK rate per source and rule, and System Health shows it.

These tests drive the real rule engine, the capture service's
``_store_anomaly`` and the real Alerts query (``search_anomalies``) against
the isolated test database. Every packet is synthetic and never leaves the
process. Nothing here lowers a threshold or creates a detection the rules did
not raise.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from aethra_sec.analytics.anomaly_rules import (
    NEAR_MISS_LEDGER_MAX,
    RULE_ICMP_FLOOD,
    RULE_SYN_FLOOD,
    AnomalyRuleEngine,
    DetectionThresholds,
    flood_severity,
)
from aethra_sec.models.enums import ServiceState, Severity
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.health_service import (
    HealthService,
    SubsystemProbes,
    describe_near_miss,
    near_miss_summary,
)
from tests.test_repeated_attack_episodes import Pipeline, icmp_burst

ATTACKER, TARGET = "10.98.1.21", "10.98.1.26"

SYN, SYN_ACK, ACK, RST, PSH_ACK = 0x02, 0x12, 0x10, 0x04, 0x18


def syn_flood_on_listening_port(start: datetime, seconds: float, pps: float,
                                *, src: str = ATTACKER, dst: str = TARGET):
    """What hping3 -S -p 80 against a running web server puts on the wire.

    The attacker sends a bare SYN; the server answers SYN/ACK; the attacker's
    kernel, which never opened the connection, answers that with RST. No
    handshake ever completes, although every SYN is answered.
    """
    step = 1.0 / pps
    for index in range(int(seconds * pps)):
        at = start + timedelta(seconds=index * step)
        port = 1024 + index % 60000
        yield CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst,
                             protocol="TCP", src_port=port, dst_port=80,
                             tcp_flags=SYN)
        yield CapturedPacket(captured_at=at + timedelta(microseconds=150),
                             src_ip=dst, dst_ip=src, protocol="TCP",
                             src_port=80, dst_port=port, tcp_flags=SYN_ACK)
        yield CapturedPacket(captured_at=at + timedelta(microseconds=300),
                             src_ip=src, dst_ip=dst, protocol="TCP",
                             src_port=port, dst_port=80, tcp_flags=RST)


def completed_connections(start: datetime, seconds: float, pps: float,
                          *, src: str = ATTACKER, dst: str = TARGET):
    """A client opening real connections at ``pps``: SYN, SYN/ACK, ACK."""
    step = 1.0 / pps
    for index in range(int(seconds * pps)):
        at = start + timedelta(seconds=index * step)
        port = 1024 + index % 60000
        yield CapturedPacket(captured_at=at, src_ip=src, dst_ip=dst,
                             protocol="TCP", src_port=port, dst_port=80,
                             tcp_flags=SYN)
        yield CapturedPacket(captured_at=at + timedelta(microseconds=150),
                             src_ip=dst, dst_ip=src, protocol="TCP",
                             src_port=80, dst_port=port, tcp_flags=SYN_ACK)
        yield CapturedPacket(captured_at=at + timedelta(microseconds=300),
                             src_ip=src, dst_ip=dst, protocol="TCP",
                             src_port=port, dst_port=80, tcp_flags=ACK)


def _start() -> datetime:
    return datetime.now(UTC) - timedelta(minutes=5)


def _engine_run(packets) -> tuple[AnomalyRuleEngine, list]:  # noqa: ANN001
    engine = AnomalyRuleEngine(DetectionThresholds())
    fired = [a for p in packets for a in engine.evaluate(p)]
    return engine, fired


# ---------------------------------------------------------------------------
# TEST A - the root cause: a SYN flood at a listening port is detected
# ---------------------------------------------------------------------------
class TestA_SynFloodOnListeningPort:
    def test_answered_syn_flood_is_detected(self) -> None:
        _engine, fired = _engine_run(syn_flood_on_listening_port(_start(), 8, 300))
        syn = [a for a in fired if a.rule_id == RULE_SYN_FLOOD]
        assert syn, "a 300 pps SYN flood the server answers must be detected"
        evidence = syn[0].evidence
        assert evidence["handshake_acks_from_source"] == 0
        # The server DID answer - which is exactly what the old rule mistook
        # for completed connections.
        assert evidence["syn_ack_replies_observed"] > 0

    def test_the_old_reply_based_ratio_would_have_hidden_it(self) -> None:
        """Proves the defect, from the same traffic: replies ~= SYNs."""
        _engine, fired = _engine_run(syn_flood_on_listening_port(_start(), 8, 300))
        evidence = next(a for a in fired if a.rule_id == RULE_SYN_FLOOD).evidence
        old_unanswered = 1.0 - min(
            1.0, evidence["syn_ack_replies_observed"] / evidence["syn_packets_in_window"]
        )
        assert old_unanswered < DetectionThresholds().syn_unanswered_ratio

    def test_unanswered_syn_flood_is_still_detected(self) -> None:
        packets = [
            CapturedPacket(captured_at=_start() + timedelta(seconds=i / 300.0),
                           src_ip=ATTACKER, dst_ip=TARGET, protocol="TCP",
                           src_port=1024 + i, dst_port=7676, tcp_flags=SYN)
            for i in range(2400)
        ]
        _engine, fired = _engine_run(packets)
        assert any(a.rule_id == RULE_SYN_FLOOD for a in fired)


# ---------------------------------------------------------------------------
# TEST B - completed connections are still not a flood, and say why
# ---------------------------------------------------------------------------
class TestB_CompletedConnectionsAreNotAFlood:
    def test_no_detection_and_the_reason_is_recorded(self) -> None:
        engine, fired = _engine_run(completed_connections(_start(), 8, 300))
        assert not [a for a in fired if a.rule_id == RULE_SYN_FLOOD]
        misses = [m for m in engine.near_misses() if m["rule"] == RULE_SYN_FLOOD]
        assert len(misses) == 1
        assert "completed handshakes" in misses[0]["reason"]
        assert misses[0]["peak_rate"] >= DetectionThresholds().syn_per_second
        assert engine.statistics["syn_crossings_set_aside"] > 0

    def test_http_requests_alongside_a_syn_flood_do_not_hide_it(self) -> None:
        start = _start()
        packets = list(syn_flood_on_listening_port(start, 8, 300))
        packets += [
            CapturedPacket(captured_at=start + timedelta(seconds=i / 30.0),
                           src_ip=ATTACKER, dst_ip=TARGET, protocol="TCP",
                           src_port=50000, dst_port=80, tcp_flags=PSH_ACK,
                           app_protocol="HTTP")
            for i in range(240)
        ]
        packets.sort(key=lambda p: p.captured_at)
        _engine, fired = _engine_run(packets)
        assert any(a.rule_id == RULE_SYN_FLOOD for a in fired)


# ---------------------------------------------------------------------------
# TEST C - near misses report the peak, not the first 60% crossing
# ---------------------------------------------------------------------------
class TestC_NearMissPeak:
    def test_peak_rate_is_kept(self) -> None:
        engine, fired = _engine_run(
            icmp_burst(_start(), 10, 100, src=ATTACKER, dst=TARGET, replies=False)
        )
        assert not fired
        miss = next(m for m in engine.near_misses() if m["rule"] == RULE_ICMP_FLOOD)
        threshold = DetectionThresholds().icmp_per_second
        # The old log line reported 72.0 (60% of 120) for this traffic.
        assert miss["peak_rate"] >= 99.0
        assert miss["peak_rate"] > threshold * 0.6
        assert miss["reason"] == ""

    def test_a_ramp_that_then_fires_is_not_a_near_miss(self) -> None:
        start = _start()
        packets = list(icmp_burst(start, 5, 80, src=ATTACKER, dst=TARGET,
                                  replies=False))
        packets += list(icmp_burst(start + timedelta(seconds=5), 6, 300,
                                   src=ATTACKER, dst=TARGET, replies=False))
        engine, fired = _engine_run(packets)
        assert any(a.rule_id == RULE_ICMP_FLOOD for a in fired)
        assert not [m for m in engine.near_misses() if m["rule"] == RULE_ICMP_FLOOD]

    def test_the_ledger_is_bounded(self) -> None:
        engine = AnomalyRuleEngine(DetectionThresholds())
        start = _start()
        for host in range(NEAR_MISS_LEDGER_MAX + 50):
            src = f"10.99.{host // 250}.{host % 250 + 1}"
            for packet in icmp_burst(start, 5, 90, src=src, dst=TARGET,
                                     replies=False):
                engine.evaluate(packet)
        assert len(engine.near_misses()) <= NEAR_MISS_LEDGER_MAX
        assert engine.statistics["near_misses_evicted"] >= 50


# ---------------------------------------------------------------------------
# TEST D - the full pipeline: crossing -> stored -> the real Alerts query
# ---------------------------------------------------------------------------
class TestD_FullPipelineToAlertsQuery:
    def test_crossed_triggers_appear_in_the_alerts_query(self, clean_db) -> None:
        pipeline = Pipeline(clean_db)
        start = _start()
        packets = list(icmp_burst(start, 8, 300, src=ATTACKER, dst=TARGET,
                                  replies=True))
        packets += list(syn_flood_on_listening_port(start, 8, 300))
        pipeline.feed(sorted(packets, key=lambda p: p.captured_at))

        assert len(pipeline.rows(RULE_ICMP_FLOOD, ATTACKER)) == 1
        assert len(pipeline.rows(RULE_SYN_FLOOD, ATTACKER)) == 1
        # The Alerts screen's default view: AETHRA-SEC detections, last 24 h.
        shown = pipeline.repo.search_anomalies(
            start=datetime.now(UTC) - timedelta(hours=24), limit=1000,
        )
        rules = {row.rule_id for row in shown if row.src_ip == ATTACKER}
        assert {RULE_ICMP_FLOOD, RULE_SYN_FLOOD} <= rules

    def test_below_trigger_creates_no_row(self, clean_db) -> None:
        """No fabrication: traffic under every trigger stores nothing."""
        pipeline = Pipeline(clean_db)
        pipeline.feed(icmp_burst(_start(), 10, 100, src=ATTACKER, dst=TARGET,
                                 replies=False))
        assert pipeline.emitted == []
        assert pipeline.rows(RULE_ICMP_FLOOD) == []
        assert pipeline.engine.near_misses()


# ---------------------------------------------------------------------------
# TEST E - severity bands are unchanged and separate from the trigger
# ---------------------------------------------------------------------------
class TestE_SeverityBandsUnchanged:
    def test_band_edges(self) -> None:
        assert flood_severity(499.9)[0] is Severity.LOW
        assert flood_severity(500.0)[0] is Severity.MEDIUM
        assert flood_severity(999.9)[0] is Severity.MEDIUM
        assert flood_severity(1000.0)[0] is Severity.HIGH

    def test_thresholds_unchanged(self) -> None:
        thresholds = DetectionThresholds()
        assert thresholds.icmp_per_second == 120
        assert thresholds.udp_per_second == 300
        assert thresholds.syn_per_second == 200
        assert thresholds.syn_unanswered_ratio == 0.8


# ---------------------------------------------------------------------------
# TEST F - System Health says when attacks were measured but not detected
# ---------------------------------------------------------------------------
class TestF_HealthReportsNearMisses:
    MISS = {
        "rule": RULE_SYN_FLOOD, "source": ATTACKER, "peak_rate": 310.0,
        "threshold": 200.0, "unit": "packets/second",
        "reason": "the source completed handshakes for 95% of its 1550 SYNs",
    }

    def test_summary_is_empty_when_nothing_came_close(self) -> None:
        assert near_miss_summary([]) == ""

    def test_summary_and_line_name_the_rule(self) -> None:
        assert RULE_SYN_FLOOD in near_miss_summary([self.MISS])
        assert "NO detection" in near_miss_summary([self.MISS])
        line = describe_near_miss(self.MISS)
        assert "155% of trigger" in line and "set aside" in line

    def test_capture_probe_reports_them(self) -> None:
        stats = SimpleNamespace(
            is_running=True, interface="lab0", total_packets=1000, dropped=0,
            queue_depth=0, last_packet_at=None,
        )
        service = object.__new__(HealthService)
        service._probes = SubsystemProbes(  # noqa: SLF001
            capture_status=lambda: stats,
            detection_near_misses=lambda: [self.MISS],
        )
        status = service._probe_capture()  # noqa: SLF001
        assert status.state is ServiceState.CAPTURING
        assert "NO detection raised" in status.detail
        assert status.metadata["near_misses"] == 1

    def test_a_broken_provider_does_not_break_the_probe(self) -> None:
        stats = SimpleNamespace(
            is_running=True, interface="lab0", total_packets=1, dropped=0,
            queue_depth=0, last_packet_at=None,
        )

        def broken():
            raise RuntimeError("engine unavailable")

        service = object.__new__(HealthService)
        service._probes = SubsystemProbes(  # noqa: SLF001
            capture_status=lambda: stats, detection_near_misses=broken,
        )
        status = service._probe_capture()  # noqa: SLF001
        assert status.state is ServiceState.CAPTURING
        assert status.metadata["near_misses"] == 0
