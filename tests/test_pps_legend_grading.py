"""New detections are graded on the §3.9.8 pps legend, whatever raised them.

HIGH is 1,000 pps and above, MEDIUM 500-999 pps, LOW below 500 pps. A port
scan is still detected by distinct ports and a host sweep by distinct hosts,
but each is now GRADED on the pps its source sent, and a Snort alert on the
live pps of its source - so the Rate column and the severity always agree.
Existing records are not regraded. Every packet here is a test fixture.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from aethra_sec.analytics.anomaly_rules import (
    RULE_HOST_SWEEP,
    RULE_PORT_SCAN,
    AnomalyRuleEngine,
    DetectionThresholds,
)
from aethra_sec.models.enums import Severity
from aethra_sec.utils.timeutil import utcnow
from tests.conftest import make_packet


def _scan(engine: AnomalyRuleEngine, ports: int, seconds: float,
          extra_per_port: int = 0) -> list:
    """One source SYNs ``ports`` distinct ports over ``seconds``."""
    raised = []
    start = utcnow()
    total = ports * (1 + extra_per_port)
    step = seconds / max(total, 1)
    index = 0
    for port in range(1, ports + 1):
        for _ in range(1 + extra_per_port):
            packet = make_packet(src_ip="10.0.0.5", dst_ip="10.0.0.9",
                                 dst_port=port, tcp_flags=0x02)
            packet.captured_at = start + timedelta(seconds=index * step)
            raised.extend(engine.evaluate(packet))
            index += 1
    return raised


def _found(raised: list, rule: str):
    hits = [a for a in raised if a.rule_id == rule]
    assert hits, f"{rule} did not fire"
    return hits[0]


def test_a_slow_port_scan_is_low_and_records_its_pps() -> None:
    engine = AnomalyRuleEngine(DetectionThresholds())
    scan = _found(_scan(engine, ports=25, seconds=8), RULE_PORT_SCAN)
    pps = scan.evidence["packets_per_second"]
    assert pps < 500
    assert scan.severity is Severity.LOW, "below 500 pps is LOW on the legend"
    assert scan.observed_value >= 20, "still DETECTED by distinct ports"


def test_a_fast_port_scan_is_graded_by_its_pps() -> None:
    engine = AnomalyRuleEngine(DetectionThresholds())
    # 25 ports, 300 packets each, inside one second: thousands of pps.
    scan = _found(_scan(engine, ports=25, seconds=1.0, extra_per_port=299),
                  RULE_PORT_SCAN)
    assert scan.evidence["packets_per_second"] >= 500
    assert scan.severity in (Severity.MEDIUM, Severity.HIGH)


def test_a_host_sweep_is_graded_by_its_pps() -> None:
    engine = AnomalyRuleEngine(DetectionThresholds())
    raised = []
    start = utcnow()
    for host in range(1, 21):
        packet = make_packet(src_ip="10.0.0.5", dst_ip=f"10.0.0.{host + 20}",
                             dst_port=80)
        packet.captured_at = start + timedelta(seconds=host * 0.4)
        raised.extend(engine.evaluate(packet))
    sweep = _found(raised, RULE_HOST_SWEEP)
    assert sweep.severity is Severity.LOW
    assert 0 < sweep.evidence["packets_per_second"] < 500


def test_source_rate_counts_only_the_source() -> None:
    engine = AnomalyRuleEngine(DetectionThresholds())
    start = utcnow()
    for i in range(50):
        out = make_packet(src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=80)
        out.captured_at = start + timedelta(seconds=i * 0.02)
        engine.evaluate(out)
        back = make_packet(src_ip="10.0.0.9", dst_ip="10.0.0.5", dst_port=40000,
                           tcp_flags=0x12)
        back.captured_at = start + timedelta(seconds=i * 0.02 + 0.01)
        engine.evaluate(back)
    rate = engine.source_rate("10.0.0.5", "10.0.0.9")
    assert rate is not None
    # 50 packets in a 5 s window = 10.0; the 50 replies are not counted.
    assert rate == 10.0


def test_source_rate_is_none_when_capture_has_gone_quiet() -> None:
    engine = AnomalyRuleEngine(DetectionThresholds())
    old = make_packet(src_ip="10.0.0.5", dst_ip="10.0.0.9")
    old.captured_at = utcnow() - timedelta(hours=1)
    engine.evaluate(old)
    assert engine.source_rate("10.0.0.5") is None
    assert AnomalyRuleEngine(DetectionThresholds()).source_rate("10.0.0.5") is None


def test_snort_alert_is_graded_by_live_pps() -> None:
    from aethra_sec.services.snort_service import SnortService

    service = SnortService.__new__(SnortService)
    service._rate_probe = lambda src, dst: 1250.0
    record = SimpleNamespace(src_ip="10.0.0.28", dst_ip="10.0.0.26")
    assert service._measure_source(record) == 1250.0

    service._rate_probe = None
    assert service._measure_source(record) is None, (
        "no capture rate - the priority grade stands"
    )


def test_snort_repeat_raises_but_never_lowers() -> None:
    from aethra_sec.services.snort_service import SnortService

    calls = []

    class _Repo:
        def raise_alert_grade(self, alert_id, pps, severity):  # noqa: ANN001
            calls.append((alert_id, pps, severity))

    service = SnortService.__new__(SnortService)
    service._alerts = _Repo()
    service._rate_probe = lambda src, dst: 640.0
    service._regrade_repeat(7, SimpleNamespace(src_ip="a", dst_ip="b"))
    assert calls == [(7, 640.0, Severity.MEDIUM)]
