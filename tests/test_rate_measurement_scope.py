"""What each rate measures, and why two correct numbers can disagree.

The reported symptom: the Traffic Rate graph read 856.6 pkt/s while
RULE-ICMP-RATE alerts sat at LOW. Investigation found both numbers correct and
measuring different things - the graph sums every packet on the interface in
both directions, a flood rule counts one protocol from one source. A ping
flood measured at 432.6 pps from each end therefore shows as roughly 865 pkt/s
on the graph.

These tests pin that distinction so a later change cannot quietly collapse the
two scopes into one, which would classify a host's own echo replies as part of
the attack against it.

Every packet here is a fixture built by the test. Nothing is presented as a
real network observation.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from aethra_sec.analytics.anomaly_rules import (
    RULE_ICMP_FLOOD,
    AnomalyRuleEngine,
    DetectionThresholds,
    flood_severity,
)
from aethra_sec.analytics.traffic_analyzer import TrafficAnalyzer
from aethra_sec.models.enums import Severity
from tests.conftest import make_packet


def _drive(engine: AnomalyRuleEngine, packets_per_second: int,
           seconds: float, *, source: str, destination: str,
           start: float = 0.0, protocol: str = "ICMP") -> list:
    """Feed the engine a steady stream at a known rate."""
    raised = []
    base = make_packet(protocol=protocol, src_ip=source, dst_ip=destination)
    step = 1.0 / packets_per_second
    total = int(packets_per_second * seconds)
    for index in range(total):
        packet = replace(
            base,
            captured_at=base.captured_at + timedelta(
                seconds=start + index * step
            ),
        )
        raised.extend(engine.evaluate(packet))
    return raised


class TestABoundaries:
    """The required thresholds, applied to a measured rate."""

    @pytest.mark.parametrize(
        ("pps", "expected"),
        [
            (499, Severity.LOW),
            (500, Severity.MEDIUM),
            (750, Severity.MEDIUM),
            (999, Severity.MEDIUM),
            (1000, Severity.HIGH),
            (1200, Severity.HIGH),
            (2000, Severity.HIGH),
        ],
    )
    def test_each_required_boundary(self, pps: int, expected: Severity) -> None:
        assert flood_severity(float(pps))[0] is expected


class TestATotalTrafficIsNotProtocolTraffic:
    """TEST A: an aggregate rate must not be applied to one flow."""

    def test_the_graph_sums_what_a_rule_counts_once(self) -> None:
        """Two hosts exchanging ICMP: the graph sees both, the rule sees one.

        This is the reported case. 400 pps in each direction is 800 pps on the
        interface, and neither endpoint individually reaches the 500 pps
        MEDIUM floor - so LOW is the correct classification for each, while
        the graph legitimately reads about 800.
        """
        analyzer = TrafficAnalyzer()
        engine = AnomalyRuleEngine(DetectionThresholds(icmp_per_second=120))

        attacker, victim = "10.96.0.10", "10.96.0.20"
        raised: list = []
        base_out = make_packet(protocol="ICMP", src_ip=attacker, dst_ip=victim)
        base_in = make_packet(protocol="ICMP", src_ip=victim, dst_ip=attacker)
        # 400 packets per second each way, for five seconds.
        for index in range(2000):
            offset = timedelta(seconds=index * (1 / 400))
            out = replace(base_out, captured_at=base_out.captured_at + offset)
            back = replace(base_in, captured_at=base_in.captured_at + offset)
            analyzer.observe(out)
            analyzer.observe(back)
            raised.extend(engine.evaluate(out))
            raised.extend(engine.evaluate(back))

        graph_rate = analyzer.packets_per_second()
        icmp = [a for a in raised if a.rule_id == RULE_ICMP_FLOOD]
        assert icmp, "the flood was not detected"

        per_source = max(a.observed_value for a in icmp)
        assert per_source < 500, (
            f"each endpoint measured {per_source:.1f} pps, which must stay "
            "below the MEDIUM floor for this test to mean anything"
        )
        assert all(a.severity is Severity.LOW for a in icmp), (
            "a sub-500 pps per-source rate must classify LOW"
        )
        # The interface total is roughly twice either endpoint's rate.
        assert graph_rate > per_source * 1.5, (
            f"graph {graph_rate:.1f} pps vs per-source {per_source:.1f} pps: "
            "the two scopes should differ by about a factor of two"
        )

    def test_the_scope_is_recorded_on_every_flood_detection(self) -> None:
        """So an operator can tell the two numbers apart without guessing."""
        engine = AnomalyRuleEngine(DetectionThresholds(icmp_per_second=120))
        raised = _drive(engine, 300, 5, source="10.96.0.10",
                        destination="10.96.0.20")
        icmp = [a for a in raised if a.rule_id == RULE_ICMP_FLOOD]
        assert icmp
        scope = icmp[0].evidence.get("rate_scope")
        assert scope, "the detection must say what its rate measures"
        assert "BY this source" in scope
        assert "Traffic Rate graph" in scope


class TestBRuleIcmpRateIsNotForcedLow:
    """TEST B: severity comes from the measurement, not from the rule name."""

    @pytest.mark.parametrize(
        ("pps", "expected"),
        [(300, Severity.LOW), (600, Severity.MEDIUM), (1400, Severity.HIGH)],
    )
    def test_icmp_severity_follows_the_measured_rate(
        self, pps: int, expected: Severity
    ) -> None:
        engine = AnomalyRuleEngine(DetectionThresholds(icmp_per_second=120))
        raised = _drive(engine, pps, 6, source="10.96.0.10",
                        destination="10.96.0.20")
        icmp = [a for a in raised if a.rule_id == RULE_ICMP_FLOOD]
        assert icmp, f"no ICMP detection at {pps} pps"
        reached = max(a.severity.rank for a in icmp)
        assert reached == expected.rank, (
            f"{pps} pps reached {Severity.from_rank(reached)}, "
            f"expected {expected}"
        )


class TestDStaleCountersDoNotInflateTheRate:
    """TEST D: the window must trim, so a rate cannot accumulate."""

    def test_a_finished_burst_does_not_keep_counting(self) -> None:
        """Packets older than the window leave the measurement.

        A cumulative counter would show the rate climbing for as long as the
        process ran. The sliding window must drop what has aged out, so a
        burst that stops is no longer measured.
        """
        from aethra_sec.analytics.anomaly_rules import _SlidingCounter

        counter = _SlidingCounter()
        window = 5.0
        for index in range(2000):
            count = counter.add(index * (1 / 400), window)
        assert count / window < 450, "the window is not trimming"

        # Nothing for a minute, then one packet: the rate must collapse.
        later = counter.add(2000 * (1 / 400) + 60.0, window)
        assert later == 1, (
            f"{later} events still counted a minute after the burst ended; "
            "the counter is cumulative, not windowed"
        )

    def test_the_rate_is_a_count_over_its_own_window(self) -> None:
        """5,000 packets in a 5-second window is 1,000 pps, not 5,000."""
        from aethra_sec.analytics.anomaly_rules import _SlidingCounter

        counter = _SlidingCounter()
        window = 5.0
        count = 0
        for index in range(5000):
            count = counter.add(index * (window / 5000), window)
        assert count / window == pytest.approx(1000, rel=0.01)
        assert flood_severity(count / window)[0] is Severity.HIGH


class TestFMissingMeasurementsAreNotInvented:
    """TEST F: no rate, no classification."""

    def test_a_rate_below_the_detection_threshold_raises_nothing(self) -> None:
        engine = AnomalyRuleEngine(DetectionThresholds(icmp_per_second=120))
        raised = _drive(engine, 50, 5, source="10.96.0.10",
                        destination="10.96.0.20")
        assert [a for a in raised if a.rule_id == RULE_ICMP_FLOOD] == []

    def test_every_detection_carries_the_numbers_behind_it(self) -> None:
        """A severity with no measurement behind it is not auditable."""
        engine = AnomalyRuleEngine(DetectionThresholds(icmp_per_second=120))
        raised = _drive(engine, 600, 6, source="10.96.0.10",
                        destination="10.96.0.20")
        icmp = [a for a in raised if a.rule_id == RULE_ICMP_FLOOD]
        assert icmp
        for anomaly in icmp:
            evidence = anomaly.evidence
            assert evidence["icmp_packets_in_window"] > 0
            assert evidence["window_seconds"] > 0
            assert evidence["observed_rate_pps"] > 0
            # The stored rate is the count over the window, not a guess.
            assert evidence["observed_rate_pps"] == pytest.approx(
                evidence["icmp_packets_in_window"]
                / evidence["window_seconds"], rel=0.01
            )


class TestGNormalTrafficIsNotAFlood:
    """TEST G: a busy interface does not make every flow an attack."""

    def test_a_quiet_source_raises_nothing_on_a_busy_interface(self) -> None:
        """One host trickling ICMP while the interface is loud.

        The graph would read the combined rate; the quiet host must still not
        be reported, because the rule measures that host and not the wire.
        """
        analyzer = TrafficAnalyzer()
        engine = AnomalyRuleEngine(DetectionThresholds(icmp_per_second=120))

        loud = make_packet(protocol="TCP", src_ip="10.96.0.50",
                           dst_ip="10.96.0.60")
        quiet = make_packet(protocol="ICMP", src_ip="10.96.0.10",
                            dst_ip="10.96.0.20")
        raised: list = []
        for index in range(4000):
            offset = timedelta(seconds=index * (1 / 800))
            busy = replace(loud, captured_at=loud.captured_at + offset)
            analyzer.observe(busy)
            raised.extend(engine.evaluate(busy))
            # 20 ICMP per second from the quiet host: far under the threshold.
            if index % 40 == 0:
                slow = replace(quiet, captured_at=quiet.captured_at + offset)
                analyzer.observe(slow)
                raised.extend(engine.evaluate(slow))

        assert analyzer.packets_per_second() > 500, (
            "the interface must be busy for this test to mean anything"
        )
        assert [a for a in raised if a.rule_id == RULE_ICMP_FLOOD] == [], (
            "a quiet ICMP source was reported as a flood because the "
            "interface as a whole was busy"
        )
