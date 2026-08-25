"""Traffic analytics, deterministic detection rules and risk scoring.

These are the pure-computation parts of AETHRA-SEC, so they are tested without
any I/O. Synthetic packets are used here and only here (§99).
"""

from __future__ import annotations

import pytest

from aethra_sec.analytics.anomaly_rules import (
    RULE_HOST_SWEEP,
    RULE_ICMP_FLOOD,
    RULE_PORT_SCAN,
    RULE_SYN_FLOOD,
    RULE_UDP_FLOOD,
    AnomalyRuleEngine,
    DetectionThresholds,
    thresholds_from_settings,
)
from aethra_sec.analytics.risk_engine import RiskEngine, ThreatEvidence
from aethra_sec.analytics.traffic_analyzer import TrafficAnalyzer, summarise_hosts
from aethra_sec.models.enums import EvidenceSource, RiskLevel, Severity, ThreatCategory
from tests.conftest import make_packet


# ---------------------------------------------------------------------------
# Traffic analyzer
# ---------------------------------------------------------------------------
class TestTrafficAnalyzer:
    """Statistics are computed only from observed packets."""

    def test_empty_analyzer_reports_no_data(self) -> None:
        """Before any packet, everything is zero and ``has_data`` is false."""
        analyzer = TrafficAnalyzer()
        snapshot = analyzer.snapshot()
        assert not analyzer.has_data
        assert not snapshot.has_data
        assert snapshot.total_packets == 0
        assert snapshot.packets_per_second == 0.0
        assert snapshot.protocols == ()
        assert snapshot.top_sources == ()

    def test_counts_and_rates(self) -> None:
        """Totals and rates reflect exactly what was observed."""
        analyzer = TrafficAnalyzer(rate_window_seconds=5)
        for index in range(20):
            analyzer.observe(make_packet(length=100, offset_seconds=-index * 0.1))
        assert analyzer.total_packets == 20
        assert analyzer.total_bytes == 2000
        assert analyzer.packets_per_second() > 0

    def test_protocol_distribution(self) -> None:
        """Protocol mix matches the observed packets."""
        analyzer = TrafficAnalyzer()
        for _ in range(6):
            analyzer.observe(make_packet(protocol="TCP"))
        for _ in range(3):
            analyzer.observe(make_packet(protocol="UDP", tcp_flags=None))
        analyzer.observe(make_packet(protocol="ICMP", src_port=None, dst_port=None, tcp_flags=None))

        distribution = {p.protocol: p.packets for p in analyzer.protocol_distribution()}
        assert distribution == {"TCP": 6, "UDP": 3, "ICMP": 1}

    def test_top_talkers_ranked_by_volume(self) -> None:
        """Top talkers are ordered by observed packet count."""
        analyzer = TrafficAnalyzer()
        for _ in range(10):
            analyzer.observe(make_packet(src_ip="192.168.1.10"))
        for _ in range(4):
            analyzer.observe(make_packet(src_ip="192.168.1.11"))
        top = analyzer.top_sources(limit=5)
        assert top[0].address == "192.168.1.10"
        assert top[0].packets == 10
        assert top[1].address == "192.168.1.11"

    def test_top_destination_ports(self) -> None:
        """Destination port ranking reflects observed traffic."""
        analyzer = TrafficAnalyzer()
        for _ in range(7):
            analyzer.observe(make_packet(dst_port=443))
        for _ in range(2):
            analyzer.observe(make_packet(dst_port=22))
        ports = analyzer.top_destination_ports(limit=3)
        assert ports[0].port == 443
        assert ports[0].packets == 7

    def test_interval_totals_for_persistence(self) -> None:
        """Interval rollups aggregate the packets inside the window."""
        from datetime import timedelta

        from aethra_sec.utils.timeutil import utcnow

        analyzer = TrafficAnalyzer()
        for index in range(10):
            analyzer.observe(make_packet(length=200, offset_seconds=-index * 0.2))
        start = utcnow() - timedelta(seconds=10)
        end = utcnow() + timedelta(seconds=1)
        totals = analyzer.interval_totals(start, end)
        assert totals["packet_count"] == 10
        assert totals["byte_count"] == 2000
        assert totals["unique_sources"] == 1

    def test_reset_clears_everything(self) -> None:
        """Clearing the display resets in-memory statistics only."""
        analyzer = TrafficAnalyzer()
        analyzer.observe(make_packet())
        analyzer.reset()
        assert analyzer.total_packets == 0
        assert not analyzer.has_data

    def test_memory_is_bounded(self) -> None:
        """Buckets outside the retention window are discarded (§105)."""
        analyzer = TrafficAnalyzer(window_seconds=10)
        for index in range(400):
            analyzer.observe(make_packet(offset_seconds=-index))
        assert len(analyzer._buckets) <= 12  # noqa: SLF001 - bound is the point

    def test_summarise_hosts(self) -> None:
        """Per-host rollups split sent and received correctly."""
        packets = [
            make_packet(src_ip="192.168.1.10", dst_ip="192.168.1.20", length=100),
            make_packet(src_ip="192.168.1.20", dst_ip="192.168.1.10", length=60),
        ]
        summary = summarise_hosts(packets)
        assert summary["192.168.1.10"]["packets_sent"] == 1
        assert summary["192.168.1.10"]["packets_received"] == 1
        assert summary["192.168.1.10"]["bytes_sent"] == 100
        assert summary["192.168.1.10"]["bytes_received"] == 60


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------
class TestAnomalyRules:
    """Each rule fires only on evidence that meets its documented threshold."""

    @staticmethod
    def _engine(**overrides: object) -> AnomalyRuleEngine:
        """Build an engine with test thresholds."""
        thresholds = DetectionThresholds(
            icmp_per_second=10,
            udp_per_second=20,
            syn_per_second=10,
            syn_unanswered_ratio=0.8,
            http_per_second=10,
            port_scan_ports=5,
            port_scan_window=10,
            host_sweep_hosts=5,
            host_sweep_window=10,
            rate_window=5,
            suppression_window=60,
            **overrides,  # type: ignore[arg-type]
        )
        return AnomalyRuleEngine(thresholds)

    def test_quiet_traffic_raises_nothing(self) -> None:
        """Ordinary traffic produces no anomalies."""
        engine = self._engine()
        raised = []
        for index in range(5):
            raised.extend(engine.evaluate(make_packet(offset_seconds=index * 0.5)))
        assert raised == []

    def test_port_scan_rule(self) -> None:
        """Many distinct destination ports in the window fire the scan rule."""
        engine = self._engine()
        raised = []
        for port in range(1, 12):
            raised.extend(
                engine.evaluate(make_packet(dst_port=port, offset_seconds=port * 0.05))
            )
        scans = [a for a in raised if a.rule_id == RULE_PORT_SCAN]
        assert scans, "the port scan rule should have fired"
        anomaly = scans[0]
        assert anomaly.category is ThreatCategory.PORT_SCAN
        assert anomaly.observed_value >= anomaly.threshold_value
        assert anomaly.evidence["distinct_ports"] >= 5
        assert anomaly.evidence["threshold_ports"] == 5
        assert anomaly.evidence["window_seconds"] == 10
        assert "behaviour" in anomaly.title.lower()

    def test_host_sweep_rule(self) -> None:
        """Many distinct destinations in the window fire the sweep rule."""
        engine = self._engine()
        raised = []
        for octet in range(1, 12):
            raised.extend(
                engine.evaluate(
                    make_packet(dst_ip=f"192.168.1.{octet}", offset_seconds=octet * 0.05)
                )
            )
        sweeps = [a for a in raised if a.rule_id == RULE_HOST_SWEEP]
        assert sweeps
        assert sweeps[0].evidence["distinct_hosts"] >= 5

    def test_icmp_rate_rule(self) -> None:
        """A high ICMP rate from one source fires the ICMP rule."""
        engine = self._engine()
        raised = []
        for index in range(80):
            raised.extend(
                engine.evaluate(
                    make_packet(
                        protocol="ICMP", src_port=None, dst_port=None,
                        tcp_flags=None, offset_seconds=index * 0.01,
                    )
                )
            )
        icmp = [a for a in raised if a.rule_id == RULE_ICMP_FLOOD]
        assert icmp
        assert icmp[0].severity in (Severity.MEDIUM, Severity.HIGH)
        assert icmp[0].observed_value >= 10

    def test_udp_rate_rule(self) -> None:
        """A high UDP rate to one port fires the UDP rule."""
        engine = self._engine()
        raised = []
        for index in range(140):
            raised.extend(
                engine.evaluate(
                    make_packet(
                        protocol="UDP", dst_port=53, tcp_flags=None,
                        offset_seconds=index * 0.005,
                    )
                )
            )
        udp = [a for a in raised if a.rule_id == RULE_UDP_FLOOD]
        assert udp
        assert udp[0].evidence["destination_port"] == 53

    def test_syn_flood_requires_unanswered_connections(self) -> None:
        """A high SYN rate that IS being answered is not reported as a flood."""
        engine = self._engine()
        raised = []
        for index in range(60):
            raised.extend(
                engine.evaluate(make_packet(tcp_flags=0x02, offset_seconds=index * 0.01))
            )
            # A SYN/ACK back from the destination for every attempt.
            raised.extend(
                engine.evaluate(
                    make_packet(
                        src_ip="192.168.1.25", dst_ip="192.168.1.50",
                        tcp_flags=0x12, offset_seconds=index * 0.01,
                    )
                )
            )
        assert not [a for a in raised if a.rule_id == RULE_SYN_FLOOD]

    def test_syn_flood_fires_when_unanswered(self) -> None:
        """A high SYN rate with no replies fires the SYN rule."""
        engine = self._engine()
        raised = []
        for index in range(80):
            raised.extend(
                engine.evaluate(make_packet(tcp_flags=0x02, offset_seconds=index * 0.01))
            )
        syn = [a for a in raised if a.rule_id == RULE_SYN_FLOOD]
        assert syn
        anomaly = syn[0]
        assert anomaly.severity is Severity.HIGH
        assert anomaly.evidence["syn_ack_replies_observed"] == 0
        assert anomaly.evidence["unanswered_ratio"] == 1.0
        assert "Potential" in anomaly.title

    def test_suppression_window_prevents_flooding(self) -> None:
        """A repeat detection inside the suppression window does not re-fire."""
        engine = self._engine()
        first = []
        for port in range(1, 12):
            first.extend(engine.evaluate(make_packet(dst_port=port)))
        second = []
        for port in range(20, 40):
            second.extend(engine.evaluate(make_packet(dst_port=port)))
        assert [a for a in first if a.rule_id == RULE_PORT_SCAN]
        assert not [a for a in second if a.rule_id == RULE_PORT_SCAN]

    def test_disabled_engine_raises_nothing(self) -> None:
        """The master switch stops every rule."""
        engine = AnomalyRuleEngine(DetectionThresholds(enabled=False))
        raised = []
        for port in range(1, 60):
            raised.extend(engine.evaluate(make_packet(dst_port=port)))
        assert raised == []

    def test_trusted_source_is_context_not_exemption(self) -> None:
        """A trusted source still triggers the rule, with the trust recorded."""
        engine = self._engine()
        engine.update_trusted({"192.168.1.50"})
        raised = []
        for port in range(1, 12):
            raised.extend(engine.evaluate(make_packet(dst_port=port)))
        scans = [a for a in raised if a.rule_id == RULE_PORT_SCAN]
        assert scans, "trust must not suppress detection"
        assert scans[0].evidence["source_is_registered_trusted_asset"] is True

    def test_every_anomaly_records_its_evidence(self) -> None:
        """Measured value, threshold and window travel with every detection."""
        engine = self._engine()
        raised = []
        for port in range(1, 12):
            raised.extend(engine.evaluate(make_packet(dst_port=port)))
        for anomaly in raised:
            assert anomaly.observation
            assert anomaly.why_it_matters
            assert anomaly.what_to_check
            assert anomaly.threshold_value > 0
            assert anomaly.window_seconds > 0
            assert anomaly.source is EvidenceSource.PYSHARK

    def test_thresholds_load_from_settings(self) -> None:
        """Thresholds are read from configuration, not hard-coded."""
        values = {
            "detection.enabled": True,
            "detection.icmp_packets_per_second": 7,
            "detection.port_scan_distinct_ports": 3,
            "detection.rate_window_seconds": 2,
        }
        thresholds = thresholds_from_settings(lambda key, default: values.get(key, default))
        assert thresholds.icmp_per_second == 7
        assert thresholds.port_scan_ports == 3
        assert thresholds.rate_window == 2


# ---------------------------------------------------------------------------
# Risk engine
# ---------------------------------------------------------------------------
class TestRiskEngine:
    """Severity is explainable and deterministic (§28)."""

    def test_scoring_is_deterministic(self) -> None:
        """The same evidence always produces the same score."""
        engine = RiskEngine()
        evidence = ThreatEvidence(
            category=ThreatCategory.BRUTE_FORCE, snort_priority=2,
            snort_alert_count=3, distinct_sources=2, event_count=6,
            affected_service="ssh",
        )
        first = engine.score_threat(evidence)
        second = engine.score_threat(evidence)
        assert first.score == second.score
        assert first.severity is second.severity

    def test_factors_explain_the_score(self) -> None:
        """Every point is attributed to a named factor."""
        engine = RiskEngine()
        assessment = engine.score_threat(
            ThreatEvidence(
                category=ThreatCategory.BRUTE_FORCE, snort_priority=1,
                snort_alert_count=2, distinct_sources=3, event_count=25,
                affected_service="ssh", exposure_confirmed=True,
            )
        )
        assert assessment.factors
        assert assessment.score == sum(points for _, points, _ in assessment.factors)
        names = {name for name, _, _ in assessment.factors}
        assert "Threat category" in names
        assert "IDS priority" in names
        assert "Correlation strength" in names
        assert "Confirmed exposure" in names
        assert all(reason for _, _, reason in assessment.factors)

    def test_multi_source_evidence_raises_severity(self) -> None:
        """More corroborating subsystems produce a higher score."""
        engine = RiskEngine()
        single = engine.score_threat(
            ThreatEvidence(category=ThreatCategory.PORT_SCAN, distinct_sources=1)
        )
        multi = engine.score_threat(
            ThreatEvidence(
                category=ThreatCategory.PORT_SCAN, distinct_sources=3,
                exposure_confirmed=True,
            )
        )
        assert multi.score > single.score
        assert multi.confidence > single.confidence

    def test_trusted_source_lowers_but_does_not_erase(self) -> None:
        """Trust reduces the score without hiding the threat."""
        engine = RiskEngine()
        untrusted = engine.score_threat(
            ThreatEvidence(category=ThreatCategory.PORT_SCAN, source_is_trusted=False)
        )
        trusted = engine.score_threat(
            ThreatEvidence(category=ThreatCategory.PORT_SCAN, source_is_trusted=True)
        )
        assert trusted.score < untrusted.score
        assert trusted.score >= 0

    def test_severity_bands(self) -> None:
        """Scores map to the documented bands."""
        engine = RiskEngine()
        assert engine.severity_for_score(100) is Severity.CRITICAL
        assert engine.severity_for_score(60) is Severity.HIGH
        assert engine.severity_for_score(35) is Severity.MEDIUM
        assert engine.severity_for_score(15) is Severity.LOW
        assert engine.severity_for_score(2) is Severity.INFO

    def test_exposure_scoring_states_its_reasoning(self) -> None:
        """An exposure finding always explains its level (§19, §20)."""
        engine = RiskEngine()
        level, rationale = engine.score_exposure(service="ssh", port=22)
        assert isinstance(level, RiskLevel)
        assert "Risk" in rationale
        assert "security-sensitive" in rationale

    def test_cleartext_service_scores_higher(self) -> None:
        """An unencrypted protocol scores above an encrypted equivalent."""
        engine = RiskEngine()
        telnet, _ = engine.score_exposure(service="telnet", port=23)
        https, _ = engine.score_exposure(service="https", port=443)
        assert telnet.severity.rank > https.severity.rank

    def test_known_vulnerability_raises_the_level(self) -> None:
        """A confirmed vulnerability outranks a bare exposure."""
        engine = RiskEngine()
        plain, _ = engine.score_exposure(service="http", port=80)
        known, rationale = engine.score_exposure(
            service="http", port=80, has_known_vulnerability=True
        )
        assert known.severity.rank > plain.severity.rank
        assert "configured vulnerability source" in rationale

    def test_snort_priority_mapping(self) -> None:
        """Snort priorities map to severities, with a stated default."""
        engine = RiskEngine()
        assert engine.severity_for_snort_priority(1) is Severity.CRITICAL
        assert engine.severity_for_snort_priority(2) is Severity.HIGH
        assert engine.severity_for_snort_priority(3) is Severity.MEDIUM
        assert engine.severity_for_snort_priority(4) is Severity.LOW
        assert engine.severity_for_snort_priority(None) is Severity.MEDIUM

    def test_host_risk_is_the_worst_finding(self) -> None:
        """A host's risk equals its most serious finding."""
        engine = RiskEngine()
        assert engine.host_risk_level([]) is RiskLevel.INFORMATIONAL
        assert (
            engine.host_risk_level([RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.MEDIUM])
            is RiskLevel.HIGH
        )
