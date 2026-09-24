"""Host-sweep detection must require sweep evidence (§46).

Counting distinct destinations alone reported this machine as sweeping its own
network: one page load contacts well over the threshold of distinct addresses
in a few seconds. A sweep walks an address range; ordinary outbound traffic
reaches scattered addresses that share no prefix.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aethra_sec.analytics.anomaly_rules import (
    RULE_HOST_SWEEP,
    AnomalyRuleEngine,
    DetectionThresholds,
)
from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.utils.timeutil import utcnow


def packet(src: str, dst: str, *, seconds: float = 0.0, protocol: str = "TCP"):
    """One captured packet, as the mapper would produce it."""
    return CapturedPacket(
        captured_at=utcnow() + timedelta(seconds=seconds),
        interface="test",
        src_ip=src,
        dst_ip=dst,
        src_port=40000,
        dst_port=443,
        protocol=protocol,
        length=80,
    )


def engine(**overrides) -> AnomalyRuleEngine:
    """A rule engine with explicit thresholds."""
    values = {
        "host_sweep_hosts": 15,
        "host_sweep_window": 10,
        "host_sweep_concentration": 0.75,
        "suppression_window": 0,
    }
    values.update(overrides)
    return AnomalyRuleEngine(DetectionThresholds(**values))


def sweeps(found) -> list:
    return [a for a in found if a.rule_id == RULE_HOST_SWEEP]


class TestOrdinaryTrafficIsNotASweep:
    """The false positive that prompted this."""

    def test_browsing_many_scattered_addresses_is_not_a_sweep(self) -> None:
        """A page load reaches many unrelated public addresses."""
        rules = engine()
        scattered = [
            "34.149.66.165", "142.251.153.119", "160.79.104.10", "13.107.42.14",
            "151.101.1.140", "104.18.32.7", "172.217.26.65", "20.190.160.14",
            "23.53.40.19", "99.86.4.121", "52.222.158.9", "204.79.197.200",
            "184.28.90.11", "35.190.72.21", "18.65.229.44", "3.163.189.7",
            "162.159.130.234", "199.232.46.132",
        ]
        found = []
        for address in scattered:
            found.extend(rules.evaluate(packet("192.168.1.7", address)))
        assert not sweeps(found)

    def test_broadcast_and_multicast_are_not_hosts_contacted(self) -> None:
        """ARP and discovery name these constantly; they are not hosts."""
        rules = engine()
        noise = (
            ["255.255.255.255"] * 10
            + ["224.0.0.251", "224.0.0.252", "239.255.255.250"] * 6
        )
        found = []
        for address in noise:
            found.extend(rules.evaluate(packet("192.168.1.7", address, protocol="UDP")))
        assert not sweeps(found)

    def test_talking_to_the_gateway_repeatedly_is_not_a_sweep(self) -> None:
        rules = engine()
        found = []
        for _ in range(40):
            found.extend(rules.evaluate(packet("192.168.1.7", "192.168.1.1")))
        assert not sweeps(found)


class TestARealSweepIsStillDetected:
    """The fix must not blunt the detection it exists for."""

    def test_walking_a_local_range_is_reported(self) -> None:
        """The pattern actually observed on this network: .51, .52, .53 ..."""
        rules = engine()
        found = []
        for host in range(20, 60):
            found.extend(rules.evaluate(packet("192.168.1.222", f"192.168.1.{host}")))
        detected = sweeps(found)
        assert detected, "a host walking a /24 must still be reported"

    def test_the_evidence_names_the_range_and_the_measurement(self) -> None:
        """An incident must carry why it was classified, not just a verdict."""
        rules = engine()
        found = []
        for host in range(20, 60):
            found.extend(rules.evaluate(packet("192.168.1.222", f"192.168.1.{host}")))
        anomaly = sweeps(found)[0]
        evidence = anomaly.evidence
        assert evidence["distinct_hosts"] >= 15
        assert evidence["threshold_hosts"] == 15
        assert evidence["window_seconds"] == 10
        assert evidence["target_range"] == "192.168.1.0/24"
        assert evidence["range_concentration"] >= 0.75
        assert evidence["threshold_concentration"] == 0.75
        # The numbers behind the decision, so the judgement can be audited.
        assert anomaly.observed_value >= anomaly.threshold_value

    def test_a_sweep_mixed_with_some_ordinary_traffic_still_fires(self) -> None:
        """Real hosts browse while they scan; the range still dominates."""
        rules = engine()
        found = []
        for host in range(20, 60):
            found.extend(rules.evaluate(packet("192.168.1.222", f"192.168.1.{host}")))
            if host % 10 == 0:
                found.extend(rules.evaluate(packet("192.168.1.222", "8.8.8.8")))
        assert sweeps(found)


class TestThresholdIsConfigurable:
    """Sites whose traffic looks different must be able to tune this."""

    def test_a_lower_concentration_admits_looser_patterns(self) -> None:
        strict = engine(host_sweep_concentration=0.95)
        loose = engine(host_sweep_concentration=0.10)
        mixed = [f"192.168.1.{n}" for n in range(20, 32)] + [
            "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "4.2.2.2",
            "64.6.64.6", "77.88.8.8", "156.154.70.1",
        ]
        strict_found, loose_found = [], []
        for address in mixed:
            strict_found.extend(strict.evaluate(packet("10.0.0.5", address)))
            loose_found.extend(loose.evaluate(packet("10.0.0.5", address)))
        assert not sweeps(strict_found)
        assert sweeps(loose_found)

    @pytest.mark.parametrize("count", [5, 30])
    def test_the_host_count_threshold_is_honoured(self, count: int) -> None:
        rules = engine(host_sweep_hosts=count)
        found = []
        for host in range(10, 10 + count - 1):
            found.extend(rules.evaluate(packet("10.0.0.5", f"10.0.0.{host}")))
        assert not sweeps(found), "must not fire below the configured count"
        found.extend(rules.evaluate(packet("10.0.0.5", f"10.0.0.{10 + count}")))
        assert sweeps(found), "must fire once the configured count is reached"
