"""What a sensor can see is a fact to be measured, not assumed (§121).

A three-device laboratory - attacker, target, and AETHRA-SEC on a third
machine - has a failure mode that looks like a broken detection engine and is
not one: capture reports CAPTURING, packets arrive in their thousands, and an
attack between the other two devices produces nothing, because the sensor's
adapter was never handed those frames.

The check that answers this has to be harder to fool than it first appears, and
these tests exist because two plausible implementations of it both returned a
confident "yes, visible" from a sensor that could see nothing of the kind:

**ARP looks exactly like the thing being tested for.** An ARP request is
broadcast to every station, but it carries a *target* IP, so a capture records
it as ``192.168.0.101 -> 192.168.0.105``. Counted naively, a silent network
full of ARP reads as station-to-station unicast.

**A sensor's own history is not evidence about other devices.** Packets
captured while the machine was on a different network name an address that is
no longer the sensor's, so its own past traffic reads as third-party. Judging
only within the current subnet is what closes that.

The verdict is deliberately conservative: it says a position *can* see
third-party traffic only when unicast between two other hosts was actually
captured, and otherwise reports the limitation rather than a detection fault.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.analytics.monitoring_position import (
    PositionReport,
    Visibility,
    assess,
)

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"
MODULE = PACKAGE / "analytics" / "monitoring_position.py"

SENSOR = {"192.168.0.104"}
SUBNET = "192.168.0.0/24"
GATEWAY = "192.168.0.1"


def _packets(*triples: tuple[str, str, str], repeat: int = 1):
    """A capture sample, repeated to clear the minimum-sample floor."""
    return list(triples) * repeat


class TestOwnTrafficOnly:
    """The wireless / switched case, which is the common one."""

    def test_a_sensor_seeing_only_itself(self) -> None:
        report = assess(
            _packets(
                ("192.168.0.104", "192.168.0.1", "TCP"),
                ("192.168.0.1", "192.168.0.104", "TCP"),
                repeat=200,
            ),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY, peers=3,
        )
        assert report.visibility is Visibility.OWN_TRAFFIC_ONLY
        assert report.third_party == 0
        assert not report.can_see_third_party

    def test_it_names_the_limitation_not_a_detection_fault(self) -> None:
        report = assess(
            _packets(("192.168.0.104", "192.168.0.1", "TCP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY, peers=3,
        )
        detail = report.detail().lower()
        assert "not delivered to this adapter" in detail
        assert "threshold" not in detail and "rule" not in detail

    def test_it_offers_supported_monitoring_positions(self) -> None:
        report = assess(
            _packets(("192.168.0.104", "192.168.0.1", "TCP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        remedy = report.remedy().lower()
        for supported in ("span", "tap", "gateway", "monitor mode"):
            assert supported in remedy

    def test_it_never_offers_to_change_the_network(self) -> None:
        report = assess(
            _packets(("192.168.0.104", "192.168.0.1", "TCP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert "will not change your network" in report.remedy()


class TestArpIsNotUnicast:
    """The first way this returned a wrong "visible" verdict."""

    def test_arp_between_two_other_hosts_is_not_visibility(self) -> None:
        """It is broadcast; every station receives it."""
        report = assess(
            _packets(("192.168.0.101", "192.168.0.105", "ARP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY, peers=3,
        )
        assert report.visibility is Visibility.OWN_TRAFFIC_ONLY, (
            "ARP was counted as station-to-station unicast, which is how a "
            "silent network reads as fully observable"
        )
        assert report.third_party == 0
        assert report.broadcast > 0

    @pytest.mark.parametrize(
        "protocol", ["ARP", "MDNS", "SSDP", "LLMNR", "NBNS", "DHCP", "IGMP"]
    )
    def test_every_broadcast_protocol_is_excluded(self, protocol: str) -> None:
        report = assess(
            _packets(("192.168.0.101", "192.168.0.105", protocol), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert report.third_party == 0, f"{protocol} counted as unicast"

    def test_real_unicast_between_others_still_counts(self) -> None:
        """The check must not have been made blind by the fix."""
        report = assess(
            _packets(("192.168.0.101", "192.168.0.105", "TCP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert report.visibility is Visibility.THIRD_PARTY_TRAFFIC
        assert report.third_party == 400
        assert ("192.168.0.101", "192.168.0.105") in report.examples


class TestTheSensorsOwnHistoryIsNotEvidence:
    """The second way this returned a wrong "visible" verdict."""

    def test_traffic_from_a_different_network_is_ignored(self) -> None:
        """The machine's own packets from when it was 192.168.100.31."""
        report = assess(
            _packets(
                ("192.168.100.31", "161.49.32.76", "QUIC"),
                ("161.49.32.76", "192.168.100.31", "QUIC"),
                repeat=200,
            ),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert report.sampled == 0, (
            "packets from another network were judged, so the sensor's own "
            "history read as traffic between other devices"
        )
        assert report.visibility is Visibility.UNDETERMINED

    def test_an_internet_endpoint_is_not_a_third_party_pair(self) -> None:
        report = assess(
            _packets(("192.168.0.105", "8.8.8.8", "UDP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert report.third_party == 0

    def test_the_subnet_is_required(self) -> None:
        assert "subnet" in inspect.signature(assess).parameters


class TestTheGatewayIsNotAThirdParty:
    """Every station talks to the access point; that proves nothing."""

    def test_traffic_to_the_gateway_is_not_counted(self) -> None:
        report = assess(
            _packets(
                ("192.168.0.105", GATEWAY, "DNS"),
                (GATEWAY, "192.168.0.105", "DNS"),
                repeat=200,
            ),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY, peers=3,
        )
        assert report.visibility is Visibility.OWN_TRAFFIC_ONLY
        assert report.third_party == 0

    def test_broadcast_destinations_are_not_counted(self) -> None:
        for destination in ("192.168.0.255", "255.255.255.255", "224.0.0.251"):
            report = assess(
                _packets(("192.168.0.105", destination, "UDP"), repeat=400),
                sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
            )
            assert report.third_party == 0, destination


class TestItRefusesToGuess:
    """Too little evidence is reported as too little evidence."""

    def test_a_small_sample_is_undetermined(self) -> None:
        report = assess(
            _packets(("192.168.0.104", GATEWAY, "TCP"), repeat=5),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert report.visibility is Visibility.UNDETERMINED
        assert "not enough" in report.summary()

    def test_undetermined_offers_no_remedy(self) -> None:
        """Advice before evidence would be a guess."""
        report = assess([], sensor_addresses=SENSOR, subnet=SUBNET)
        assert report.remedy() == ""

    def test_an_empty_capture_claims_nothing(self) -> None:
        report = assess([], sensor_addresses=SENSOR, subnet=SUBNET)
        assert report.visibility is Visibility.UNDETERMINED
        assert not report.can_see_third_party

    def test_a_malformed_subnet_does_not_raise(self) -> None:
        report = assess(
            _packets(("192.168.0.101", "192.168.0.105", "TCP"), repeat=400),
            sensor_addresses=SENSOR, subnet="not-a-subnet",
        )
        assert isinstance(report, PositionReport)


class TestItOnlyReadsCapturedPackets:
    """It measures; it does not probe, change or invent."""

    def test_the_module_touches_no_network_or_database(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        for forbidden in ("socket", "subprocess", "os", "scapy", "pyshark"):
            assert forbidden not in imported, f"the check imports {forbidden}"

    def test_it_never_fabricates_a_packet(self) -> None:
        """Read the statements: the docstring names what it does not do."""
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(
                node,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                body = node.body
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    node.body = body[1:] or [ast.Pass()]
        code = ast.unparse(tree)
        for forbidden in ("random", "sample(", "choice(", "inject"):
            assert forbidden not in code

    def test_a_positive_verdict_requires_observed_evidence(self) -> None:
        """It cannot report visibility without a captured example."""
        report = assess(
            _packets(("192.168.0.101", "192.168.0.105", "TCP"), repeat=400),
            sensor_addresses=SENSOR, subnet=SUBNET, gateway=GATEWAY,
        )
        assert report.can_see_third_party
        assert report.examples, "a positive verdict with no evidence behind it"
