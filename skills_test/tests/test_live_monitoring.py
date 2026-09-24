"""Live monitoring: what enters the inventory, and what must not.

The pipeline is interface -> TShark/PyShark -> capture worker -> queue ->
parser -> UI. These tests exercise the decision points in that chain with
synthetic packets, never live traffic, and never write production rows.

The rule they defend: an address enters the host inventory only when it was
seen *transmitting* on a network the sensor is *attached to*. Relaxing either
half is how a /24 sweep once enrolled all 256 addresses.
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools.coverage import covers  # noqa: E402

CAPTURE = "aethra_sec/services/packet_capture.py"
NET = "aethra_sec/utils/net.py"

LOCAL = (ipaddress.ip_network("192.168.1.0/24"),)


@covers(NET, "is_on_link", feature="Live Monitoring", action="On-link decision")
def test_only_addresses_on_the_sensor_subnet_are_on_link() -> None:
    from aethra_sec.utils.net import is_on_link

    assert is_on_link("192.168.1.50", LOCAL) is True
    assert is_on_link("8.8.8.8", LOCAL) is False, (
        "an internet address was treated as a device on the monitored network"
    )
    assert is_on_link("", LOCAL) is False
    assert is_on_link("192.168.1.50", ()) is False, (
        "with no known subnet the sensor must not guess"
    )


@covers(NET, "host_address_rejection",
        feature="Live Monitoring", action="Address validation")
def test_addresses_no_device_owns_are_refused() -> None:
    from aethra_sec.utils.net import host_address_rejection

    for address in ("224.0.0.251", "ff02::fb", "fe80::1", "0.0.0.0", "127.0.0.1"):
        assert host_address_rejection(address), f"{address} was accepted as a host"
    assert host_address_rejection("192.168.1.255", LOCAL), "broadcast accepted"
    assert host_address_rejection("192.168.1.50", LOCAL) == "", (
        "an ordinary private address was refused"
    )


@covers(CAPTURE, "PacketCaptureService._accumulate_host",
        feature="Live Monitoring", action="Host discovery from packets")
def test_only_a_sender_counts_as_evidence_of_a_host(packet_factory) -> None:
    """A destination is an address someone named, not a device that answered."""
    from aethra_sec.services.packet_capture import PacketCaptureService

    service = PacketCaptureService.__new__(PacketCaptureService)
    service._pending_hosts = {}
    service._is_on_link = lambda address: is_local(address)

    def is_local(address: str) -> bool:
        try:
            return ipaddress.ip_address(address) in LOCAL[0]
        except ValueError:
            return False

    packet = packet_factory(src_ip="192.168.1.50", dst_ip="192.168.1.99")
    service._accumulate_host(packet)

    sender = service._pending_hosts["192.168.1.50"]
    receiver = service._pending_hosts["192.168.1.99"]
    assert sender["transmitted"] is True
    assert receiver["transmitted"] is False, (
        "a packet destination was recorded as having transmitted"
    )


@covers(CAPTURE, "PacketCaptureService._flush_host_observations",
        feature="Live Monitoring", action="Host inventory admission")
def test_the_admission_rule_requires_transmission_and_on_link() -> None:
    """Both halves, plus the address being a host at all."""
    import inspect

    from aethra_sec.services.packet_capture import PacketCaptureService

    source = inspect.getsource(
        PacketCaptureService._flush_host_observations
    )
    for condition in ('data["transmitted"]', 'data["on_link"]',
                      "host_address_rejection(address"):
        assert condition in source, (
            f"the admission rule no longer requires {condition}"
        )


@covers("aethra_sec/analytics/anomaly_rules.py", "flood_severity",
        feature="Live Monitoring", action="Flood severity bands")
def test_flood_severity_rises_with_the_rate() -> None:
    """A band that stops escalating hides the worst floods."""
    from aethra_sec.analytics.anomaly_rules import MANUSCRIPT_THRESHOLDS, flood_severity
    from aethra_sec.models.enums import Severity

    base = MANUSCRIPT_THRESHOLDS["detection.icmp_packets_per_second"]
    low, _ = flood_severity(base + 1)
    high, _ = flood_severity(base * 100)
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH]
    assert order.index(high) >= order.index(low), (
        "a far larger flood did not produce an equal or higher severity"
    )


@covers("aethra_sec/analytics/traffic_classes.py", "traffic_load_class",
        feature="Live Monitoring", action="Load classification")
def test_the_load_bands_are_ordered() -> None:
    from aethra_sec.analytics.traffic_classes import traffic_load_class

    assert traffic_load_class(10).lower().startswith("small")
    assert traffic_load_class(1000).lower().startswith("medium")
    assert traffic_load_class(5000).lower().startswith("large")


@covers("aethra_sec/analytics/traffic_classes.py", "CaptureReliability",
        feature="Live Monitoring", action="Packet loss (ITU-T Y.1541)")
def test_one_percent_loss_is_not_reliable() -> None:
    """The manuscript's threshold is < 1%, not <= 1%."""
    from aethra_sec.analytics.traffic_classes import CaptureReliability

    assert CaptureReliability(990, 9).reliable is True
    assert CaptureReliability(99, 1).reliable is False
    assert CaptureReliability(0, 0).loss_percent is None
