"""Direction is decided from the capture interface's own addresses, and nothing else.

Addresses in these tests are from the documentation ranges (RFC 5737, RFC 3849),
so none of them can be mistaken for a real host. The application itself carries
no address at all - that is one of the things pinned here.
"""

from __future__ import annotations

import inspect
import re
from datetime import UTC, datetime

import pytest

from aethra_sec.analytics import traffic_direction as module
from aethra_sec.analytics.traffic_direction import (
    Direction,
    LocalAddresses,
    OsInterface,
    classify,
    is_group_mac,
    normalise_ip,
    resolve_local_addresses,
)
from aethra_sec.models.traffic import CapturedPacket

MONITOR = "192.0.2.10"
MONITOR_V6 = "2001:db8::10"
REMOTE = "198.51.100.20"
REMOTE_V6 = "2001:db8:ffff::20"
ATTACKER = "192.0.2.30"
TARGET = "192.0.2.40"
MONITOR_MAC = "02:00:00:00:00:10"
OTHER_MAC = "02:00:00:00:00:99"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

LOCAL = LocalAddresses(
    interface="test0",
    addresses=frozenset({MONITOR, MONITOR_V6}),
    mac_addresses=frozenset({MONITOR_MAC}),
    broadcast_addresses=frozenset({"192.0.2.255"}),
)


def packet(
    src: str = "",
    dst: str = "",
    *,
    src_mac: str = OTHER_MAC,
    dst_mac: str = "02:00:00:00:00:98",
    src_port: int | None = None,
    dst_port: int | None = None,
    layers: tuple[str, ...] = ("ETH", "IP", "TCP"),
) -> CapturedPacket:
    version = None
    if src or dst:
        version = 6 if ":" in (src or dst) else 4
    return CapturedPacket(
        captured_at=datetime.now(UTC),
        interface="test0",
        src_ip=src,
        dst_ip=dst,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_port=src_port,
        dst_port=dst_port,
        transport="TCP",
        layers=layers,
        ip_version=version,
    )


class TestTheRulesTheSpecificationStates:
    def test_remote_to_monitor_is_incoming(self) -> None:
        assert classify(packet(REMOTE, MONITOR), LOCAL) is Direction.INCOMING

    def test_monitor_to_remote_is_outgoing(self) -> None:
        assert classify(packet(MONITOR, REMOTE), LOCAL) is Direction.OUTGOING

    def test_attacker_to_target_is_transit_not_incoming_or_outgoing(self) -> None:
        """The case a three-device laboratory depends on getting right."""
        assert classify(packet(ATTACKER, TARGET), LOCAL) is Direction.TRANSIT

    def test_ipv6_follows_the_same_rules(self) -> None:
        assert classify(packet(REMOTE_V6, MONITOR_V6), LOCAL) is Direction.INCOMING
        assert classify(packet(MONITOR_V6, REMOTE_V6), LOCAL) is Direction.OUTGOING

    def test_monitor_to_itself_is_local(self) -> None:
        assert classify(packet(MONITOR, MONITOR), LOCAL) is Direction.LOCAL


class TestBroadcastIsNotTransit:
    """Every station receives broadcast; it is not evidence of seeing others."""

    @pytest.mark.parametrize(
        "destination",
        ["192.0.2.255", "255.255.255.255", "224.0.0.251", "239.255.255.250", "ff02::fb"],
    )
    def test_broadcast_and_multicast_from_another_host(self, destination: str) -> None:
        source = REMOTE_V6 if ":" in destination else ATTACKER
        assert classify(packet(source, destination), LOCAL) is Direction.BROADCAST

    def test_a_broadcast_frame_with_a_unicast_ip_is_broadcast(self) -> None:
        """An ARP request names a target IP but is sent to every station."""
        request = packet(
            ATTACKER, TARGET, dst_mac=BROADCAST_MAC, layers=("ETH", "ARP")
        )
        assert classify(request, LOCAL) is Direction.BROADCAST

    def test_an_arp_request_about_the_monitor_is_incoming(self) -> None:
        request = packet(REMOTE, MONITOR, dst_mac=BROADCAST_MAC, layers=("ETH", "ARP"))
        assert classify(request, LOCAL) is Direction.INCOMING

    def test_an_arp_request_from_the_monitor_is_outgoing(self) -> None:
        request = packet(MONITOR, TARGET, src_mac=MONITOR_MAC, dst_mac=BROADCAST_MAC, layers=("ETH", "ARP"))
        assert classify(request, LOCAL) is Direction.OUTGOING


class TestFramesWithoutIpEndpoints:
    def test_sent_by_the_monitor(self) -> None:
        assert classify(packet(src_mac=MONITOR_MAC, dst_mac=BROADCAST_MAC), LOCAL) is Direction.OUTGOING

    def test_addressed_to_the_monitor(self) -> None:
        assert classify(packet(dst_mac=MONITOR_MAC), LOCAL) is Direction.INCOMING

    def test_group_addressed(self) -> None:
        assert classify(packet(dst_mac="01:80:c2:00:00:0e"), LOCAL) is Direction.BROADCAST

    def test_between_two_other_devices(self) -> None:
        assert classify(packet(), LOCAL) is Direction.TRANSIT

    def test_no_endpoints_at_all(self) -> None:
        assert classify(packet(src_mac="", dst_mac=""), LOCAL) is Direction.UNKNOWN


class TestNothingIsGuessed:
    def test_unknown_addresses_make_every_packet_unknown(self) -> None:
        unresolved = LocalAddresses(interface="test0", detail="not matched")
        for candidate in (packet(REMOTE, MONITOR), packet(MONITOR, REMOTE), packet(ATTACKER, TARGET)):
            assert classify(candidate, unresolved) is Direction.UNKNOWN

    def test_ports_never_decide_direction(self) -> None:
        """Swapping well-known ports must not change the answer."""
        for source_port, destination_port in ((50000, 443), (443, 50000), (80, 53)):
            assert classify(
                packet(REMOTE, MONITOR, src_port=source_port, dst_port=destination_port), LOCAL
            ) is Direction.INCOMING
        assert "port" not in inspect.getsource(classify).lower()

    def test_the_module_contains_no_address_literal(self) -> None:
        source = inspect.getsource(module)
        assert re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", source) == []


class TestResolvingTheInterface:
    def test_a_windows_device_is_joined_to_its_adapter_by_guid(self) -> None:
        table = {
            "Wi-Fi": OsInterface(
                name="Wi-Fi",
                addresses=(MONITOR, MONITOR_V6),
                netmasks=((MONITOR, "255.255.255.0"),),
                mac=MONITOR_MAC,
            ),
            "Ethernet 3": OsInterface(name="Ethernet 3", addresses=("198.51.100.1",)),
        }
        local = resolve_local_addresses(
            r"\Device\NPF_{ABCDEF00-0000-0000-0000-000000000001}",
            interfaces=lambda: table,
            adapter_names=lambda: {"{ABCDEF00-0000-0000-0000-000000000001}": "Wi-Fi"},
        )
        assert local.resolved
        assert local.addresses == frozenset({MONITOR, MONITOR_V6})
        assert local.broadcast_addresses == frozenset({"192.0.2.255"})
        assert "198.51.100.1" not in local.addresses

    def test_a_device_named_like_the_os_interface_resolves_directly(self) -> None:
        table = {"eth0": OsInterface(name="eth0", addresses=(MONITOR,))}
        local = resolve_local_addresses("eth0", interfaces=lambda: table, adapter_names=dict)
        assert local.addresses == frozenset({MONITOR})

    def test_loopback_capture_treats_every_machine_address_as_local(self) -> None:
        table = {
            "Wi-Fi": OsInterface(name="Wi-Fi", addresses=(MONITOR,)),
            "Loopback Pseudo-Interface 1": OsInterface(name="lo", addresses=("127.0.0.1",)),
        }
        local = resolve_local_addresses(r"\Device\NPF_Loopback", interfaces=lambda: table, adapter_names=dict)
        assert local.loopback
        assert classify(packet("127.0.0.1", "127.0.0.2"), local) is Direction.LOCAL
        assert classify(packet(MONITOR, MONITOR), local) is Direction.LOCAL

    def test_an_unmatched_interface_is_reported_not_guessed(self) -> None:
        local = resolve_local_addresses(
            r"\Device\NPF_{UNKNOWN}", interfaces=dict, adapter_names=dict
        )
        assert not local.resolved
        assert "cannot be determined" in local.detail

    def test_an_interface_without_an_address_is_unresolved(self) -> None:
        table = {"Wi-Fi": OsInterface(name="Wi-Fi", mac=MONITOR_MAC)}
        local = resolve_local_addresses("Wi-Fi", interfaces=lambda: table, adapter_names=dict)
        assert not local.resolved

    def test_an_ipv6_zone_suffix_is_dropped(self) -> None:
        assert normalise_ip("fe80::1%12") == "fe80::1"

    @pytest.mark.parametrize(
        ("mac", "expected"),
        [(BROADCAST_MAC, True), ("01:00:5e:00:00:fb", True), ("33:33:00:00:00:fb", True), (MONITOR_MAC, False), ("", False)],
    )
    def test_group_addresses(self, mac: str, expected: bool) -> None:
        assert is_group_mac(mac) is expected


class TestTheUnspecifiedAddressIdentifiesNoHost:
    """0.0.0.0 and :: say nothing about an endpoint; its hardware address decides.

    Found on a real laboratory capture: ARP replies addressed to this adapter's
    MAC, with a target IP of 0.0.0.0, were reported as TRANSIT.
    """

    def test_an_arp_reply_to_this_adapters_probe_is_incoming(self) -> None:
        reply = packet(REMOTE, "0.0.0.0", dst_mac=MONITOR_MAC, layers=("ETH", "ARP"))
        assert classify(reply, LOCAL) is Direction.INCOMING

    def test_this_adapters_dhcp_discover_is_outgoing(self) -> None:
        discover = packet(
            "0.0.0.0", "255.255.255.255", src_mac=MONITOR_MAC, dst_mac=BROADCAST_MAC,
            layers=("ETH", "IP", "UDP", "DHCP"),
        )
        assert classify(discover, LOCAL) is Direction.OUTGOING

    def test_another_hosts_dhcp_discover_is_broadcast(self) -> None:
        discover = packet("0.0.0.0", "255.255.255.255", dst_mac=BROADCAST_MAC)
        assert classify(discover, LOCAL) is Direction.BROADCAST

    def test_this_adapters_duplicate_address_probe_is_outgoing(self) -> None:
        probe = packet("::", "ff02::1:ff00:10", src_mac=MONITOR_MAC, dst_mac="33:33:ff:00:00:10")
        assert classify(probe, LOCAL) is Direction.OUTGOING

    def test_a_reply_to_another_hosts_probe_is_still_transit(self) -> None:
        reply = packet(REMOTE, "0.0.0.0", dst_mac="02:00:00:00:00:77", layers=("ETH", "ARP"))
        assert classify(reply, LOCAL) is Direction.TRANSIT

    def test_a_routed_packet_through_this_adapter_stays_transit(self) -> None:
        """Our MAC on a frame between two other IPs means we forwarded it."""
        forwarded = packet(ATTACKER, TARGET, dst_mac=MONITOR_MAC)
        assert classify(forwarded, LOCAL) is Direction.TRANSIT
