"""The inventory holds devices on the monitored network (§123).

Host Inventory showed 1,983 hosts on a laboratory LAN of about four devices.
1,491 of them were public internet addresses - Google, Cloudflare, Canonical -
recorded because the sensor had exchanged packets with them, and each was
offered "Scan this host" and counted towards ONLINE.

The hardware identities were worse than the count. A frame arriving from an
off-link address was forwarded by the router, so its *source MAC is the
router's*. Attaching it to the remote address gave 333 unrelated internet
servers the gateway's MAC, 567 another router's, and 420 a third - hardware
addresses for machines the sensor has never touched. The screen's own caption
promised "capture sees an address and a MAC ... neither is invented", and the
MAC was invented.

The rule that fixes it is one distinction: a MAC identifies a host only when
that host shares a broadcast domain with the sensor. Everything else follows -
an off-link address gets no MAC, and does not enter the inventory at all,
because it is a conversation peer rather than a device on the network being
monitored.

Nothing is discarded. Every address is still counted for traffic, and remote
endpoints remain in the traffic records and the top-talkers, which is where a
remote endpoint belongs.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.packet_capture import PacketCaptureService, _is_host_mac
from aethra_sec.utils.net import is_on_link, local_ipv4_networks
from aethra_sec.utils.timeutil import utcnow

import ipaddress

GATEWAY_MAC = "d8:07:b6:6d:9e:30"
MY_MAC = "30:89:4a:85:4a:c1"
PEER_MAC = "00:d4:9e:e0:aa:60"
LAN = (ipaddress.ip_network("192.168.0.0/24"),)


def _service() -> PacketCaptureService:
    """A bare accumulator with a known set of local subnets."""
    service = PacketCaptureService.__new__(PacketCaptureService)
    service._pending_hosts = {}
    service._local_networks = LAN
    # Far in the future so the 60s refresh never re-reads real interfaces.
    service._local_networks_at = 1e12
    service._onlink_cache = {}
    return service


def _packet(src: str, dst: str, src_mac: str, dst_mac: str) -> CapturedPacket:
    return CapturedPacket(
        captured_at=utcnow(), src_ip=src, dst_ip=dst, src_mac=src_mac,
        dst_mac=dst_mac, protocol="TCP", transport="TCP", length=100,
        interface="test",
    )


def _inventory(service: PacketCaptureService) -> set[str]:
    """Addresses that would be written to the inventory."""
    return {
        address
        for address, data in service._pending_hosts.items()
        if data["transmitted"] and data["on_link"]
    }


# ---------------------------------------------------------------------------
# The on-link distinction
# ---------------------------------------------------------------------------
class TestOnLinkDetection:
    """A subnet the sensor is attached to, read from the live interfaces."""

    def test_the_sensors_own_subnets_are_found(self) -> None:
        networks = local_ipv4_networks()
        assert networks, "no local subnet was detected at all"
        assert all(
            isinstance(network, ipaddress.IPv4Network) for network in networks
        )

    def test_loopback_is_not_a_monitored_subnet(self) -> None:
        assert not any(network.is_loopback for network in local_ipv4_networks())

    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("192.168.0.104", True),
            ("192.168.0.1", True),
            ("192.168.0.255", True),
            ("142.251.150.4", False),
            ("57.144.228.145", False),
            ("8.8.8.8", False),
            ("192.168.100.31", False),
            ("", False),
            ("not-an-address", False),
        ],
    )
    def test_membership(self, address: str, expected: bool) -> None:
        assert is_on_link(address, LAN) is expected

    def test_no_subnets_means_nothing_is_on_link(self) -> None:
        """Fails closed: without knowing the network, claim no host."""
        assert is_on_link("192.168.0.104", ()) is False


class TestAMacIsOnlyEverTheHostsOwn:
    """The fabrication that mattered."""

    def test_a_routed_frame_does_not_donate_its_mac(self) -> None:
        service = _service()
        service._accumulate_host(
            _packet("142.251.150.4", "192.168.0.104", GATEWAY_MAC, MY_MAC)
        )
        record = service._pending_hosts["142.251.150.4"]
        assert record["mac"] == "", (
            "an internet server was given the router's hardware address"
        )

    def test_two_internet_servers_do_not_share_a_mac(self) -> None:
        service = _service()
        for address in ("142.251.150.4", "57.144.228.145", "8.8.8.8"):
            service._accumulate_host(
                _packet(address, "192.168.0.104", GATEWAY_MAC, MY_MAC)
            )
        macs = {
            data["mac"] for address, data in service._pending_hosts.items()
            if not data["on_link"]
        }
        assert macs == {""}, f"off-link addresses carry MACs: {macs}"

    def test_an_on_link_neighbour_keeps_its_own(self) -> None:
        service = _service()
        service._accumulate_host(
            _packet("192.168.0.103", "192.168.0.104", PEER_MAC, MY_MAC)
        )
        assert service._pending_hosts["192.168.0.103"]["mac"] == PEER_MAC

    def test_a_destination_never_donates_a_mac(self) -> None:
        """Only a sender proves whose address it is."""
        service = _service()
        service._accumulate_host(
            _packet("192.168.0.104", "192.168.0.103", MY_MAC, PEER_MAC)
        )
        assert service._pending_hosts["192.168.0.103"]["mac"] == ""

    @pytest.mark.parametrize(
        "mac",
        ["ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "33:33:00:00:00:01", "", "xx"],
    )
    def test_group_addresses_are_rejected_outright(self, mac: str) -> None:
        assert not _is_host_mac(mac)

    def test_a_unicast_mac_is_accepted(self) -> None:
        assert _is_host_mac(PEER_MAC)
        assert _is_host_mac(GATEWAY_MAC), (
            "a router's MAC is a valid unicast address - which is why the "
            "on-link test, not the MAC itself, is what excludes it"
        )


class TestOnlyMonitoredDevicesEnterTheInventory:
    """§ Total hosts must describe the network, not the internet."""

    def test_an_internet_peer_is_not_an_inventory_host(self) -> None:
        service = _service()
        service._accumulate_host(
            _packet("142.251.150.4", "192.168.0.104", GATEWAY_MAC, MY_MAC)
        )
        assert "142.251.150.4" not in _inventory(service)

    def test_an_on_link_transmitter_is(self) -> None:
        service = _service()
        service._accumulate_host(
            _packet("192.168.0.103", "192.168.0.104", PEER_MAC, MY_MAC)
        )
        assert "192.168.0.103" in _inventory(service)

    def test_a_destination_that_never_transmitted_is_not(self) -> None:
        """An ARP sweep must not enrol an entire /24."""
        service = _service()
        for last in range(2, 40):
            service._accumulate_host(
                _packet("192.168.0.104", f"192.168.0.{last}", MY_MAC, PEER_MAC)
            )
        assert _inventory(service) == {"192.168.0.104"}

    def test_both_conditions_are_required(self) -> None:
        """Transmitted *and* on-link, plus the address being a host at all.

        The three now sit on separate lines, so this matches the terms rather
        than one spelling of the expression.
        """
        source = inspect.getsource(
            PacketCaptureService._flush_host_observations
        )
        for condition in (
            'data["transmitted"]',
            'data["on_link"]',
            "host_address_rejection(address",
        ):
            assert condition in source, f"{condition} is no longer required"

    def test_a_mixed_capture_yields_only_the_local_devices(self) -> None:
        service = _service()
        exchanges = [
            ("192.168.0.103", "192.168.0.104", PEER_MAC, MY_MAC),
            ("192.168.0.104", "142.251.150.4", MY_MAC, GATEWAY_MAC),
            ("142.251.150.4", "192.168.0.104", GATEWAY_MAC, MY_MAC),
            ("57.144.228.145", "192.168.0.104", GATEWAY_MAC, MY_MAC),
            ("172.64.155.209", "192.168.0.104", GATEWAY_MAC, MY_MAC),
            ("192.168.0.1", "192.168.0.104", GATEWAY_MAC, MY_MAC),
        ]
        for args in exchanges:
            service._accumulate_host(_packet(*args))
        assert _inventory(service) == {
            "192.168.0.103", "192.168.0.104", "192.168.0.1",
        }


class TestNothingIsDiscarded:
    """Traffic accounting is unchanged; only the inventory narrowed."""

    def test_every_address_is_still_counted(self) -> None:
        service = _service()
        service._accumulate_host(
            _packet("142.251.150.4", "192.168.0.104", GATEWAY_MAC, MY_MAC)
        )
        record = service._pending_hosts["142.251.150.4"]
        assert record["packets_sent"] == 1
        assert record["bytes_sent"] == 100

    def test_both_endpoints_are_accounted_for(self) -> None:
        service = _service()
        service._accumulate_host(
            _packet("192.168.0.104", "8.8.8.8", MY_MAC, GATEWAY_MAC)
        )
        assert set(service._pending_hosts) == {"192.168.0.104", "8.8.8.8"}
        assert service._pending_hosts["8.8.8.8"]["packets_received"] == 1

    def test_the_rollup_follows_the_inventory(self) -> None:
        """A per-host row cannot reference a host that does not exist."""
        source = inspect.getsource(
            PacketCaptureService._flush_host_observations
        )
        loop = source[source.index("rows: list[tuple[Any, ...]] = []"):]
        assert "for address, data in observed.items():" in loop


class TestTheCheckIsCheapEnoughForThePacketPath:
    """It is consulted per packet."""

    def test_the_answer_is_cached_per_address(self) -> None:
        service = _service()
        assert service._is_on_link("192.168.0.7") is True
        assert "192.168.0.7" in service._onlink_cache
        assert service._is_on_link("192.168.0.7") is True

    def test_the_cache_is_bounded(self) -> None:
        source = inspect.getsource(PacketCaptureService._is_on_link)
        assert "len(self._onlink_cache) < 20_000" in source

    def test_the_subnets_are_re_read_periodically(self) -> None:
        """So the answer is right after the machine changes network."""
        source = inspect.getsource(PacketCaptureService._is_on_link)
        assert "local_ipv4_networks()" in source
        assert "60.0" in source

    def test_a_refresh_clears_the_cache(self) -> None:
        source = inspect.getsource(PacketCaptureService._is_on_link)
        assert "self._onlink_cache.clear()" in source, (
            "stale answers survive a network change"
        )
