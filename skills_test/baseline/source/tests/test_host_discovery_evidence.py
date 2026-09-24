"""Passive host discovery must rest on evidence (§58).

A host inventory is a security artefact: "this address exists and is up" is a
claim, and the only thing on the wire that establishes it is the address having
transmitted. Appearing as a *destination* establishes nothing — an ARP request
names an address nobody has answered for, and a packet sent to a machine that
is switched off looks exactly like one sent to a machine that is not.

The assessment found the live inventory holding 1,499 hosts, every one marked
UP: 284 of them carrying the Ethernet broadcast address as their MAC (ARP
request targets), and 972 sharing a single MAC — the local gateway's, stamped
onto public internet addresses that had merely been contacted through it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import ipaddress

import pytest

from aethra_sec.models.traffic import CapturedPacket
from aethra_sec.services.packet_capture import PacketCaptureService, _is_host_mac


class _Rollup:
    """Just enough of the service to run the real method against.

    ``_accumulate_host`` reads and writes ``_pending_hosts`` and nothing else,
    so the real implementation runs here unmodified - this avoids standing up a
    database and a capture pipeline to exercise a pure fold.
    """

    def __init__(self) -> None:
        self._pending_hosts: dict = {}
        # A fixed local subnet, so on-link membership is deterministic rather
        # than depending on whatever network the test machine is attached to.
        self._local_networks = (ipaddress.ip_network("192.168.1.0/24"),)
        self._local_networks_at = 1e12
        self._onlink_cache: dict[str, bool] = {}

    _accumulate_host = PacketCaptureService._accumulate_host
    _is_on_link = PacketCaptureService._is_on_link


@pytest.fixture
def capture_service() -> _Rollup:
    """A holder running the service's own accumulation logic."""
    return _Rollup()

BROADCAST = "ff:ff:ff:ff:ff:ff"
SENDER = "aa:bb:cc:dd:ee:ff"
GATEWAY = "f0:3f:95:0b:ce:77"
# A real unicast MAC: bit 0 of the first octet clear. 11:22:... would be
# multicast, which the filter correctly refuses.
RESPONDER = "00:1a:2b:3c:4d:5e"


class TestOnlyAHostsOwnMacCounts:
    """A MAC that belongs to no single machine is not a host's identity."""

    def test_a_normal_unicast_address_is_accepted(self) -> None:
        assert _is_host_mac(SENDER)
        assert _is_host_mac(GATEWAY)

    def test_the_broadcast_address_is_refused(self) -> None:
        """284 inventory rows carried this as their hardware address."""
        assert not _is_host_mac(BROADCAST)

    def test_multicast_addresses_are_refused(self) -> None:
        # Bit 0 of the first octet marks a group address: IPv4 multicast
        # (01:00:5e:...) and IPv6 multicast (33:33:...) both set it.
        assert not _is_host_mac("01:00:5e:00:00:fb")
        assert not _is_host_mac("33:33:00:00:00:01")

    def test_nonsense_is_refused_rather_than_stored(self) -> None:
        for value in ("", "   ", "garbage", "aa:bb", "zz:zz:zz:zz:zz:zz"):
            assert not _is_host_mac(value), value

    def test_separators_and_case_do_not_change_the_answer(self) -> None:
        assert _is_host_mac("AA-BB-CC-DD-EE-FF")
        assert not _is_host_mac("FF-FF-FF-FF-FF-FF")


class TestTransmissionIsWhatEstablishesAHost:
    """The rollup must distinguish a sender from an address merely named."""

    @staticmethod
    def _accumulate(service, packets: list[CapturedPacket]) -> dict:
        for packet in packets:
            service._accumulate_host(packet)  # noqa: SLF001 - the unit under test
        return service._pending_hosts  # noqa: SLF001

    @staticmethod
    def _packet(src_ip: str, dst_ip: str, src_mac: str, dst_mac: str) -> CapturedPacket:
        return CapturedPacket(
            captured_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            protocol="ARP",
            length=42,
        )

    def test_an_arp_request_target_is_not_treated_as_discovered(self, capture_service) -> None:
        """"Who has .127? Tell .222" is a question about .127, not a sighting."""
        pending = self._accumulate(
            capture_service,
            [self._packet("192.168.1.222", "192.168.1.127", SENDER, BROADCAST)],
        )
        assert pending["192.168.1.222"]["transmitted"] is True
        assert pending["192.168.1.127"]["transmitted"] is False, (
            "the address being asked about was marked as observed"
        )

    def test_the_broadcast_mac_is_never_attached_to_the_target(
        self, capture_service
    ) -> None:
        pending = self._accumulate(
            capture_service,
            [self._packet("192.168.1.222", "192.168.1.127", SENDER, BROADCAST)],
        )
        assert pending["192.168.1.127"]["mac"] == ""
        assert pending["192.168.1.222"]["mac"] == SENDER

    def test_an_arp_reply_does_establish_the_responder(self, capture_service) -> None:
        """A reply is evidence: the address answered, with its own MAC."""
        pending = self._accumulate(
            capture_service,
            [self._packet("192.168.1.127", "192.168.1.222", RESPONDER, SENDER)],
        )
        assert pending["192.168.1.127"]["transmitted"] is True
        assert pending["192.168.1.127"]["mac"] == RESPONDER

    def test_an_external_address_does_not_inherit_the_gateway_mac(
        self, capture_service
    ) -> None:
        """Off-LAN traffic carries the router's MAC in eth.dst, not the host's."""
        pending = self._accumulate(
            capture_service,
            [self._packet("192.168.1.222", "142.250.66.68", SENDER, GATEWAY)],
        )
        assert pending["142.250.66.68"]["mac"] == "", (
            "a public address was given the local gateway's hardware address"
        )
        assert pending["142.250.66.68"]["transmitted"] is False

    def test_an_external_sender_does_not_inherit_the_gateway_mac(
        self, capture_service
    ) -> None:
        """The case the test above missed, and the one that actually happened.

        A reply from the internet *is* a sender, so it passed the transmitted
        check - and a sender's MAC was recorded. But the frame was forwarded by
        the router, so that MAC is the router's. This is how 333 unrelated
        internet servers came to share one hardware address.
        """
        pending = self._accumulate(
            capture_service,
            [self._packet("142.250.66.68", "192.168.1.222", GATEWAY, SENDER)],
        )
        record = pending["142.250.66.68"]
        assert record["transmitted"] is True, "it did send a frame"
        assert record["on_link"] is False, "but not on this link"
        assert record["mac"] == "", (
            "an off-link sender was given the router's hardware address"
        )

    def test_an_off_link_sender_is_not_an_inventory_host(
        self, capture_service
    ) -> None:
        """It is a conversation peer, not a device on the monitored network."""
        pending = self._accumulate(
            capture_service,
            [self._packet("142.250.66.68", "192.168.1.222", GATEWAY, SENDER)],
        )
        enrolled = {
            address for address, data in pending.items()
            if data["transmitted"] and data["on_link"]
        }
        assert "142.250.66.68" not in enrolled
        assert pending["142.250.66.68"]["packets_sent"] == 1, (
            "its traffic must still be counted"
        )

    def test_a_reply_from_that_address_still_records_traffic_both_ways(
        self, capture_service
    ) -> None:
        """Counters must survive the tighter inventory rule."""
        pending = self._accumulate(
            capture_service,
            [
                self._packet("192.168.1.222", "142.250.66.68", SENDER, GATEWAY),
                self._packet("142.250.66.68", "192.168.1.222", GATEWAY, SENDER),
            ],
        )
        local = pending["192.168.1.222"]
        assert local["packets_sent"] == 1
        assert local["packets_received"] == 1
