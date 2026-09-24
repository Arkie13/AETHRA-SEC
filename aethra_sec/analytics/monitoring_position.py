"""Can this sensor see traffic between *other* devices? (§121)

A passive sensor only detects what its adapter is handed. In a three-device
laboratory - attacker, target, and AETHRA-SEC on a third machine - that turns
out to be the question everything else depends on, and it is invisible from
inside the application: capture reports CAPTURING, packets arrive in their
thousands, the pipeline is healthy, and an attack between the other two devices
produces nothing at all. Every subsystem is working. The sensor simply never
received the frames.

Why a wireless sensor usually cannot
------------------------------------
On a switched or wireless network a frame is delivered only to its destination.
An Ethernet switch forwards unicast out the one port that owns the destination
MAC; a Wi-Fi access point does the same over the air, and on WPA2/WPA3 each
station's traffic is additionally encrypted under a pairwise key that no other
station holds. A third station in ordinary (managed) mode therefore receives:

* its own traffic,
* broadcast and multicast - ARP, DHCP, mDNS,
* nothing else.

Promiscuous mode does not change this. It stops the *adapter* discarding frames
addressed elsewhere, but the switch or AP never sent them, so there is nothing
to stop discarding. This is the distinction the check below is built around,
because it is the one operators most often expect to be untrue.

What this measures, and what it does not
----------------------------------------
This looks only at packets AETHRA-SEC actually captured. It counts how many
were exchanged between two hosts that are *neither* this sensor nor its
gateway, and reports the answer. It does not probe, scan, inject, or reconfigure
anything, and it never claims a capability it has not observed evidence for.

A verdict of :attr:`Visibility.OWN_TRAFFIC_ONLY` is a statement about the
sensor's network position, not about the detection rules. Raising a threshold
would not help; nothing reached the rules to be measured.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

#: Traffic to these is broadcast or multicast by design, so seeing it says
#: nothing about whether unicast between two other hosts is observable.
_MULTICAST_V4 = ipaddress.ip_network("224.0.0.0/4")

#: Protocols delivered to every station regardless of the addresses they name.
#:
#: ARP is the trap here. An ARP request is broadcast at layer 2, but it carries
#: a *target* IP, so a capture records it as "192.168.0.101 -> 192.168.0.105"
#: and it reads exactly like station-to-station unicast. Counting it produced a
#: confident "third-party traffic visible" verdict from a sensor that could see
#: nothing of the kind.
_BROADCAST_PROTOCOLS = frozenset(
    {"ARP", "MDNS", "SSDP", "LLMNR", "NBNS", "DHCP", "BOOTP", "IGMP"}
)


class Visibility(str, Enum):
    """What the sensor has been observed to be able to see."""

    #: Unicast between two other hosts has been captured. A passive sensor in
    #: this position can observe an attack between them.
    THIRD_PARTY_TRAFFIC = "THIRD_PARTY_TRAFFIC"
    #: Only this host's own traffic, plus broadcast. An attack between two
    #: other devices cannot be observed from here at all.
    OWN_TRAFFIC_ONLY = "OWN_TRAFFIC_ONLY"
    #: Too little captured to say either way.
    UNDETERMINED = "UNDETERMINED"

    @property
    def label(self) -> str:
        """How the diagnostics screen names it."""
        return {
            Visibility.THIRD_PARTY_TRAFFIC: "Third-party traffic visible",
            Visibility.OWN_TRAFFIC_ONLY: "Own traffic only",
            Visibility.UNDETERMINED: "Not yet determined",
        }[self]


@dataclass
class PositionReport:
    """What the capture has shown about the sensor's vantage point."""

    visibility: Visibility = Visibility.UNDETERMINED
    sampled: int = 0
    own: int = 0
    broadcast: int = 0
    third_party: int = 0
    #: A few observed third-party pairs, as evidence for the verdict.
    examples: list[tuple[str, str]] = field(default_factory=list)
    #: Hosts seen on the local network other than this sensor.
    peers: int = 0

    @property
    def can_see_third_party(self) -> bool:
        """True only when third-party unicast was actually observed."""
        return self.visibility is Visibility.THIRD_PARTY_TRAFFIC

    def summary(self) -> str:
        """One line for the diagnostics row."""
        if self.visibility is Visibility.UNDETERMINED:
            return (
                f"Only {self.sampled:,} packet(s) captured so far - not enough "
                "to judge what this position can see."
            )
        if self.can_see_third_party:
            return (
                f"{self.third_party:,} of {self.sampled:,} captured packet(s) "
                "were exchanged between two other devices."
            )
        return (
            f"None of {self.sampled:,} captured packet(s) were exchanged "
            f"between two other devices. {self.own:,} involved this host and "
            f"{self.broadcast:,} were broadcast or multicast."
        )

    def detail(self) -> str:
        """The consequence, spelled out for an operator."""
        if self.visibility is Visibility.UNDETERMINED:
            return (
                "Start a capture and let it run while the other devices are "
                "communicating, then run diagnostics again."
            )
        if self.can_see_third_party:
            pairs = ", ".join(f"{s} -> {d}" for s, d in self.examples[:3])
            return (
                "An attack between other devices on this network can be "
                "observed from here. Examples: " + (pairs or "-")
            )
        return (
            f"{self.peers} other host(s) are known on this network, so the "
            "network is not idle - their traffic is simply not delivered to "
            "this adapter. A switch forwards unicast only to the destination "
            "port, and a Wi-Fi access point does the same over the air with "
            "each station's frames encrypted under its own key. Promiscuous "
            "mode cannot recover frames that were never sent to this radio."
        )

    def remedy(self) -> str:
        """The supported ways to gain the missing visibility."""
        if self.can_see_third_party or self.visibility is Visibility.UNDETERMINED:
            return ""
        return (
            "To monitor traffic between two other devices, place the sensor "
            "where that traffic physically passes:\n"
            "  1. A switch SPAN / port-mirror session copying the target's "
            "port to the sensor's port. This is the usual laboratory answer.\n"
            "  2. A network TAP inline between the target and the switch.\n"
            "  3. Run the sensor on the target itself, so the traffic is its "
            "own.\n"
            "  4. Route the attack through the sensor - give it two "
            "interfaces and make it the target's gateway.\n"
            "  5. For wireless specifically: an adapter and driver that "
            "support monitor mode, on the right channel, with the network key "
            "supplied for decryption.\n"
            "AETHRA-SEC will not change your network to obtain this; each of "
            "these is a deliberate change for an operator to make."
        )


def assess(
    packets: list[tuple[str, str, str]],
    *,
    sensor_addresses: set[str],
    subnet: str,
    gateway: str = "",
    peers: int = 0,
    minimum_sample: int = 200,
) -> PositionReport:
    """Judge the sensor's vantage point from packets it actually captured.

    Args:
        packets: observed ``(source, destination, protocol)`` triples.
        sensor_addresses: every address belonging to this machine *now*.
        subnet: the network the sensor is on, e.g. ``192.168.0.0/24``. Only
            packets with both endpoints inside it are judged.
        gateway: the default gateway, excluded from the third-party count.
        peers: how many other hosts are known on the network, so an empty
            result can be distinguished from an empty network.
        minimum_sample: below this the answer is UNDETERMINED rather than a
            guess from too little evidence.

    Both the protocol and the subnet are required, and each closes a way of
    reaching a confidently wrong answer:

    * without the protocol, ARP counts as unicast. An ARP request names a
      target IP but is broadcast to every station, so it looks exactly like
      the station-to-station traffic being tested for;
    * without the subnet, packets captured while the machine was on a
      *different* network count as third-party, because the sensor's address
      then is not among its addresses now. A sensor's own history is the last
      thing that should be read as evidence about other devices.

    Returns:
        The report. Nothing is inferred that was not observed.
    """
    report = PositionReport(peers=peers)
    excluded = {address for address in sensor_addresses if address}
    if gateway:
        excluded.add(gateway)
    try:
        local = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        local = None

    seen: set[tuple[str, str]] = set()
    for source, destination, protocol in packets:
        if not source or not destination:
            continue
        if local is not None and not (
            _in_network(source, local) and _in_network(destination, local)
        ):
            # Either an internet endpoint or a different era's network. Not
            # evidence about what this position can see on this LAN.
            continue
        report.sampled += 1
        if source in sensor_addresses or destination in sensor_addresses:
            report.own += 1
            continue
        if str(protocol or "").upper() in _BROADCAST_PROTOCOLS:
            report.broadcast += 1
            continue
        if _is_broadcast(destination) or source == destination:
            report.broadcast += 1
            continue
        if source in excluded or destination in excluded:
            # Talking to the gateway is not third-party visibility.
            report.broadcast += 1
            continue
        report.third_party += 1
        if len(seen) < 5:
            seen.add((source, destination))

    report.examples = sorted(seen)
    if report.sampled < max(1, minimum_sample):
        report.visibility = Visibility.UNDETERMINED
    elif report.third_party:
        report.visibility = Visibility.THIRD_PARTY_TRAFFIC
    else:
        report.visibility = Visibility.OWN_TRAFFIC_ONLY
    return report


def _in_network(address: str, network: ipaddress.IPv4Network) -> bool:
    """True when ``address`` sits inside ``network``."""
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def _is_broadcast(address: str) -> bool:
    """True for a broadcast or multicast destination."""
    if address.endswith(".255") or address == "255.255.255.255":
        return True
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_multicast or parsed in _MULTICAST_V4
