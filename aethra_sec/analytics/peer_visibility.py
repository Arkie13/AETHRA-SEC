"""Does this capture point actually receive other devices' traffic?

"Live Monitoring does not show the other device" has two causes that look
identical in the packet table and have opposite remedies. Either the frames
arrive and something here discards them - fixable in this application - or they
never arrive, which no amount of code can fix. Only counting real captured
frames tells them apart, and the count has to come from packets rather than
from the host inventory: a host in the Hosts table was seen at *some* point,
which says nothing about whether its traffic is visible now.

Measured on this machine, it was the second cause, and the evidence is
unusually clean. Forty seconds of genuinely promiscuous capture on the Wi-Fi
interface produced 1,796 frames: 1,769 belonged to this host, 16 were broadcast
or multicast, 11 were ARP, and **zero** were another device's unicast. Four
other devices were plainly present - 192.168.100.192, .24, .61 and .39 all sent
SSDP and IGMP, which is flooded to every station - yet not one of their unicast
frames was delivered. Windows explains why: for this adapter,
``netsh wlan show wirelesscapabilities`` reports

    Network monitor mode : Not supported
    Promiscuous Mode     : Not Supported

so the request TShark makes is refused by the driver.

That distinction matters enough to state precisely, because the two are
routinely confused:

* **Promiscuous mode** lets an adapter keep frames that *reach it* but are
  addressed to some other MAC.
* **Mirroring (SPAN) or a TAP** is what causes another device's frames to
  reach the interface in the first place.

Promiscuous mode alone therefore cannot make a switched or wireless network
deliver a peer's unicast traffic. It is a network topology requirement, not a
setting in this application - and this module exists so the interface can say
that plainly instead of showing an empty table and letting the operator assume
the software is broken.

Everything here counts frames the capture actually produced. Nothing is read
from the database and nothing is inferred.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass

#: Cap on remembered addresses per class. A scan or a flood can touch thousands
#: of endpoints; the counts stay useful long after the sets stop growing.
MAX_TRACKED = 2048

#: Frames from other devices needed before peer traffic is called visible. One
#: stray frame is not visibility, and treating it as such would turn a network
#: limitation into a claim the operator would act on.
VISIBILITY_THRESHOLD = 5

#: §20. Shown when peers are known to exist but none of their unicast arrives.
NOT_VISIBLE = (
    "Other-device traffic is not currently visible at this capture point."
)

#: What to do about it. Deliberately about the network, not this application.
OBSERVATION_POINT_ADVICE = (
    "To monitor other devices, the capture interface must receive their "
    "traffic. Connect it to an authorised observation point: switch SPAN / "
    "port mirroring, a network TAP, a capture point on the gateway or router, "
    "or another interface through which that traffic actually passes."
)

#: The distinction §7 asks to be documented in the application itself.
PROMISCUOUS_VS_MIRRORING = (
    "Promiscuous mode lets the adapter keep frames that reach it but are "
    "addressed to another device. Mirroring (SPAN) or a TAP is what makes "
    "those frames reach the interface at all. Promiscuous mode alone cannot "
    "make a switched network deliver another device's unicast traffic."
)


def _is_group_destination(ip_address: str, mac: str) -> bool:
    """True for broadcast and multicast, at either layer.

    These are flooded to every station by design. Counting them as peer
    traffic would report visibility that does not exist - the first version of
    this check missed IP multicast and reported nine SSDP frames as peer
    unicast.
    """
    cleaned = (mac or "").strip().lower().replace("-", ":")
    if cleaned.startswith("ff:ff"):
        return True
    if cleaned and len(cleaned) >= 2:
        try:
            if int(cleaned.split(":")[0], 16) & 0x01:
                return True
        except ValueError:
            pass
    try:
        parsed = ipaddress.ip_address((ip_address or "").strip())
    except ValueError:
        return False
    return bool(parsed.is_multicast) or str(parsed).endswith(".255")


@dataclass(frozen=True)
class VisibilityReport:
    """What the capture has actually seen, and what that means."""

    frames: int = 0
    own_frames: int = 0
    group_frames: int = 0
    peer_frames: int = 0
    local_hosts: int = 0
    peer_hosts: int = 0
    group_only_hosts: int = 0

    @property
    def peer_traffic_visible(self) -> bool:
        """True only when enough real peer unicast frames were captured."""
        return self.peer_frames >= VISIBILITY_THRESHOLD

    @property
    def peers_exist_but_are_invisible(self) -> bool:
        """Other devices are demonstrably present, yet unreachable.

        The strongest possible statement of the limitation: their broadcast
        traffic arrives, so they are on this network, and their unicast does
        not. That is the network declining to deliver it, not a parser fault.
        """
        return self.group_only_hosts > 0 and not self.peer_traffic_visible

    def verdict(self) -> str:
        """One line an operator can act on."""
        if self.peer_traffic_visible:
            return (
                f"Peer traffic IS visible: {self.peer_frames:,} frame(s) from "
                f"{self.peer_hosts} other device(s)."
            )
        if self.peers_exist_but_are_invisible:
            return (
                f"{NOT_VISIBLE} {self.group_only_hosts} other device(s) are "
                "present on this network - their broadcast traffic arrives - "
                "but none of their unicast traffic is delivered here."
            )
        if self.frames:
            return NOT_VISIBLE
        return "No frames have been captured yet."


class PeerVisibilityTracker:
    """Counts, from real captured frames, whose traffic is arriving.

    Fed from the capture worker, read from anywhere. Cheap enough for the hot
    path: two set lookups and an integer increment per packet, with the sets
    capped so a flood cannot grow them without bound.
    """

    def __init__(self, *, max_tracked: int = MAX_TRACKED) -> None:
        self._max = max(16, int(max_tracked))
        self._lock = threading.Lock()
        self._local: set[str] = set()
        self._peers: set[str] = set()
        self._group_only: set[str] = set()
        self._frames = 0
        self._own = 0
        self._group = 0
        self._peer = 0

    def observe(self, packet, local) -> None:  # noqa: ANN001
        """Count one captured frame.

        ``local`` is the LocalAddresses view the direction classifier already
        builds, so this agrees with how the rest of the application decides
        what "this host" means rather than inventing a second answer.
        """
        source = (getattr(packet, "src_ip", "") or "").strip()
        destination = (getattr(packet, "dst_ip", "") or "").strip()
        destination_mac = getattr(packet, "dst_mac", "") or ""

        with self._lock:
            self._frames += 1

            source_local = bool(source) and local.is_local(source)
            destination_local = bool(destination) and local.is_local(destination)
            if source_local or destination_local:
                self._own += 1
                if source_local and len(self._local) < self._max:
                    self._local.add(source)
                if destination_local and len(self._local) < self._max:
                    self._local.add(destination)
                return

            if _is_group_destination(destination, destination_mac):
                self._group += 1
                # A device whose only traffic here is broadcast is present on
                # the network but not observable - the exact case worth naming.
                if source and source not in self._peers:
                    if len(self._group_only) < self._max:
                        self._group_only.add(source)
                return

            if not source and not destination:
                return

            self._peer += 1
            for address in (source, destination):
                if address and len(self._peers) < self._max:
                    self._peers.add(address)
                    self._group_only.discard(address)

    def report(self) -> VisibilityReport:
        """A consistent snapshot of what has been observed."""
        with self._lock:
            return VisibilityReport(
                frames=self._frames,
                own_frames=self._own,
                group_frames=self._group,
                peer_frames=self._peer,
                local_hosts=len(self._local),
                peer_hosts=len(self._peers),
                group_only_hosts=len(self._group_only),
            )

    def reset(self) -> None:
        """Forget everything. Called when a capture session starts."""
        with self._lock:
            self._local.clear()
            self._peers.clear()
            self._group_only.clear()
            self._frames = self._own = self._group = self._peer = 0
