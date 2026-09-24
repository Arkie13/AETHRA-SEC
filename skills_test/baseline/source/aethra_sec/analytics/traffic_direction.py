"""Which way a captured packet travelled, relative to the capture interface.

Direction is a statement about *this sensor*, so it can only be decided from
this sensor's own addresses - the ones the operating system reports for the
interface being captured on, read at capture time. No address is written into
this module, none is taken from configuration, and a port number never enters
the decision: TCP to port 443 is not "outgoing" because of the port, it is
outgoing because its source is one of this interface's addresses.

The categories
--------------
``OUTGOING``   the source is an address of the capture interface.
``INCOMING``   the destination is an address of the capture interface and the
               source is not.
``LOCAL``      both endpoints are addresses of the capture interface (loopback
               capture, or a machine talking to itself).
``BROADCAST``  neither endpoint is local and the destination is broadcast or
               multicast - ARP requests about other hosts, mDNS, SSDP, DHCP.
``TRANSIT``    neither endpoint is local and the destination is an ordinary
               unicast address: traffic *between two other devices* that this
               adapter nevertheless received, which on a switched network only
               happens through a mirror (SPAN) port, a TAP, or when this machine
               sits in the path.
``UNKNOWN``    the interface's addresses could not be determined, or the frame
               carries no endpoints to judge.

Why BROADCAST is separate from TRANSIT
--------------------------------------
Every station on a LAN receives broadcast and multicast, whatever its position.
Folding that chatter into TRANSIT would make a laptop on ordinary Wi-Fi report
"transit traffic observed" within seconds - a claim that the sensor can see
traffic between other devices, made on evidence that says nothing of the kind.
:mod:`aethra_sec.analytics.monitoring_position` draws the same line for the
same reason. TRANSIT is kept for the evidence that actually matters to a
three-device laboratory: unicast between an attacker and a target, delivered to
this adapter.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("analytics.direction")

#: RFC 919 limited broadcast, computed rather than written as a literal so the
#: module carries no address in its source.
LIMITED_BROADCAST = str(ipaddress.IPv4Address((1 << 32) - 1))


class Direction(str, Enum):
    """A packet's relationship to the capture interface."""

    INCOMING = "INCOMING"
    OUTGOING = "OUTGOING"
    TRANSIT = "TRANSIT"
    BROADCAST = "BROADCAST"
    LOCAL = "LOCAL"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        """The stored value."""
        return self.value

    @property
    def label(self) -> str:
        """How the interface names it."""
        return self.value.title()

    @property
    def explanation(self) -> str:
        """Why a packet was given this direction, in one sentence."""
        return _EXPLANATIONS[self]


_EXPLANATIONS: dict[Direction, str] = {
    Direction.INCOMING: (
        "the destination is an address of the capture interface and the "
        "source is not"
    ),
    Direction.OUTGOING: "the source is an address of the capture interface",
    Direction.TRANSIT: (
        "neither endpoint belongs to the capture interface - this is traffic "
        "between two other devices that reached this adapter"
    ),
    Direction.BROADCAST: (
        "neither endpoint belongs to the capture interface and the destination "
        "is broadcast or multicast, which every station on the segment receives"
    ),
    Direction.LOCAL: "both endpoints are addresses of the capture interface",
    Direction.UNKNOWN: (
        "the capture interface's addresses are not known, or the frame carries "
        "no endpoints to judge"
    ),
}

#: The order directions are listed in wherever they are counted.
DIRECTION_ORDER: tuple[Direction, ...] = (
    Direction.INCOMING,
    Direction.OUTGOING,
    Direction.TRANSIT,
    Direction.BROADCAST,
    Direction.LOCAL,
    Direction.UNKNOWN,
)


def normalise_ip(value: str) -> str:
    """Canonical text for an IP address, or ``""`` when it is not one.

    The zone suffix of an IPv6 link-local address (``%12``) is dropped: the
    operating system reports it, TShark does not, and the two must compare.
    """
    text = (value or "").strip().split("%", 1)[0]
    if not text:
        return ""
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return ""


def normalise_mac(value: str) -> str:
    """``aa:bb:cc:dd:ee:ff`` form, or ``""`` when the value is not a MAC."""
    text = (value or "").strip().lower().replace("-", ":")
    return text if len(text) == 17 else ""


def is_group_mac(value: str) -> bool:
    """True for a broadcast or multicast hardware address.

    Bit 0 of the first octet is the IEEE individual/group bit; broadcast
    (all ones) is a group address too.
    """
    mac = normalise_mac(value)
    if not mac:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x01)
    except ValueError:
        return False


@dataclass(frozen=True)
class LocalAddresses:
    """The capture interface's own addresses, as the OS reported them.

    Attributes:
        interface: the capture device name these belong to.
        addresses: IPv4 and IPv6 addresses, canonical text.
        mac_addresses: hardware addresses, used only for frames that carry no
            IP or ARP endpoints.
        broadcast_addresses: directed-broadcast addresses of the interface's own
            IPv4 subnets, derived from the reported netmasks.
        loopback: True for a loopback capture device, where every loopback
            address and every address of the machine is local.
        source: how the addresses were found, for the interface to show.
        detail: why they could not be found, when they could not.
    """

    interface: str = ""
    addresses: frozenset[str] = frozenset()
    mac_addresses: frozenset[str] = frozenset()
    broadcast_addresses: frozenset[str] = frozenset()
    loopback: bool = False
    source: str = ""
    detail: str = ""

    @property
    def resolved(self) -> bool:
        """True when there is at least one IP address to judge direction by."""
        return bool(self.addresses)

    def is_local(self, address: str) -> bool:
        """Whether a canonical address belongs to the capture interface."""
        if not address:
            return False
        if address in self.addresses:
            return True
        if self.loopback:
            try:
                return ipaddress.ip_address(address).is_loopback
            except ValueError:
                return False
        return False

    def describe(self) -> str:
        """One line naming the addresses, or why there are none."""
        if not self.resolved:
            return self.detail or "The capture interface's addresses are not known."
        ordered = sorted(self.addresses, key=lambda a: (":" in a, a))
        shown = ", ".join(ordered[:4])
        more = len(ordered) - 4
        return shown + (f" and {more} more" if more > 0 else "")


@dataclass(frozen=True)
class OsInterface:
    """One operating-system interface: its addresses, netmasks and MAC."""

    name: str
    addresses: tuple[str, ...] = ()
    netmasks: tuple[tuple[str, str], ...] = ()
    mac: str = ""


def os_interfaces() -> dict[str, OsInterface]:
    """Every interface the operating system reports, keyed by its name.

    Read through psutil, which on Windows keys interfaces by the adapter's
    friendly name ("Wi-Fi") and on Linux by the device name ("eth0").
    """
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a declared dependency
        return {}
    try:
        table = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001 - never break capture over this
        return {}

    link_family = getattr(psutil, "AF_LINK", None)
    result: dict[str, OsInterface] = {}
    for name, entries in table.items():
        addresses: list[str] = []
        netmasks: list[tuple[str, str]] = []
        mac = ""
        for entry in entries:
            family = getattr(entry, "family", None)
            if family in (socket.AF_INET, socket.AF_INET6):
                address = normalise_ip(getattr(entry, "address", "") or "")
                if not address:
                    continue
                addresses.append(address)
                netmask = getattr(entry, "netmask", "") or ""
                if family == socket.AF_INET and netmask:
                    netmasks.append((address, netmask))
            elif link_family is not None and family == link_family:
                mac = normalise_mac(getattr(entry, "address", "") or "")
        result[name] = OsInterface(
            name=name,
            addresses=tuple(dict.fromkeys(addresses)),
            netmasks=tuple(netmasks),
            mac=mac,
        )
    return result


def _adapter_names() -> dict[str, str]:
    """Windows adapter GUID -> friendly name, from the OS's own adapter list."""
    from aethra_sec.utils.net import windows_adapter_details

    return {
        guid: detail.friendly_name
        for guid, detail in windows_adapter_details().items()
        if detail.friendly_name
    }


def _guid(interface: str) -> str:
    r"""The adapter GUID inside a Windows ``\Device\NPF_{GUID}`` name."""
    marker = "NPF_"
    if marker not in interface:
        return ""
    return interface.split(marker, 1)[1].strip().upper()


def _directed_broadcasts(netmasks: tuple[tuple[str, str], ...]) -> frozenset[str]:
    """Directed-broadcast addresses of the interface's own IPv4 subnets."""
    found: set[str] = set()
    for address, netmask in netmasks:
        try:
            network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        except ValueError:
            continue
        # /31 and /32 have no broadcast address (RFC 3021).
        if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < 31:
            found.add(str(network.broadcast_address))
    return frozenset(found)


def resolve_local_addresses(
    interface: str,
    *,
    interfaces: Callable[[], dict[str, OsInterface]] | None = None,
    adapter_names: Callable[[], dict[str, str]] | None = None,
) -> LocalAddresses:
    """Find the addresses of the interface a capture is running on.

    TShark names a Windows device ``\\Device\\NPF_{GUID}``; the operating
    system names the same adapter "Wi-Fi". The GUID is the exact join between
    the two, so it is used rather than matching names, which operators rename.

    Args:
        interface: the capture device name, exactly as TShark was given it.
        interfaces: OS interface table, injectable for tests.
        adapter_names: GUID -> friendly-name table, injectable for tests.

    Returns:
        The addresses, or an unresolved result whose ``detail`` says why. An
        unresolved result makes every packet UNKNOWN rather than guessing.
    """
    name = (interface or "").strip()
    if not name:
        return LocalAddresses(detail="No capture interface is selected.")

    try:
        table = (interfaces or os_interfaces)()
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Could not read the OS interface table: %s", exc)
        table = {}

    if "loopback" in name.lower():
        # A loopback capture sees traffic to every address on the machine.
        every: set[str] = set()
        for entry in table.values():
            every.update(entry.addresses)
        return LocalAddresses(
            interface=name,
            addresses=frozenset(every),
            loopback=True,
            source="loopback capture: every address on this machine is local",
            detail="" if every else "No addresses are configured on this machine.",
        )

    match = table.get(name)
    source = f"operating-system interface '{name}'"
    if match is None:
        guid = _guid(name)
        if guid:
            try:
                friendly = (adapter_names or _adapter_names)().get(guid, "")
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Could not read the Windows adapter list: %s", exc)
                friendly = ""
            if friendly:
                match = table.get(friendly)
                source = f"adapter '{friendly}'"

    if match is None:
        return LocalAddresses(
            interface=name,
            detail=(
                "The capture interface could not be matched to an operating-"
                "system adapter, so its addresses are unknown and packet "
                "direction cannot be determined."
            ),
        )

    macs = frozenset({match.mac}) if match.mac else frozenset()
    if not match.addresses:
        return LocalAddresses(
            interface=name,
            mac_addresses=macs,
            source=source,
            detail=(
                f"The {source} has no IP address, so packet direction cannot "
                "be determined."
            ),
        )

    return LocalAddresses(
        interface=name,
        addresses=frozenset(match.addresses),
        mac_addresses=macs,
        broadcast_addresses=_directed_broadcasts(match.netmasks),
        source=source,
    )


def _is_broadcast_or_multicast(address: str, local: LocalAddresses) -> bool:
    """True for a broadcast or multicast IP destination."""
    if not address:
        return False
    if address == LIMITED_BROADCAST or address in local.broadcast_addresses:
        return True
    try:
        return ipaddress.ip_address(address).is_multicast
    except ValueError:
        return False


def _identifying(address: str) -> str:
    """The address, or ``""`` when it identifies no host.

    The unspecified address - all zeros, in IPv4 or IPv6 - is what a host sends
    from before it has an address (DHCP, ARP probes, duplicate-address
    detection), and what an ARP reply names as the target of such a probe. It
    says nothing about which machine an endpoint is.
    """
    if not address:
        return ""
    try:
        return "" if ipaddress.ip_address(address).is_unspecified else address
    except ValueError:
        return ""


def classify(packet: Any, local: LocalAddresses) -> Direction:
    """Decide one packet's direction from its addresses and nothing else.

    An endpoint's IP (or ARP protocol address) decides whether that endpoint is
    this interface. Where the frame carries no identifying IP for an endpoint -
    a non-IP frame such as LLDP or STP, or the unspecified address a host uses
    before it has one - that endpoint's hardware address is the only evidence
    there is, and it is used instead.

    The fallback is per endpoint, and it matters. A real laboratory capture held
    ARP replies addressed to this adapter's own MAC whose target IP was the
    unspecified address - answers to the probe this machine sent before its
    address was assigned. Judged on IP alone, neither endpoint was local and
    they were classified as TRANSIT: traffic between two other devices, which
    they were not.
    """
    if not local.resolved:
        return Direction.UNKNOWN

    source = _identifying(normalise_ip(getattr(packet, "src_ip", "") or ""))
    destination = _identifying(normalise_ip(getattr(packet, "dst_ip", "") or ""))
    source_mac = normalise_mac(getattr(packet, "src_mac", "") or "")
    destination_mac = normalise_mac(getattr(packet, "dst_mac", "") or "")

    source_local = (
        local.is_local(source) if source
        else bool(source_mac) and source_mac in local.mac_addresses
    )
    destination_local = (
        local.is_local(destination) if destination
        else bool(destination_mac) and destination_mac in local.mac_addresses
    )
    if source_local and destination_local:
        return Direction.LOCAL
    if source_local:
        return Direction.OUTGOING
    if destination_local:
        return Direction.INCOMING
    if _is_broadcast_or_multicast(destination, local) or is_group_mac(destination_mac):
        return Direction.BROADCAST
    if (source or source_mac) and (destination or destination_mac):
        return Direction.TRANSIT
    return Direction.UNKNOWN
