"""Which hosts automatic assessment may touch: the monitored laboratory network.

The manuscript places AETHRA-SEC on a controlled, isolated laboratory LAN and
restricts all testing to it (§3.6.1, §3.7). Automatic assessment starts Nmap
against machines nobody typed in, so the question "is this address part of the
authorised laboratory network?" has to have a precise answer - and the answer
must not be "any private address".

It used to be exactly that. The configured authorised networks were the whole
of RFC 1918 plus loopback, so every private address anywhere was in scope. On
the development machine that included a ZeroTier overlay (172.22.0.0/16), whose
"on-link" peers are other people's computers reached over the internet, and a
VMware adapter claiming the same /24 as the Wi-Fi.

The rule now
------------
Automatic assessment covers the intersection of two independent facts:

* the subnets **attached to the interface being monitored** - read live from
  the operating system for the adapter capture is actually using; and
* the **configured authorised ranges** an administrator set.

Neither alone is enough. The interface says where the sensor is; the
configuration says what the institution authorised. A laptop that moves to a
different network keeps its configuration but gets a new attached subnet, and
the intersection follows it: the old laboratory hosts fall out of scope and are
no longer scanned.

When the scope cannot be determined safely, it is *unavailable*, never guessed:
no configured ranges, no monitored interface, an interface that cannot be
matched to an adapter, no overlap between the two, or an overlap too large to
be a laboratory segment. Automatic assessment then stops and says why.

Manual, operator-initiated scans are not governed by this module. They remain
bounded by the configured authorised networks in
:class:`~aethra_sec.services.nmap_service.NmapService`, because an operator
typing a target is an explicit act of authorisation that automation is not.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("analytics.assessment_scope")

#: Shown whenever automatic assessment cannot establish its scope.
UNAVAILABLE_MESSAGE = (
    "Automatic assessment unavailable — authorized network scope not configured."
)

#: Largest effective scope, in addresses, automatic assessment will accept.
#: 1,024 is a /22: comfortably above a laboratory segment, and far below the
#: /16 overlays and campus networks this exists to keep out.
DEFAULT_MAX_SCOPE_ADDRESSES = 1024

IPv4Net = ipaddress.IPv4Network

#: GUID -> friendly-name table, cached: it is read with a PowerShell query that
#: takes most of a second, and adapters are not renamed from one minute to the
#: next. Addresses are *not* cached here - they are read live through psutil.
_ADAPTER_NAME_TTL = 300.0
_adapter_cache: tuple[float, dict[str, str]] = (0.0, {})


def _cached_adapter_names() -> dict[str, str]:
    """The Windows adapter GUID -> friendly-name table, cached briefly."""
    global _adapter_cache
    import time

    from aethra_sec.analytics.traffic_direction import _adapter_names

    stamp, table = _adapter_cache
    now = time.monotonic()
    if table and now - stamp < _ADAPTER_NAME_TTL:
        return table
    table = _adapter_names()
    _adapter_cache = (now, table)
    return table


def adapter_networks(adapter: str) -> tuple[IPv4Net, ...]:
    """IPv4 subnets on one OS adapter, read live through psutil (fast)."""
    from aethra_sec.analytics.traffic_direction import os_interfaces

    entry = os_interfaces().get(adapter)
    if entry is None:
        return ()
    networks: list[IPv4Net] = []
    for address, netmask in entry.netmasks:
        try:
            network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and not network.is_link_local:
            networks.append(network)
    return tuple(dict.fromkeys(networks))


@dataclass(frozen=True)
class AssessmentScope:
    """The networks automatic assessment may assess, or why there are none."""

    available: bool
    #: Capture device name exactly as TShark was given it.
    interface: str = ""
    #: The operating-system adapter it resolved to ("Wi-Fi").
    adapter: str = ""
    #: Subnets attached to that adapter, as the operating system reports them.
    attached: tuple[IPv4Net, ...] = ()
    #: Configured authorised ranges, as given.
    configured: tuple[str, ...] = ()
    #: The effective scope: attached subnets inside the configured ranges.
    networks: tuple[IPv4Net, ...] = ()
    #: Why the scope is unavailable. Empty when it is available.
    reason: str = ""
    #: Addresses of the monitoring machine itself, never assessed.
    own_addresses: frozenset[str] = field(default_factory=frozenset)

    def contains(self, address: str) -> bool:
        """True when ``address`` lies inside the effective scope."""
        if not self.available or not address:
            return False
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        if not isinstance(parsed, ipaddress.IPv4Address):
            # No IPv6 prefix can be read reliably from the Windows adapter
            # table, so no IPv6 address is ever inside an automatic scope.
            return False
        return any(parsed in network for network in self.networks)

    def is_assessable_address(self, address: str) -> bool:
        """In scope, and a unicast host address rather than a subnet artefact."""
        if not self.contains(address):
            return False
        parsed = ipaddress.ip_address(address)
        for network in self.networks:
            if parsed not in network:
                continue
            if network.prefixlen < 31 and parsed in (
                network.network_address, network.broadcast_address,
            ):
                return False
        return not (parsed.is_multicast or parsed.is_unspecified)

    @property
    def address_ranges(self) -> tuple[tuple[int, int], ...]:
        """``(first, last)`` integer bounds per network, for SQL range filters."""
        return tuple(
            (int(network.network_address), int(network.broadcast_address))
            for network in self.networks
        )

    @property
    def signature(self) -> str:
        """A stable string that changes exactly when the scope changes."""
        if not self.available:
            return f"unavailable:{self.reason}"
        return ",".join(str(n) for n in self.networks)

    def describe(self) -> str:
        """One line for the interface and the audit trail."""
        if not self.available:
            return f"{UNAVAILABLE_MESSAGE} {self.reason}".strip()
        where = self.adapter or self.interface
        return (
            f"Automatic assessment scope: {', '.join(str(n) for n in self.networks)} "
            f"(monitored interface {where}, inside the configured authorised "
            f"ranges {', '.join(self.configured)})."
        )


def _parse_configured(configured: Iterable[str]) -> tuple[list[IPv4Net], list[str]]:
    """Configured IPv4 ranges, and the entries that could not be read."""
    parsed: list[IPv4Net] = []
    rejected: list[str] = []
    for raw in configured:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            rejected.append(text)
            continue
        if isinstance(network, ipaddress.IPv4Network):
            parsed.append(network)
    return parsed, rejected


def intersect(a: IPv4Net, b: IPv4Net) -> IPv4Net | None:
    """The overlap of two CIDR blocks. CIDR blocks either nest or are disjoint."""
    if a.subnet_of(b):
        return a
    if b.subnet_of(a):
        return b
    return None


def attached_networks(
    interface: str,
    *,
    interfaces: Callable[[], dict] | None = None,
    adapter_names: Callable[[], dict[str, str]] | None = None,
) -> tuple[str, tuple[IPv4Net, ...], frozenset[str], str]:
    """Resolve a capture device to its adapter's attached IPv4 subnets.

    Returns:
        ``(adapter, networks, own_addresses, problem)``. ``problem`` is empty
        on success and otherwise explains why the subnets are unknown.
    """
    from aethra_sec.analytics.traffic_direction import _guid, os_interfaces

    name = (interface or "").strip()
    if not name:
        return "", (), frozenset(), (
            "No interface is being monitored. Start packet capture on the "
            "laboratory interface first."
        )
    try:
        table = (interfaces or os_interfaces)()
    except Exception as exc:  # noqa: BLE001
        return "", (), frozenset(), f"The adapter table could not be read: {exc}"

    own = frozenset(
        address for entry in table.values() for address in entry.addresses
    )

    match = None
    adapter = ""
    if "loopback" in name.lower():
        for entry in table.values():
            if any(a.startswith("127.") for a in entry.addresses):
                match, adapter = entry, entry.name
                break
    else:
        match = table.get(name)
        adapter = name if match is not None else ""
        if match is None:
            guid = _guid(name)
            if guid:
                try:
                    friendly = (adapter_names or _cached_adapter_names)().get(guid, "")
                except Exception:  # noqa: BLE001
                    friendly = ""
                if friendly:
                    match, adapter = table.get(friendly), friendly
    if match is None:
        return "", (), own, (
            f"The monitored interface '{name}' could not be matched to an "
            "operating-system adapter, so its network is unknown."
        )

    networks: list[IPv4Net] = []
    for address, netmask in match.netmasks:
        try:
            network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and not network.is_link_local:
            networks.append(network)
    if not networks:
        return adapter, (), own, (
            f"The monitored adapter '{adapter}' has no IPv4 subnet."
        )
    return adapter, tuple(dict.fromkeys(networks)), own, ""


def resolve_scope(
    interface: str,
    configured: Iterable[str],
    *,
    max_addresses: int = DEFAULT_MAX_SCOPE_ADDRESSES,
    interfaces: Callable[[], dict] | None = None,
    adapter_names: Callable[[], dict[str, str]] | None = None,
) -> AssessmentScope:
    """Work out the automatic assessment scope, or why it is unavailable.

    Args:
        interface: the capture device currently (or last) monitored.
        configured: the configured authorised ranges.
        max_addresses: refuse an effective scope larger than this.
        interfaces: OS interface table, injectable for tests.
        adapter_names: GUID -> friendly name, injectable for tests.
    """
    configured_text = tuple(str(c).strip() for c in configured if str(c).strip())
    ranges, rejected = _parse_configured(configured_text)
    if not ranges:
        detail = (
            "No authorised IPv4 range is configured (AETHRA_AUTHORIZED_NETWORKS)."
        )
        if rejected:
            detail += f" Unreadable entries: {', '.join(rejected)}."
        return AssessmentScope(
            available=False, interface=interface, configured=configured_text,
            reason=detail,
        )

    adapter, attached, own, problem = attached_networks(
        interface, interfaces=interfaces, adapter_names=adapter_names
    )
    if problem:
        return AssessmentScope(
            available=False, interface=interface, adapter=adapter,
            attached=attached, configured=configured_text, reason=problem,
            own_addresses=own,
        )

    effective: list[IPv4Net] = []
    for network in attached:
        for allowed in ranges:
            overlap = intersect(network, allowed)
            if overlap is not None:
                effective.append(overlap)
    effective = list(dict.fromkeys(effective))
    if not effective:
        return AssessmentScope(
            available=False, interface=interface, adapter=adapter,
            attached=attached, configured=configured_text, own_addresses=own,
            reason=(
                f"The monitored network ({', '.join(str(n) for n in attached)}) "
                "is not inside any configured authorised range."
            ),
        )

    too_large = [n for n in effective if n.num_addresses > max(4, int(max_addresses))]
    if too_large:
        return AssessmentScope(
            available=False, interface=interface, adapter=adapter,
            attached=attached, configured=configured_text, own_addresses=own,
            reason=(
                f"The monitored network {', '.join(str(n) for n in too_large)} "
                f"is larger than {max_addresses} addresses, which is not a "
                "laboratory segment. Configure a narrower authorised range."
            ),
        )

    return AssessmentScope(
        available=True, interface=interface, adapter=adapter, attached=attached,
        configured=configured_text, networks=tuple(effective), own_addresses=own,
    )
