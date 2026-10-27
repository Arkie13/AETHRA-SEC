"""Which adapter does what: management, or monitoring.

A machine that monitors a network has two jobs that want different adapters.
One carries the application's own traffic - the database, DNS, updates. The
other receives a copy of *somebody else's* traffic from a switch mirror port,
and should carry nothing of ours.

Keeping them apart is a reporting and configuration concern only. This module
reads and resolves the roles; it never alters routing, never changes a default
gateway, never assigns an address, and never touches adapter configuration. A
SPAN destination port is receive-only and normally has no IP at all, so a
monitoring interface with no address is the expected case, not a fault.

Identity is by the adapter's **capture device name** - on Windows the
``\\Device\\NPF_{GUID}`` form. The friendly name ("Ethernet 4") is a
user-editable label that Windows renumbers when adapters come and go, and
pinning a monitoring role to it is how a sensor silently ends up watching the
wrong adapter after a reboot. The same mistake exists in this installation
already: the capture feeding Snort is launched as ``tshark -i 2``, a
positional index, and index 2 no longer resolves to the adapter it did when
that process started.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

SETTING_MONITORING = "capture.monitoring_interface"
SETTING_MANAGEMENT = "capture.management_interface"
SETTING_SPAN_DECLARED = "capture.monitoring_span_declared"


class InterfaceRole(str, Enum):
    """What an adapter is nominated to do."""

    MANAGEMENT = "MANAGEMENT"
    MONITORING = "MONITORING"
    #: Discovered, but not nominated for either role.
    UNASSIGNED = "UNASSIGNED"

    @property
    def label(self) -> str:
        return {
            InterfaceRole.MANAGEMENT: "Management",
            InterfaceRole.MONITORING: "Monitoring / capture",
            InterfaceRole.UNASSIGNED: "Unassigned",
        }[self]


@dataclass(frozen=True)
class InterfaceIdentity:
    """One adapter, as the operating system reports it.

    Every field comes from the OS. A field the OS does not supply stays empty
    and is rendered as a dash rather than guessed at.
    """

    device: str
    display_name: str = ""
    description: str = ""
    mac_address: str = ""
    ipv4_addresses: tuple[str, ...] = ()
    is_up: bool = False
    capture_capable: bool = True
    role: InterfaceRole = InterfaceRole.UNASSIGNED

    @property
    def ipv4_text(self) -> str:
        """Addresses, or ``N/A`` - which is the normal case for a SPAN port."""
        return ", ".join(self.ipv4_addresses) if self.ipv4_addresses else "N/A"

    @property
    def mac_text(self) -> str:
        return self.mac_address or "N/A"

    @property
    def status_text(self) -> str:
        return "UP" if self.is_up else "DOWN"

    @property
    def capture_text(self) -> str:
        return "Available" if self.capture_capable else "Unavailable"

    def summary(self) -> str:
        """One line for a picker, built from stable facts first."""
        parts = [self.display_name or self.device]
        if self.description and self.description != self.display_name:
            parts.append(f"({self.description})")
        parts.append(f"· {self.ipv4_text}")
        if self.mac_address:
            parts.append(f"· {self.mac_address}")
        return " ".join(parts)


@dataclass(frozen=True)
class RoleAssignment:
    """The configured roles, resolved against the adapters present now."""

    monitoring: InterfaceIdentity | None = None
    management: InterfaceIdentity | None = None
    #: Device names configured but not found on this machine right now.
    missing: tuple[str, ...] = ()
    span_declared: bool = False

    @property
    def has_dedicated_monitoring(self) -> bool:
        """True when a monitoring interface is configured AND present."""
        return self.monitoring is not None

    @property
    def roles_are_separate(self) -> bool:
        """True when monitoring and management are different adapters.

        One adapter doing both is a valid configuration and is not an error -
        it is simply an endpoint sensor, which can only ever see its own
        traffic plus broadcast. It is reported so an operator can see which
        case they are in.
        """
        if self.monitoring is None or self.management is None:
            return False
        return self.monitoring.device != self.management.device

    def describe(self) -> str:
        """A sentence for the health screen. States only what is known."""
        if self.missing:
            missing = ", ".join(self.missing)
            return (
                f"A configured interface is not present on this machine: "
                f"{missing}. Capture cannot use it until it is reconnected, "
                "or the role is reassigned."
            )
        if self.monitoring is None:
            return (
                "No dedicated monitoring interface is configured. Capture runs "
                "on the interface selected for it, which on an ordinary "
                "switched port sees this host's own traffic and broadcast "
                "only."
            )
        if self.roles_are_separate:
            return (
                f"Monitoring interface: {self.monitoring.summary()}. "
                f"Management interface: {self.management.summary()}."
            )
        return (
            f"Monitoring interface: {self.monitoring.summary()}. No separate "
            "management interface is configured, so one adapter carries both "
            "roles."
        )


def address_map() -> dict[str, tuple[str, ...]]:
    """MAC address -> IPv4 addresses, read from the operating system.

    The capture-interface list comes from TShark, which reports the stable
    device name but no addresses; the adapter list reports addresses but a
    friendly name that is not stable. Joining them on the MAC gives both,
    without having to trust either name.

    A monitoring interface wired to a SPAN destination normally has no address
    at all, so an empty result for one adapter is expected rather than a fault.
    """
    from aethra_sec.utils.net import list_interfaces

    out: dict[str, tuple[str, ...]] = {}
    for adapter in list_interfaces():
        mac = (getattr(adapter, "mac_address", "") or "").lower()
        if not mac:
            continue
        addresses = tuple(a for a in (adapter.ipv4_addresses or ()) if a)
        if addresses:
            out[mac] = addresses
    return out


def identify(
    interface: Any,
    role: InterfaceRole = InterfaceRole.UNASSIGNED,
    addresses_by_mac: dict[str, tuple[str, ...]] | None = None,
) -> InterfaceIdentity:
    """Build an identity from a capture-service interface record."""
    addresses = tuple(
        str(a) for a in (getattr(interface, "ipv4_addresses", ()) or ()) if a
    )
    if not addresses and addresses_by_mac:
        mac = (getattr(interface, "mac_address", "") or "").lower()
        addresses = addresses_by_mac.get(mac, ())
    return InterfaceIdentity(
        device=str(getattr(interface, "name", "") or ""),
        display_name=str(getattr(interface, "display_name", "") or ""),
        description=str(getattr(interface, "description", "") or ""),
        mac_address=str(getattr(interface, "mac_address", "") or ""),
        ipv4_addresses=addresses,
        is_up=bool(getattr(interface, "is_up", False)),
        capture_capable=bool(getattr(interface, "capture_capable", True)),
        role=role,
    )


def resolve(
    interfaces: Iterable[Any],
    *,
    monitoring_device: str = "",
    management_device: str = "",
    span_declared: bool = False,
) -> RoleAssignment:
    """Match configured device names against the adapters present now.

    A configured device that is absent is reported in ``missing`` rather than
    silently falling back to another adapter. Falling back is how a sensor
    ends up monitoring the wrong segment while still reporting success.
    """
    addresses = address_map()
    by_device: dict[str, Any] = {}
    for interface in interfaces:
        device = str(getattr(interface, "name", "") or "")
        if device:
            by_device[device] = interface

    missing: list[str] = []
    monitoring = management = None

    if monitoring_device:
        found = by_device.get(monitoring_device)
        if found is None:
            missing.append(monitoring_device)
        else:
            monitoring = identify(found, InterfaceRole.MONITORING, addresses)

    if management_device:
        found = by_device.get(management_device)
        if found is None:
            missing.append(management_device)
        else:
            management = identify(found, InterfaceRole.MANAGEMENT, addresses)

    return RoleAssignment(
        monitoring=monitoring,
        management=management,
        missing=tuple(missing),
        span_declared=bool(span_declared),
    )


def inventory(
    interfaces: Iterable[Any],
    *,
    monitoring_device: str = "",
    management_device: str = "",
) -> list[InterfaceIdentity]:
    """Every adapter present, each tagged with the role it is nominated for."""
    addresses = address_map()
    out: list[InterfaceIdentity] = []
    for interface in interfaces:
        device = str(getattr(interface, "name", "") or "")
        if device and device == monitoring_device:
            role = InterfaceRole.MONITORING
        elif device and device == management_device:
            role = InterfaceRole.MANAGEMENT
        else:
            role = InterfaceRole.UNASSIGNED
        out.append(identify(interface, role, addresses))
    return out
