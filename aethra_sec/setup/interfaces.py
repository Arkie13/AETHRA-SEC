"""Network interface discovery and the choice of which one to monitor.

Picking the first adapter is the wrong answer on almost any real machine. A
developer workstation typically carries a Wi-Fi adapter, an Ethernet port,
VirtualBox and VMware host-only adapters, a Docker bridge, a WSL adapter and
sometimes a VPN - most of them "up", most with plausible private addresses, and
only one of them carrying the traffic anyone wants to see.

So the recommendation here is made from routing, not from order or from names:

1. ask the OS which source address it would use to leave this machine
   (:func:`aethra_sec.utils.net.primary_outbound_address` - a UDP socket that
   is never connected, so nothing is transmitted);
2. find the adapter that owns that address;
3. prefer it, and rank everything else behind it.

Names are never trusted. "Ethernet 3" is a VirtualBox host-only adapter on the
machine this was written on, and an adapter called "Wi-Fi" can be a disabled
one. What is trusted is the OS's own media type, the OS's own operational
status, and the routing table.

Overlapping routes are reported rather than resolved. When two adapters carry
the same subnet, which of them sees a given conversation depends on the routing
metric and on the switch, and quietly choosing one would be a guess presented as
a fact - so :func:`detect_interfaces` marks the conflict and the operator picks.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("setup.interfaces")

#: Descriptions that mark an adapter as virtual. Used only to *rank* and to
#: label, never to hide: a virtual adapter is a legitimate monitoring target in
#: a lab built out of virtual machines, which is exactly this project's case.
VIRTUAL_MARKERS = (
    "virtualbox", "vmware", "hyper-v", "docker", "wsl", "loopback", "npcap loopback",
    "tap-windows", "zerotier", "tailscale", "openvpn", "wireguard", "bluetooth",
    "teredo", "isatap", "vethernet", "nordlynx", "proton",
)


@dataclass
class DetectedInterface:
    """One network interface, described from what the OS reported.

    Attributes:
        name: capture device name TShark uses (``\\Device\\NPF_{GUID}`` on
            Windows), or the OS interface name elsewhere.
        friendly_name: the label a person recognises ("Wi-Fi").
        description: the adapter's hardware description.
        ipv4: primary IPv4 address, empty when it has none.
        netmask: subnet mask for that address.
        gateway: default gateway on this adapter, when it has one.
        mac: hardware address.
        status: operational status as the OS reports it ("Up"/"Down").
        kind: Wi-Fi / Ethernet / Bluetooth / Other, from the media type.
        is_default_route: whether this adapter carries the default route.
        is_virtual: whether it looks like a virtual or tunnel adapter.
        conflicts: names of other adapters sharing this adapter's subnet.
        score: ranking used to order the list; higher is more likely correct.
    """

    name: str
    friendly_name: str = ""
    description: str = ""
    ipv4: str = ""
    netmask: str = ""
    gateway: str = ""
    mac: str = ""
    status: str = ""
    kind: str = "Other"
    is_default_route: bool = False
    is_virtual: bool = False
    conflicts: list[str] = field(default_factory=list)
    score: int = 0

    @property
    def is_up(self) -> bool:
        """True when the OS reports the adapter as operational."""
        return self.status.strip().lower() in {"up", "connected", "1"}

    @property
    def subnet(self) -> str:
        """The adapter's network in CIDR form, when it can be derived."""
        if not self.ipv4 or not self.netmask:
            return ""
        try:
            network = ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False)
        except ValueError:
            return ""
        return str(network)

    @property
    def display_label(self) -> str:
        """One line describing this adapter for a list."""
        parts = [self.friendly_name or self.description or self.name]
        if self.ipv4:
            parts.append(self.ipv4)
        parts.append(self.kind)
        parts.append(self.status or "unknown")
        if self.is_default_route:
            parts.append("default route")
        # ASCII separator: this label is printed to a Windows console during
        # setup.bat as well as drawn in the wizard, and cp1252 turns a middle
        # dot into a question mark.
        return " | ".join(parts)


@dataclass
class InterfaceReport:
    """Every interface found, the recommendation, and what is ambiguous.

    Attributes:
        interfaces: all interfaces, best candidate first.
        recommended: the interface routing says to use, or ``None``.
        reason: why that one was recommended, in the operator's words.
        warnings: ambiguities that need a human decision.
        tshark_available: whether the list came from TShark. When false the
            list came from the OS and may not name devices the way TShark
            does - which matters, because capture uses TShark's names.
    """

    interfaces: list[DetectedInterface] = field(default_factory=list)
    recommended: DetectedInterface | None = None
    reason: str = ""
    warnings: list[str] = field(default_factory=list)
    tshark_available: bool = False

    @property
    def has_usable_interface(self) -> bool:
        """True when at least one interface could actually be captured on."""
        return any(item.is_up and item.ipv4 for item in self.interfaces)


def _is_virtual(description: str, friendly: str) -> bool:
    """Whether an adapter looks virtual, from its description not its name."""
    haystack = f"{description} {friendly}".lower()
    return any(marker in haystack for marker in VIRTUAL_MARKERS)


_ROUTE_QUERY = (
    "Get-NetIPConfiguration | ForEach-Object { [PSCustomObject]@{ "
    "Guid = $_.NetAdapter.InterfaceGuid; "
    "Alias = $_.InterfaceAlias; "
    "Mac = $_.NetAdapter.MacAddress; "
    "Status = $_.NetAdapter.Status; "
    "IPv4 = ($_.IPv4Address | Select-Object -First 1).IPAddress; "
    "Prefix = ($_.IPv4Address | Select-Object -First 1).PrefixLength; "
    "Gateway = ($_.IPv4DefaultGateway | Select-Object -First 1).NextHop "
    "} } | ConvertTo-Json -Compress"
)


def _windows_ip_configuration() -> dict[str, dict[str, str]]:
    """IPv4 address, prefix, gateway and MAC per adapter GUID (Windows).

    Uses ``Get-NetIPConfiguration`` because it reports the gateway per adapter,
    which is what identifies the default route. Returns an empty mapping on any
    failure - the caller then shows what it has rather than showing nothing.
    """
    if os.name != "nt":
        return {}
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return {}
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [powershell, "-NoProfile", "-NonInteractive", "-Command", _ROUTE_QUERY],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if completed.returncode != 0 or not completed.stdout.strip():
        return {}
    try:
        payload = json.loads(completed.stdout)
    except (ValueError, TypeError):
        return {}
    if isinstance(payload, dict):
        payload = [payload]

    configuration: dict[str, dict[str, str]] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        guid = str(entry.get("Guid") or "").strip().upper()
        if not guid:
            continue
        configuration[guid] = {
            "alias": str(entry.get("Alias") or "").strip(),
            "mac": str(entry.get("Mac") or "").strip().replace("-", ":"),
            "status": str(entry.get("Status") or "").strip(),
            "ipv4": str(entry.get("IPv4") or "").strip(),
            "prefix": str(entry.get("Prefix") or "").strip(),
            "gateway": str(entry.get("Gateway") or "").strip(),
        }
    return configuration


def _prefix_to_netmask(prefix: str) -> str:
    """``24`` -> ``255.255.255.0``; empty when the prefix is unusable."""
    try:
        length = int(prefix)
    except (TypeError, ValueError):
        return ""
    if not 0 <= length <= 32:
        return ""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)


def _guid_of(device_name: str) -> str:
    """Extract the adapter GUID from a TShark Windows device name."""
    start = device_name.find("{")
    end = device_name.find("}", start + 1)
    if start == -1 or end == -1:
        return ""
    return device_name[start : end + 1].upper()


def detect_interfaces(tshark_path: object = None) -> InterfaceReport:
    """Enumerate interfaces and recommend one, using routing to decide.

    Args:
        tshark_path: configured TShark location, or ``None`` to discover it.

    Returns:
        A report listing every interface, the recommended one and any
        ambiguity that a person needs to resolve. Never raises: a machine whose
        adapters cannot be enumerated produces an empty report with a warning,
        which the wizard shows, rather than an exception.
    """
    from aethra_sec.integrations.pyshark_capture.interfaces import list_capture_interfaces
    from aethra_sec.utils.net import primary_outbound_address, windows_adapter_details

    report = InterfaceReport()

    try:
        capture_interfaces = list_capture_interfaces(tshark_path)  # type: ignore[arg-type]
        report.tshark_available = bool(capture_interfaces)
    except Exception as exc:  # noqa: BLE001 - never fail the wizard on this
        LOGGER.warning("TShark interface enumeration failed: %s", exc)
        capture_interfaces = []

    adapters = windows_adapter_details()
    configuration = _windows_ip_configuration()

    if capture_interfaces:
        for item in capture_interfaces:
            guid = _guid_of(getattr(item, "name", "")) or getattr(item, "guid", "")
            guid = (guid or "").upper()
            adapter = adapters.get(guid)
            config = configuration.get(guid, {})
            friendly = (
                getattr(adapter, "friendly_name", "")
                or config.get("alias", "")
                or getattr(item, "description", "")
            )
            description = (
                getattr(adapter, "description", "")
                or getattr(item, "description", "")
            )
            report.interfaces.append(
                DetectedInterface(
                    name=getattr(item, "name", ""),
                    friendly_name=friendly,
                    description=description,
                    ipv4=config.get("ipv4", "") or getattr(item, "primary_ipv4", ""),
                    netmask=_prefix_to_netmask(config.get("prefix", "")),
                    gateway=config.get("gateway", ""),
                    mac=config.get("mac", ""),
                    status=config.get("status", "")
                    or getattr(adapter, "status", "")
                    or getattr(item, "status_text", ""),
                    kind=getattr(adapter, "kind", "Other") if adapter else "Other",
                    is_default_route=bool(config.get("gateway")),
                    is_virtual=_is_virtual(description, friendly),
                )
            )
    else:
        report.warnings.append(
            "TShark did not return an interface list, so these adapters came "
            "from the operating system. Capture uses TShark's own device "
            "names, so verify the selection once TShark is installed."
        )
        report.interfaces.extend(_os_interfaces(configuration, adapters))

    _mark_conflicts(report)
    _rank(report, primary_outbound_address())
    return report


def _os_interfaces(
    configuration: dict[str, dict[str, str]], adapters: dict[str, object]
) -> list[DetectedInterface]:
    """Fall back to the OS's own adapter list when TShark is unavailable."""
    found: list[DetectedInterface] = []
    for guid, config in configuration.items():
        adapter = adapters.get(guid)
        friendly = config.get("alias", "") or getattr(adapter, "friendly_name", "")
        description = getattr(adapter, "description", "") if adapter else ""
        found.append(
            DetectedInterface(
                name=rf"\Device\NPF_{guid}" if os.name == "nt" else friendly,
                friendly_name=friendly,
                description=description,
                ipv4=config.get("ipv4", ""),
                netmask=_prefix_to_netmask(config.get("prefix", "")),
                gateway=config.get("gateway", ""),
                mac=config.get("mac", ""),
                status=config.get("status", ""),
                kind=getattr(adapter, "kind", "Other") if adapter else "Other",
                is_default_route=bool(config.get("gateway")),
                is_virtual=_is_virtual(description, friendly),
            )
        )
    if found:
        return found

    # Last resort: psutil, which is available everywhere the application runs.
    try:
        from aethra_sec.utils.net import list_interfaces

        for item in list_interfaces():
            found.append(
                DetectedInterface(
                    name=getattr(item, "name", ""),
                    friendly_name=getattr(item, "name", ""),
                    ipv4=getattr(item, "primary_ipv4", ""),
                    status=getattr(item, "status_text", ""),
                )
            )
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Could not enumerate interfaces at all: %s", exc)
    return found


def _mark_conflicts(report: InterfaceReport) -> None:
    """Flag adapters that share a subnet with another adapter.

    Two adapters on one subnet is normal on a machine running virtualisation,
    and it genuinely changes which conversations a capture will see. It is
    reported, never silently resolved.
    """
    by_subnet: dict[str, list[DetectedInterface]] = {}
    for item in report.interfaces:
        subnet = item.subnet
        if subnet:
            by_subnet.setdefault(subnet, []).append(item)

    for subnet, members in by_subnet.items():
        if len(members) < 2:
            continue
        labels = [m.friendly_name or m.name for m in members]
        for item in members:
            item.conflicts = [
                label for label in labels if label != (item.friendly_name or item.name)
            ]
        report.warnings.append(
            f"{len(members)} adapters share the subnet {subnet}: "
            f"{', '.join(labels)}. Which one sees a given conversation depends "
            "on the routing metric, so choose the one attached to the segment "
            "you are authorised to monitor."
        )


def _rank(report: InterfaceReport, outbound_address: str) -> None:
    """Score and order the interfaces, and choose the recommendation.

    The score is a ranking aid for the list. The *recommendation* is made on
    routing evidence alone, and ``reason`` states which evidence it was, so an
    operator can disagree with it knowingly.
    """
    for item in report.interfaces:
        score = 0
        if item.ipv4:
            score += 40
        if item.is_up:
            score += 30
        if item.is_default_route:
            score += 25
        if outbound_address and item.ipv4 == outbound_address:
            score += 100
        if item.kind in {"Ethernet", "Wi-Fi"}:
            score += 15
        if item.is_virtual:
            score -= 35
        if item.conflicts:
            score -= 10
        item.score = score

    report.interfaces.sort(key=lambda item: (-item.score, item.friendly_name or item.name))

    if not report.interfaces:
        report.reason = "No network interfaces were detected."
        return

    routed = [
        item for item in report.interfaces
        if outbound_address and item.ipv4 == outbound_address
    ]
    if routed:
        report.recommended = routed[0]
        report.reason = (
            f"The routing table uses {outbound_address} as this machine's "
            f"source address, and that address belongs to "
            f"{routed[0].friendly_name or routed[0].name}."
        )
        if len(routed) > 1:
            report.warnings.append(
                f"{len(routed)} adapters report the address {outbound_address}. "
                "Verify the selection before starting a capture."
            )
        return

    usable = [item for item in report.interfaces if item.is_up and item.ipv4]
    if usable:
        report.recommended = usable[0]
        report.reason = (
            "The routing table did not identify an outbound adapter, so the "
            f"highest-ranked usable interface was chosen: "
            f"{usable[0].friendly_name or usable[0].name}"
            f"{' (default route)' if usable[0].is_default_route else ''}. "
            "Confirm it is on the segment you are authorised to monitor."
        )
        return

    report.reason = (
        "No interface has both an IPv4 address and an operational status, so "
        "none could be recommended. Enable an adapter and re-run detection."
    )
    report.warnings.append(
        "No usable interface was found. Live capture cannot start until one is."
    )


def monitoring_position_note(selected: DetectedInterface | None) -> str:
    """What this interface can and cannot see, stated plainly.

    A switched network does not deliver one host's unicast traffic to another
    host's adapter. An operator who expects to watch an attacker reach a target
    from a third machine has to arrange for that traffic to arrive - by port
    mirroring, a TAP, or by placing AETHRA-SEC in the path. Saying so during
    setup is better than an empty Traffic screen and a hunt for the bug.
    """
    if selected is None:
        return (
            "No interface is selected, so nothing will be captured until one "
            "is chosen on the Network Monitoring screen."
        )
    return (
        f"AETHRA-SEC will capture on {selected.friendly_name or selected.name}. "
        "On a switched network this sees broadcast and multicast traffic, and "
        "unicast traffic to or from this machine. It does not automatically "
        "see unicast traffic between two other hosts: for that the switch port "
        "must be mirrored (SPAN), a network TAP must be installed, or "
        "AETHRA-SEC must sit in the traffic path. Without one of those, "
        "attacker-to-target traffic between two other machines will not appear, "
        "and AETHRA-SEC will correctly show that it saw nothing."
    )
