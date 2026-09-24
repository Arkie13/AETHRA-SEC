"""Choose the Nmap interface that can actually reach a target (§39).

Nmap picks an outgoing interface by its own route metric. That is wrong
whenever two adapters claim the same subnet, which is routine on a workstation
running VirtualBox, VMware or Hyper-V: on this development machine both
``eth5`` (192.168.1.1/24, a VMware adapter) and ``eth8`` (192.168.1.7/24, the
Wi-Fi adapter) claim 192.168.1.0/24.

The consequence is not a warning, it is a wrong answer. Against a live host at
192.168.1.33, measured within seconds of each other:

    nmap -sn -e eth8 192.168.1.33   ->  Host is up (0.063s latency)
    nmap -sn -e eth5 192.168.1.33   ->  Host seems down

A scan that leaves on the virtual adapter reports a live host as down, and
"0 hosts up" is then recorded as though it were a finding about the network.

This module asks the operating system's routing table which source address it
would use to reach the target, then maps that address back to the Nmap device
name so the probe can be pinned with ``-e``. Both halves are read from the
system; nothing is guessed from adapter names or address ordering.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("integrations.nmap.routing")

#: Only a bare IPv4 literal can be routed. A CIDR range or hostname target has
#: no single route, so automatic selection declines rather than guessing.
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True)
class RouteChoice:
    """The interface chosen for a target, and why.

    Attributes:
        device: Nmap device name (``eth8``), empty when none was resolved.
        source_address: local address the OS would send from.
        interface_alias: the operating system's name for that adapter.
        reason: human-readable explanation, shown in scan diagnostics.
        resolved: True when a device was determined from a real route.
    """

    device: str = ""
    source_address: str = ""
    interface_alias: str = ""
    reason: str = ""
    resolved: bool = False


def _is_routable_target(target: str) -> bool:
    """True when the target is a single IPv4 address with a single route."""
    candidate = (target or "").strip()
    if not _IPV4.match(candidate):
        return False
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    return True


def _source_address_via_socket(target: str) -> str:
    """Local address the OS would use to reach ``target``.

    A UDP socket performs no handshake and transmits nothing; connecting one
    only asks the kernel to resolve a route. This works on every platform and
    is the fallback when the Windows-specific query is unavailable.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.settimeout(0.5)
        probe.connect((target, 9))
        return str(probe.getsockname()[0])
    except OSError:
        return ""
    finally:
        probe.close()


def _windows_route(target: str) -> tuple[str, str]:
    """Source address and adapter alias for ``target`` (Windows only).

    ``Find-NetRoute`` answers the same question the network stack answers when
    it sends a packet, including the adapter's friendly name, which the socket
    probe cannot supply.

    Returns:
        ``(source_address, interface_alias)``; empty strings when unavailable.
    """
    if os.name != "nt":
        return ("", "")
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return ("", "")
    command = (
        f"$r = Find-NetRoute -RemoteIPAddress '{target}' -ErrorAction Stop | "
        "Select-Object -First 1; "
        "\"$($r.IPAddress)|$($r.InterfaceAlias)\""
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ("", "")
    if completed.returncode != 0:
        return ("", "")
    address, _, alias = (completed.stdout or "").strip().partition("|")
    return (address.strip(), alias.strip())


def arp_source_address(target: str) -> str:
    """Local interface address that has an ARP entry for ``target``.

    The routing table states a *preference*; an ARP entry is *evidence*. A
    virtual adapter can win the route metric for a subnet it cannot actually
    reach - on this machine the VMware VMnet1 adapter (192.168.1.1) wins the
    route to 192.168.1.0/24 while the host at 192.168.1.33 is only reachable
    over Wi-Fi (192.168.1.7). Windows keeps the ARP cache per interface, so an
    entry for the target names the adapter that genuinely resolved it at layer
    two.

    This selects an interface. It never asserts that a host exists: only Nmap's
    own result decides that.

    Returns:
        The local interface address, or an empty string when the target has no
        ARP entry (it may simply not have been contacted recently).
    """
    if os.name != "nt" or not _is_routable_target(target):
        return ""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["arp", "-a", target],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""

    current = ""
    for raw in (completed.stdout or "").splitlines():
        line = raw.strip()
        if line.lower().startswith("interface:"):
            parts = line.split()
            current = parts[1] if len(parts) > 1 else ""
            continue
        # An entry line is "<address> <mac> <type>"; an incomplete entry has no
        # hardware address and is not evidence of anything.
        parts = line.split()
        if len(parts) >= 2 and parts[0] == target and ":" not in parts[0]:
            mac = parts[1]
            if mac and mac.count("-") >= 5:
                return current
    return ""


def resolve_route(
    target: str,
    interfaces: tuple = (),
    configured_path: Path | None = None,
) -> RouteChoice:
    """Pick the Nmap device that can reach ``target``.

    Args:
        target: the scan target. Only a single IPv4 address can be routed.
        interfaces: Nmap's own interface list. Queried when not supplied.
        configured_path: Nmap executable, used only to enumerate interfaces.

    Returns:
        A :class:`RouteChoice`. When it could not be resolved, ``device`` is
        empty and ``reason`` says why - the caller then lets Nmap choose, which
        is the previous behaviour, rather than pinning a guess.
    """
    if not _is_routable_target(target):
        return RouteChoice(
            reason=(
                f"'{target}' is not a single IPv4 address, so it has no one "
                "route. Nmap chooses the interface for each host it scans."
            ),
        )

    # Evidence first. An ARP entry names the adapter that actually resolved
    # this target at layer two, which beats the routing table's preference -
    # a virtual adapter routinely wins the metric for a subnet it cannot
    # reach, and following it reports live hosts as down.
    evidence = arp_source_address(target)
    source, alias = _windows_route(target)
    if evidence and evidence != source:
        LOGGER.info(
            "Route to %s prefers %s but its ARP entry is on %s; using the "
            "ARP evidence.", target, source or "(none)", evidence,
        )
        source, alias = evidence, ""

    if not source:
        source = _source_address_via_socket(target)
    if not source:
        return RouteChoice(
            reason=(
                f"The operating system reported no route to {target}, so no "
                "interface could be selected for it."
            ),
        )

    if not interfaces:
        from aethra_sec.integrations.nmap.runner import list_nmap_interfaces

        interfaces = list_nmap_interfaces(configured_path)

    # Nmap reports addresses as CIDR (``192.168.1.7/24``); match on the address.
    for entry in interfaces:
        address = str(getattr(entry, "address", "")).split("/", 1)[0].strip()
        if address and address == source:
            device = str(getattr(entry, "device", ""))
            where = f" ({alias})" if alias else ""
            return RouteChoice(
                device=device,
                source_address=source,
                interface_alias=alias,
                reason=(
                    (
                        f"{target} has an ARP entry on {source}{where}, which "
                        f"is Nmap device {device}. That adapter has reached it "
                        "at layer two, so probes are pinned there."
                    )
                    if evidence and evidence == source
                    else (
                        f"The operating system routes {target} through "
                        f"{source}{where}, which is Nmap device {device}."
                    )
                ),
                resolved=True,
            )

    return RouteChoice(
        source_address=source,
        interface_alias=alias,
        reason=(
            f"The operating system routes {target} through {source}, but no "
            "Nmap interface reports that address, so the interface could not "
            "be pinned."
        ),
    )
