"""Network helpers: authorisation boundary, interfaces, executable discovery."""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from aethra_sec.config.settings import AuthorizationSettings

# Well-known service names used to describe observed ports when Nmap has not
# supplied a service name. This is a static lookup table, not security data.
COMMON_PORT_SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 3268: "globalcatldap",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    5985: "wsman", 5986: "wsmans", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


@dataclass(frozen=True)
class NetworkInterface:
    """A network interface discovered on this machine.

    Every field is read from the operating system; nothing is invented. When a
    value is unavailable it stays empty and the UI shows a dash.
    """

    name: str
    description: str = ""
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()
    mac_address: str = ""
    is_up: bool = False
    speed_mbps: int = 0

    @property
    def primary_ipv4(self) -> str:
        """First IPv4 address, or an empty string when the interface has none."""
        return self.ipv4_addresses[0] if self.ipv4_addresses else ""

    @property
    def status_text(self) -> str:
        """``UP`` / ``DOWN`` as reported by the operating system."""
        return "UP" if self.is_up else "DOWN"

    def display_label(self) -> str:
        """Label used in interface pickers."""
        parts = [self.name]
        if self.description and self.description != self.name:
            parts.append(f"({self.description})")
        if self.primary_ipv4:
            parts.append(f"- {self.primary_ipv4}")
        return " ".join(parts)


def list_interfaces() -> list[NetworkInterface]:
    """Enumerate the machine's network interfaces via psutil.

    Returns:
        A list of interfaces sorted with operational, addressed interfaces
        first. An empty list means psutil is unavailable or reported nothing;
        callers surface that condition instead of substituting placeholders.
    """
    try:
        import psutil
    except ImportError:
        return []

    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return []

    interfaces: list[NetworkInterface] = []
    for name, addr_list in addresses.items():
        ipv4: list[str] = []
        ipv6: list[str] = []
        mac = ""
        for addr in addr_list:
            family = getattr(addr, "family", None)
            if family == socket.AF_INET and addr.address:
                ipv4.append(addr.address)
            elif family == socket.AF_INET6 and addr.address:
                ipv6.append(addr.address.split("%", 1)[0])
            elif getattr(psutil, "AF_LINK", None) is not None and family == psutil.AF_LINK:
                mac = (addr.address or "").replace("-", ":").lower()

        stat = stats.get(name)
        interfaces.append(
            NetworkInterface(
                name=name,
                description=name,
                ipv4_addresses=tuple(ipv4),
                ipv6_addresses=tuple(ipv6),
                mac_address=mac,
                is_up=bool(stat.isup) if stat else False,
                speed_mbps=int(stat.speed) if stat and stat.speed else 0,
            )
        )

    interfaces.sort(key=lambda i: (not i.is_up, not i.ipv4_addresses, i.name.lower()))
    return interfaces


def tshark_interfaces(tshark_path: Path | None = None) -> list[tuple[str, str]]:
    """List capture interfaces exactly as TShark reports them.

    On Windows the capture interface name that PyShark needs is the NPF device
    identifier, which differs from the friendly adapter name psutil reports, so
    this is the authoritative list for capture.

    Returns:
        ``(name, description)`` pairs. Empty when TShark is unavailable.
    """
    executable = str(tshark_path) if tshark_path else shutil.which("tshark")
    if not executable or not Path(executable).exists():
        return []
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [executable, "-D"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []

    found: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line or "." not in line:
            continue
        _, _, remainder = line.partition(".")
        remainder = remainder.strip()
        if not remainder:
            continue
        if "(" in remainder and remainder.endswith(")"):
            name, _, description = remainder.partition("(")
            found.append((name.strip(), description[:-1].strip()))
        else:
            found.append((remainder, ""))
    return found


def is_authorized_target(address: str, settings: AuthorizationSettings) -> bool:
    """True when ``address`` falls inside a configured authorised network.

    This is the enforcement point for the assessment authorisation boundary. A
    target that is not an IP address (a hostname) cannot be checked here and is
    handled by the caller, which resolves it first.
    """
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    if settings.allow_public:
        return True
    return any(ip in network for network in settings.parsed_networks)


def unauthorized_addresses(
    addresses: tuple[str, ...], settings: AuthorizationSettings
) -> tuple[str, ...]:
    """Return the subset of ``addresses`` outside the authorisation boundary."""
    return tuple(
        addr for addr in addresses if not is_authorized_target(addr, settings)
    )


def resolve_hostname(address: str, *, timeout: float = 1.0) -> str:
    """Reverse-resolve an IP address.

    Returns an empty string when resolution fails. A failed lookup is never
    replaced by an invented name; callers display the IP address instead.
    """
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(address)
        return hostname
    except (OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(previous)


def local_ipv4_networks() -> tuple[ipaddress.IPv4Network, ...]:
    """Subnets this machine is directly attached to, right now.

    An address inside one of these is *on-link*: it shares a broadcast domain
    with the sensor, so a frame from it carries that host's own MAC. An address
    outside them was reached through a router, and the source MAC on its frames
    is the router's - attaching it to the remote address would invent a
    hardware identity for a machine the sensor has never touched.

    Read from the live interfaces rather than configured once, so it is still
    correct after the machine moves to a different network.
    """
    networks: list[ipaddress.IPv4Network] = []
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a declared dependency
        return ()
    try:
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family != socket.AF_INET or not entry.netmask:
                    continue
                try:
                    network = ipaddress.ip_network(
                        f"{entry.address}/{entry.netmask}", strict=False
                    )
                except ValueError:
                    continue
                if isinstance(network, ipaddress.IPv4Network) and not (
                    network.is_loopback
                ):
                    networks.append(network)
    except Exception:  # noqa: BLE001 - never break capture over this
        return ()
    return tuple(dict.fromkeys(networks))


def is_on_link(address: str, networks: Sequence[ipaddress.IPv4Network]) -> bool:
    """True when ``address`` sits in one of the sensor's own subnets."""
    if not address or not networks:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def host_address_rejection(
    address: str, networks: Sequence[ipaddress.IPv4Network] = ()
) -> str:
    """Why ``address`` cannot be a discovered host, or ``""`` if it can.

    An inventory row asserts that a device exists at an address. Several kinds
    of address can never satisfy that, however genuinely they appear on the
    wire, because no single device owns them:

    * the unspecified address, which a DHCP client uses before it has one;
    * multicast and broadcast, which name a *group*, not a machine - this
      installation accumulated 45 IPv6 multicast groups and 12 IPv4
      broadcast/multicast addresses as "hosts";
    * loopback, which is the sensor talking to itself;
    * link-local, which is unroutable autoconfiguration - 117 ``fe80::``
      addresses were stored as separate hosts here;
    * a subnet's own network or broadcast address.

    A valid private address is never rejected for lacking a hostname: a real
    device with no DNS record is still a real device.

    Args:
        networks: the sensor's subnets, used to recognise a network or
            broadcast address. Omitted, only the address-intrinsic rules apply.

    Returns:
        A short reason suitable for an audit note, or ``""`` when the address
        is acceptable.
    """
    text = (address or "").strip()
    if not text:
        return "empty address"
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return "not a valid IP address"
    if parsed.is_unspecified:
        return "the unspecified address"
    if parsed.is_loopback:
        return "a loopback address"
    if parsed.is_multicast:
        return "a multicast group, not a host"
    if parsed.is_link_local:
        return "a link-local address"
    # Before is_reserved, which also covers it but says less: these reasons
    # are written into the audit trail, so the specific one is worth keeping.
    if str(parsed) == "255.255.255.255":
        return "the broadcast address"
    if parsed.is_reserved:
        return "a reserved address"
    if isinstance(parsed, ipaddress.IPv4Address):
        for network in networks:
            if parsed not in network or network.prefixlen >= 31:
                continue
            if parsed == network.broadcast_address:
                return "the subnet broadcast address"
            if parsed == network.network_address:
                return "the subnet network address"
    return ""


def local_addresses() -> set[str]:
    """IP addresses belonging to this machine (used to label local traffic)."""
    addresses: set[str] = set()
    for interface in list_interfaces():
        addresses.update(interface.ipv4_addresses)
        addresses.update(interface.ipv6_addresses)
    return addresses


def find_executable(
    configured: Path | None, *candidates: str, extra_dirs: tuple[Path, ...] = ()
) -> Path | None:
    """Locate a tool executable.

    Search order: the configured path, then ``PATH``, then well-known install
    directories (which is what makes zero-configuration startup work on a
    standard Windows install of Nmap/Wireshark/Snort).

    Returns:
        The resolved path, or ``None`` when the tool cannot be found. Callers
        must report absence rather than substituting alternative behaviour.
    """
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
        if candidate.is_dir():
            for name in candidates:
                nested = candidate / name
                if nested.is_file():
                    return nested.resolve()

    for name in candidates:
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

    for directory in extra_dirs:
        for name in candidates:
            candidate = Path(directory) / name
            if candidate.is_file():
                return candidate.resolve()
    return None


def service_name_for_port(port: int, protocol: str = "tcp") -> str:
    """Best-effort service name for a port from static, well-known mappings."""
    if port in COMMON_PORT_SERVICES:
        return COMMON_PORT_SERVICES[port]
    try:
        return socket.getservbyport(port, protocol.lower())
    except (OSError, TypeError, ValueError):
        return ""


@dataclass(frozen=True)
class AdapterDetail:
    """Physical characteristics of one adapter, as the OS reports them.

    Windows exposes the media type an adapter actually uses, which is the only
    trustworthy way to tell Wi-Fi from Ethernet - adapter names like "Ethernet
    3" are user-editable labels and are routinely wrong (that one is a
    VirtualBox host-only adapter on this machine). Nothing here is guessed from
    a name.
    """

    guid: str
    friendly_name: str = ""
    description: str = ""
    media_type: str = ""
    physical_media: str = ""
    status: str = ""
    link_speed: str = ""

    @property
    def kind(self) -> str:
        """Wi-Fi / Ethernet / Bluetooth / Other, from the reported media type.

        ``MediaType`` is the OS's own classification: "Native 802.11" is
        wireless and "802.3" is wired. ``PhysicalMediaType`` refines it, since
        a Bluetooth PAN also presents itself as 802.3.
        """
        physical = self.physical_media.strip().lower()
        media = self.media_type.strip().lower()
        if "802.11" in media or "802.11" in physical:
            return "Wi-Fi"
        if "bluetooth" in physical:
            return "Bluetooth"
        if "802.3" in media:
            return "Ethernet"
        return "Other"


#: PowerShell projection used to read adapter details. CIM, so no elevation.
_ADAPTER_QUERY = (
    "Get-NetAdapter | Select-Object "
    "InterfaceGuid,Name,InterfaceDescription,MediaType,PhysicalMediaType,"
    "Status,LinkSpeed | ConvertTo-Json -Compress"
)


def windows_adapter_details() -> dict[str, AdapterDetail]:
    r"""Adapter details keyed by upper-case interface GUID (Windows only).

    The GUID is what makes this reliable: TShark names a Windows capture device
    ``\Device\NPF_{GUID}``, and ``Get-NetAdapter`` reports the same GUID, so
    the two lists join exactly rather than by matching display names.

    Returns:
        GUID -> detail. Empty on non-Windows, or when the query fails for any
        reason - callers then simply show what TShark gave them.
    """
    if os.name != "nt":
        return {}
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return {}
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [powershell, "-NoProfile", "-NonInteractive", "-Command", _ADAPTER_QUERY],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if completed.returncode != 0 or not completed.stdout.strip():
        return {}

    import json

    try:
        payload = json.loads(completed.stdout)
    except (ValueError, TypeError):
        return {}
    if isinstance(payload, dict):  # a single adapter is not wrapped in a list
        payload = [payload]

    details: dict[str, AdapterDetail] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        guid = str(entry.get("InterfaceGuid") or "").strip().upper()
        if not guid:
            continue
        details[guid] = AdapterDetail(
            guid=guid,
            friendly_name=str(entry.get("Name") or "").strip(),
            description=str(entry.get("InterfaceDescription") or "").strip(),
            media_type=str(entry.get("MediaType") or "").strip(),
            physical_media=str(entry.get("PhysicalMediaType") or "").strip(),
            status=str(entry.get("Status") or "").strip(),
            link_speed=str(entry.get("LinkSpeed") or "").strip(),
        )
    return details


def primary_outbound_address() -> str:
    """The local IPv4 address this machine would use to reach the internet.

    Asking the routing table which source address it would choose is the only
    reliable way to tell which of several "up" adapters actually carries
    traffic - on a machine with VirtualBox, VMware and ZeroTier installed, most
    of them look equally plausible from their addresses alone.

    The socket is never connected and nothing is transmitted: a UDP socket has
    no handshake, so this only asks the OS to resolve a route.

    Returns:
        The chosen source address, or an empty string when there is no route.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.settimeout(0.5)
        # A routable address that is never contacted; it only selects a route.
        probe.connect(("192.0.2.1", 9))
        return str(probe.getsockname()[0])
    except OSError:
        return ""
    finally:
        probe.close()
