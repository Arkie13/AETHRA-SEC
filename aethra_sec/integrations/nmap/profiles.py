"""Nmap scan profiles - the only source of Nmap command-line arguments (§97).

Operator input never becomes an Nmap argument. The operator picks a profile
from this fixed catalogue, optionally supplies a port specification that must
match a strict numeric grammar, and picks a timing template from a fixed list.
Everything else is a constant defined here.

There is no profile that exploits anything. Nmap is used for host discovery,
port state, service/version detection and OS detection only (§16, §89).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from aethra_sec.utils.validation import (
    ValidationError,
    validate_choice,
    validate_port_range,
)

#: Timing templates the operator may choose (Nmap ``-T0`` .. ``-T5``).
TIMING_TEMPLATES: tuple[str, ...] = ("T0", "T1", "T2", "T3", "T4", "T5")
DEFAULT_TIMING = "T3"

TIMING_DESCRIPTIONS: dict[str, str] = {
    "T0": "Paranoid - extremely slow, for IDS evasion testing. Rarely useful here.",
    "T1": "Sneaky - very slow and quiet.",
    "T2": "Polite - slows down to consume less bandwidth.",
    "T3": "Normal - the default balance of speed and reliability.",
    "T4": "Aggressive - faster; suitable for a healthy local LAN.",
    "T5": "Insane - fastest; may miss results on a congested network.",
}


@dataclass(frozen=True)
class ScanProfile:
    """A named, fixed set of Nmap arguments.

    Attributes:
        key: stable identifier stored with the scan record.
        label: text shown in the profile picker.
        description: what the profile does, in plain language.
        arguments: literal argument fragments. Never contains operator input.
        requires_ports: whether a port specification applies.
        default_ports: port specification used when the operator supplies none.
        requires_privilege: whether the profile needs raw-socket privileges
            (Administrator on Windows, root/CAP_NET_RAW on Linux).
        detects_os: whether the profile attempts OS detection.
        detects_versions: whether the profile attempts service version
            detection.
    """

    key: str
    label: str
    description: str
    arguments: tuple[str, ...]
    requires_ports: bool = True
    default_ports: str = ""
    requires_privilege: bool = False
    detects_os: bool = False
    detects_versions: bool = False
    estimated_duration: str = ""


PROFILES: tuple[ScanProfile, ...] = (
    ScanProfile(
        key="discovery",
        label="Host discovery (ping sweep)",
        description=(
            "Finds which addresses are live without scanning any ports. The "
            "fastest way to build a host inventory for a subnet."
        ),
        arguments=("-sn",),
        requires_ports=False,
        estimated_duration="seconds for a /24",
    ),
    ScanProfile(
        key="quick",
        label="Quick port scan (top 100 ports)",
        description=(
            "TCP connect scan of the 100 most common ports. Reports which "
            "ports are open; it does not identify service versions."
        ),
        arguments=("-sT", "--top-ports", "100"),
        requires_ports=False,
        estimated_duration="under a minute per host",
    ),
    ScanProfile(
        key="standard",
        label="Standard scan (top 1000 ports + versions)",
        description=(
            "TCP connect scan of the 1000 most common ports with service and "
            "version detection. The usual choice for a laboratory assessment."
        ),
        arguments=("-sT", "-sV", "--top-ports", "1000"),
        requires_ports=False,
        detects_versions=True,
        estimated_duration="1-3 minutes per host",
    ),
    ScanProfile(
        key="custom_ports",
        label="Custom port range + versions",
        description=(
            "TCP connect scan with service and version detection over a port "
            "range you specify."
        ),
        arguments=("-sT", "-sV"),
        requires_ports=True,
        default_ports="1-1024",
        detects_versions=True,
        estimated_duration="depends on the range",
    ),
    ScanProfile(
        key="full_tcp",
        label="Full TCP scan (all 65535 ports)",
        description=(
            "TCP connect scan of every port with version detection. Thorough "
            "but slow - use it on a single host, not a whole subnet."
        ),
        arguments=("-sT", "-sV", "-p-"),
        requires_ports=False,
        detects_versions=True,
        estimated_duration="10+ minutes per host",
    ),
    ScanProfile(
        key="os_detect",
        label="OS detection + service versions",
        description=(
            "Adds operating system fingerprinting to a standard scan. Needs "
            "raw-socket privileges: run AETHRA-SEC as Administrator on "
            "Windows, or as root on Linux."
        ),
        arguments=("-sS", "-sV", "-O", "--top-ports", "1000"),
        requires_ports=False,
        requires_privilege=True,
        detects_os=True,
        detects_versions=True,
        estimated_duration="2-5 minutes per host",
    ),
    ScanProfile(
        key="udp_common",
        label="Common UDP services",
        description=(
            "Scans frequently abused UDP services (DNS, DHCP, TFTP, NTP, SNMP "
            "and similar). UDP scanning is slow by nature and needs raw-socket "
            "privileges."
        ),
        arguments=("-sU", "--top-ports", "50"),
        requires_ports=False,
        requires_privilege=True,
        estimated_duration="several minutes per host",
    ),
)

PROFILE_BY_KEY: dict[str, ScanProfile] = {p.key: p for p in PROFILES}
DEFAULT_PROFILE = "standard"

#: The Nmap NSE script categories an administrator may optionally enable.
#: Only assessment scripts are permitted; intrusive, brute-force, exploit and
#: denial-of-service categories are absent by design (§89).
ALLOWED_SCRIPT_CATEGORIES: tuple[str, ...] = ("default", "safe", "banner", "vuln")

#: Categories that are explicitly refused even if configured by mistake.
FORBIDDEN_SCRIPT_CATEGORIES: frozenset[str] = frozenset(
    {"exploit", "brute", "dos", "intrusive", "malware", "auth"}
)

#: Per-host time limit, so one unreachable address cannot stall a subnet scan.
HOST_TIMEOUT = "900s"


@dataclass(frozen=True)
class ScanRequest:
    """A fully validated assessment request ready to be executed."""

    target: str
    profile: ScanProfile
    port_spec: str
    timing: str
    arguments: tuple[str, ...]
    script_categories: tuple[str, ...] = field(default_factory=tuple)

    @property
    def argument_string(self) -> str:
        """Arguments as the single string ``python-nmap`` expects.

        Every fragment originates from this module or from a value that passed
        the strict numeric grammar, so the result cannot carry injected text.
        """
        return " ".join(self.arguments)


def has_raw_socket_privilege() -> bool:
    """Best-effort check for raw-socket capability.

    On Windows, Nmap's SYN/OS/UDP scans need an elevated process plus Npcap.
    On POSIX, they need root or ``CAP_NET_RAW``. A false result only downgrades
    the offered profiles - it never silently substitutes a different scan.
    """
    if os.name == "nt":  # pragma: no cover - platform specific
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover
        return False


def available_profiles(*, privileged: bool | None = None) -> tuple[ScanProfile, ...]:
    """Profiles that can actually run on this machine.

    Args:
        privileged: override the privilege probe (used in tests).

    Returns:
        Every profile, with privileged ones excluded when the process cannot
        run them. The UI explains the exclusion rather than hiding it silently.
    """
    can_raw = has_raw_socket_privilege() if privileged is None else privileged
    if can_raw:
        return PROFILES
    return tuple(p for p in PROFILES if not p.requires_privilege)


def build_scan_request(
    target: str,
    profile_key: str = DEFAULT_PROFILE,
    port_spec: str = "",
    timing: str = DEFAULT_TIMING,
    script_categories: tuple[str, ...] = (),
) -> ScanRequest:
    """Validate operator choices and assemble the Nmap argument list.

    Args:
        target: already-validated target text (validated again by the service
            layer against the authorisation boundary).
        profile_key: one of :data:`PROFILE_BY_KEY`.
        port_spec: port specification; required for profiles that need one.
        timing: one of :data:`TIMING_TEMPLATES`.
        script_categories: optional NSE categories, filtered against
            :data:`ALLOWED_SCRIPT_CATEGORIES`.

    Returns:
        A :class:`ScanRequest`.

    Raises:
        ValidationError: on an unknown profile, a malformed port range, an
            unknown timing template, or a forbidden script category.
    """
    profile = PROFILE_BY_KEY.get((profile_key or "").strip().lower())
    if profile is None:
        raise ValidationError(
            f"Unknown scan profile '{profile_key}'. Choose one of: "
            + ", ".join(PROFILE_BY_KEY)
        )

    safe_timing = validate_choice(timing or DEFAULT_TIMING, TIMING_TEMPLATES, "Timing")

    arguments: list[str] = list(profile.arguments)
    arguments.append(f"-{safe_timing}")

    effective_ports = ""
    if profile.requires_ports:
        effective_ports = validate_port_range(port_spec or profile.default_ports)
        arguments.extend(["-p", effective_ports])
    elif port_spec:
        # A port specification supplied for a profile that fixes its own ports
        # is honoured rather than ignored, because silently dropping operator
        # input would make the recorded arguments a lie.
        effective_ports = validate_port_range(port_spec)
        arguments = [a for a in arguments if a not in ("-p-",)]
        if "--top-ports" in arguments:
            index = arguments.index("--top-ports")
            del arguments[index : index + 2]
        arguments.extend(["-p", effective_ports])

    cleaned_scripts: list[str] = []
    for category in script_categories:
        normalised = (category or "").strip().lower()
        if not normalised:
            continue
        if normalised in FORBIDDEN_SCRIPT_CATEGORIES:
            raise ValidationError(
                f"NSE category '{normalised}' is not permitted: AETHRA-SEC "
                "performs assessment only and never runs intrusive, "
                "brute-force or exploit scripts."
            )
        if normalised not in ALLOWED_SCRIPT_CATEGORIES:
            raise ValidationError(
                f"NSE category '{normalised}' is not in the permitted list "
                f"({', '.join(ALLOWED_SCRIPT_CATEGORIES)})."
            )
        cleaned_scripts.append(normalised)

    if cleaned_scripts:
        arguments.extend(["--script", ",".join(sorted(set(cleaned_scripts)))])

    # Bound each host so one unreachable address cannot stall the whole scan.
    # DNS resolution is left enabled so hostnames come from Nmap rather than
    # being guessed later.
    arguments.extend(["--host-timeout", HOST_TIMEOUT])

    return ScanRequest(
        target=target,
        profile=profile,
        port_spec=effective_ports,
        timing=safe_timing,
        arguments=tuple(arguments),
        script_categories=tuple(sorted(set(cleaned_scripts))),
    )
