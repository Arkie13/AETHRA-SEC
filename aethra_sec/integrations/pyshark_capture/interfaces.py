"""Capture interface discovery and TShark availability (§38).

On Windows the name PyShark needs is the NPF device identifier that TShark
reports (``\\Device\\NPF_{GUID}``), which is not the friendly adapter name the
operating system shows. This module therefore prefers TShark's own list and
enriches it with addresses from psutil where the names can be matched.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import NetworkInterface, list_interfaces, tshark_interfaces

LOGGER = get_logger("integrations.pyshark.interfaces")

#: Standard Wireshark installation directories checked when tshark is not on PATH.
WINDOWS_WIRESHARK_DIRS: tuple[Path, ...] = (
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
)

TSHARK_MISSING_MESSAGE = (
    "TShark (part of Wireshark) is not available, so live packet capture "
    "cannot start. Install Wireshark from https://www.wireshark.org/download "
    "(include Npcap on Windows) and, if it is installed somewhere unusual, set "
    "AETHRA_TSHARK_PATH in .env to the full path of tshark.exe."
)


@dataclass(frozen=True)
class CaptureInterface:
    """An interface that can actually be used for capture.

    Attributes:
        name: the identifier passed to TShark/PyShark.
        description: friendly description, when one is known.
        ipv4/ipv6: addresses observed on the interface (may be empty).
        mac_address: hardware address, when known.
        is_up: operational state as reported by the OS.
        source: ``tshark`` or ``psutil`` - which enumeration produced it.
    """

    name: str
    description: str = ""
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    mac_address: str = ""
    is_up: bool = False
    source: str = "tshark"

    @property
    def primary_ipv4(self) -> str:
        """First IPv4 address, or an empty string."""
        return self.ipv4[0] if self.ipv4 else ""

    @property
    def status_text(self) -> str:
        """``UP`` / ``DOWN`` / ``UNKNOWN`` - never assumed."""
        if self.source == "tshark" and not self.ipv4 and not self.mac_address:
            return "UP" if self.is_up else "UNKNOWN"
        return "UP" if self.is_up else "DOWN"

    def display_label(self) -> str:
        """Label used in the interface picker."""
        parts = [self.description or self.name]
        if self.primary_ipv4:
            parts.append(f"[{self.primary_ipv4}]")
        if self.description and self.description != self.name:
            parts.append(f"({self.name})")
        return " ".join(parts)


@dataclass(frozen=True)
class TsharkAvailability:
    """Result of probing for a usable TShark installation."""

    available: bool
    executable: str = ""
    version: str = ""
    detail: str = ""
    pyshark_available: bool = False

    @property
    def status_text(self) -> str:
        """Status shown on the diagnostics screen."""
        return "AVAILABLE" if self.available else "NOT AVAILABLE"


def find_tshark(configured_path: Path | None = None) -> Path | None:
    """Locate the ``tshark`` executable."""
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        if candidate.is_dir():
            for name in ("tshark.exe", "tshark"):
                nested = candidate / name
                if nested.is_file():
                    return nested.resolve()

    for name in ("tshark", "tshark.exe"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

    for directory in WINDOWS_WIRESHARK_DIRS:
        candidate = directory / "tshark.exe"
        if candidate.is_file():
            return candidate.resolve()
    return None


def probe_tshark(configured_path: Path | None = None) -> TsharkAvailability:
    """Check whether TShark and PyShark are both usable."""
    try:
        import pyshark  # noqa: F401

        pyshark_ok = True
        pyshark_error = ""
    except Exception as exc:  # noqa: BLE001
        pyshark_ok = False
        pyshark_error = str(exc)

    executable = find_tshark(configured_path)
    if executable is None:
        return TsharkAvailability(
            available=False,
            detail=TSHARK_MISSING_MESSAGE,
            pyshark_available=pyshark_ok,
        )

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            [str(executable), "-v"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return TsharkAvailability(
            available=False,
            executable=str(executable),
            detail=f"TShark was found at {executable} but could not run: {exc}",
            pyshark_available=pyshark_ok,
        )

    version_lines = (completed.stdout or completed.stderr or "").strip().splitlines()
    version = version_lines[0].strip() if version_lines else "unknown version"

    if not pyshark_ok:
        return TsharkAvailability(
            available=False,
            executable=str(executable),
            version=version,
            detail=(
                f"TShark is installed ({version}) but the PyShark library is "
                f"not usable: {pyshark_error}. Run: pip install pyshark"
            ),
            pyshark_available=False,
        )

    return TsharkAvailability(
        available=True,
        executable=str(executable),
        version=version,
        detail=f"{version} at {executable}",
        pyshark_available=True,
    )


def list_capture_interfaces(
    tshark_path: Path | None = None,
) -> list[CaptureInterface]:
    """Enumerate interfaces available for capture.

    TShark's list is authoritative because its names are the ones PyShark
    accepts. Addresses from psutil are merged in when the names correspond.
    When TShark is unavailable the psutil list is returned so the operator can
    still see their adapters, clearly marked as coming from the OS.

    Returns:
        Capture interfaces, or an empty list when nothing could be enumerated -
        the caller then reports that rather than inventing an entry.
    """
    os_interfaces: dict[str, NetworkInterface] = {
        iface.name: iface for iface in list_interfaces()
    }

    tshark_list = tshark_interfaces(tshark_path)
    if tshark_list:
        result: list[CaptureInterface] = []
        for name, description in tshark_list:
            match = os_interfaces.get(name)
            if match is None and description:
                match = os_interfaces.get(description)
            result.append(
                CaptureInterface(
                    name=name,
                    description=description or (match.description if match else ""),
                    ipv4=match.ipv4_addresses if match else (),
                    ipv6=match.ipv6_addresses if match else (),
                    mac_address=match.mac_address if match else "",
                    is_up=match.is_up if match else True,
                    source="tshark",
                )
            )
        result.sort(key=lambda i: (not i.ipv4, i.name.lower()))
        return result

    LOGGER.warning(
        "TShark did not report any capture interfaces; falling back to the "
        "operating system list. Capture may not work with these names."
    )
    return [
        CaptureInterface(
            name=iface.name,
            description=iface.description,
            ipv4=iface.ipv4_addresses,
            ipv6=iface.ipv6_addresses,
            mac_address=iface.mac_address,
            is_up=iface.is_up,
            source="psutil",
        )
        for iface in os_interfaces.values()
    ]


def capture_permission_notes() -> list[str]:
    """Platform-specific notes about capture privileges (§38)."""
    notes: list[str] = []
    if os.name == "nt":  # pragma: no cover - platform specific
        notes.append(
            "Windows capture requires the Npcap driver (installed with "
            "Wireshark). Select 'Support raw 802.11 traffic' only if you need "
            "wireless monitor mode."
        )
        notes.append(
            "If interfaces are listed but capture fails, run AETHRA-SEC as "
            "Administrator, or add your account to the 'Npcap Packet Capture "
            "Users' group during Npcap installation."
        )
    else:
        notes.append(
            "Linux capture requires root, or CAP_NET_RAW and CAP_NET_ADMIN on "
            "the dumpcap binary: "
            "sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)"
        )
    notes.append(
        "To monitor traffic between other hosts, connect the monitoring "
        "interface to a switch mirror/SPAN port; a normal switch port only "
        "shows this machine's own traffic and broadcasts."
    )
    return notes
