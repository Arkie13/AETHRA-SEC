"""What the capture adapter can actually do, as its driver reports it.

TShark asks for promiscuous mode by default, and AETHRA-SEC does not pass
``-p``, so the request is always made. Whether it is *granted* is a property of
the adapter and its driver, and on Windows the operating system will say so
outright. On this machine it says no:

    netsh wlan show wirelesscapabilities
        Network monitor mode : Not supported
        Promiscuous Mode     : Not Supported

That single line explains an entire class of confusion. An operator who has
enabled everything there is to enable, on a tool that is asking for exactly the
right thing, still sees none of their other devices - and nothing in the
application was telling them why.

So this module reads the answer rather than assuming one, in either direction.
An adapter that does support promiscuous mode is reported as supporting it, and
even then the interface must not promise peer visibility: promiscuous mode only
keeps frames that *reach* the adapter. Making them reach it is mirroring, a TAP
or a gateway capture point - see :mod:`aethra_sec.analytics.peer_visibility`.

Nothing here changes an adapter's state. Monitor mode in particular is only
ever *reported*: enabling it on a Windows station drops the Wi-Fi association,
which would disconnect the operator from the network they are monitoring.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

#: Reported when the platform gives no answer. Never guessed from the adapter
#: name: "Wi-Fi 6" says nothing about whether its driver exposes raw frames.
UNKNOWN = "unknown"

#: How long a probe may take. It shells out to a Windows tool; a hung probe
#: must not hold up the interface that asked for it.
TIMEOUT_SECONDS = 6.0

_MONITOR = re.compile(r"network\s+monitor\s+mode\s*:\s*(.+)", re.IGNORECASE)
_PROMISCUOUS = re.compile(r"promiscuous\s+mode\s*:\s*(.+)", re.IGNORECASE)


@dataclass(frozen=True)
class AdapterCapability:
    """What the driver says it can do, and where the answer came from."""

    interface_type: str = UNKNOWN
    promiscuous: str = UNKNOWN
    monitor_mode: str = UNKNOWN
    source: str = ""
    detail: str = ""

    @property
    def is_wireless(self) -> bool:
        return self.interface_type == "Wi-Fi"

    @property
    def supports_promiscuous(self) -> bool | None:
        """True, False, or None when the platform did not say."""
        return _as_bool(self.promiscuous)

    @property
    def supports_monitor_mode(self) -> bool | None:
        return _as_bool(self.monitor_mode)

    def limitation(self) -> str:
        """The sentence §6 asks for, when it applies. Empty when it does not."""
        if self.is_wireless and self.supports_promiscuous is False:
            return (
                "Current Wi-Fi adapter/driver does not provide the required "
                "peer-device visibility: Windows reports promiscuous mode as "
                "not supported for this adapter, so frames addressed to other "
                "devices are discarded by the driver before any capture tool "
                "can see them."
            )
        if self.is_wireless and self.supports_monitor_mode is False:
            return (
                "This Wi-Fi adapter does not support monitor mode. Even where "
                "peer frames are present in the air, they cannot be captured "
                "by this adapter, and on WPA2/WPA3 each station's traffic is "
                "encrypted under its own pairwise key in any case."
            )
        return ""


def _as_bool(value: str) -> bool | None:
    text = (value or "").strip().lower()
    if text.startswith("not supported"):
        return False
    if text.startswith("supported"):
        return True
    return None


def _run(arguments: list[str]) -> str:
    """Run a read-only platform query, returning text or an empty string."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            arguments,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or ""


def probe(interface_description: str = "", interface_name: str = "") -> AdapterCapability:
    """Ask the platform what this adapter supports.

    Args:
        interface_description: the adapter description, used only to decide
            whether the wireless query is the right one to run.
        interface_name: the capture device name, for the same purpose.

    Read-only. It runs one Windows query and parses its output; it never
    changes an adapter's mode.
    """
    text = f"{interface_description} {interface_name}".lower()
    wireless = any(
        marker in text
        for marker in ("wi-fi", "wifi", "wireless", "802.11", "wlan")
    )
    interface_type = "Wi-Fi" if wireless else ("Ethernet" if text.strip() else UNKNOWN)

    if not wireless:
        return AdapterCapability(
            interface_type=interface_type,
            # A wired adapter is not covered by the wireless query. Reporting
            # "supported" here would be a guess; the honest answer is that we
            # did not ask, and for Ethernet the question is usually moot -
            # what matters is whether the switch mirrors to this port.
            promiscuous=UNKNOWN,
            monitor_mode=UNKNOWN,
            source="not queried (wireless capabilities apply to Wi-Fi only)",
            detail=(
                "On a wired segment, visibility of other devices depends on "
                "the switch: an ordinary switch forwards a unicast frame only "
                "to the port that owns the destination address."
            ),
        )

    output = _run(["netsh", "wlan", "show", "wirelesscapabilities"])
    if not output:
        return AdapterCapability(
            interface_type=interface_type,
            source="netsh wlan show wirelesscapabilities",
            detail="The query produced no output; capability is unknown.",
        )

    monitor = _MONITOR.search(output)
    promiscuous = _PROMISCUOUS.search(output)
    return AdapterCapability(
        interface_type=interface_type,
        promiscuous=(promiscuous.group(1).strip() if promiscuous else UNKNOWN),
        monitor_mode=(monitor.group(1).strip() if monitor else UNKNOWN),
        source="netsh wlan show wirelesscapabilities",
    )
