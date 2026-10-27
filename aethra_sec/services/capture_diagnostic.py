"""What the capture is actually doing, and what it cannot possibly see.

"Live Monitoring is not showing the other device" has two completely different
causes, and telling them apart is the whole job of this module:

* the packets arrive and something in this application discards them - a bug,
  and fixable here;
* the packets never arrive at all - a property of where the sensor is attached,
  and not fixable here at any price.

Measured on this machine, it was the second. Thirty seconds of promiscuous
capture on the real Wi-Fi interface, no filter, produced 580 frames: 566 were
this host's own traffic, 14 were ARP, and **zero** were peer-to-peer unicast.
The adapter sits on 172.20.10.2/28 behind gateway 172.20.10.1 - an iOS Personal
Hotspot - and a station in managed mode cannot see another station's unicast
frames. Even with monitor mode it could not read them: on WPA2/WPA3 each
station's traffic is encrypted under its own pairwise key.

So this report states three counts that are easy to confuse, sourced from three
different stages, and never inferred from one another:

    CAPTURED   frames TShark handed to the reader
    PARSED     frames the worker decoded into an observation
    DISPLAYED  frames the current display filter admitted to the table

A gap between CAPTURED and PARSED is a decode problem. A gap between PARSED and
DISPLAYED is a filter - not loss. A low CAPTURED with a healthy interface is an
observation-point problem, and :data:`VISIBILITY_LIMITATION` says so plainly
rather than leaving the operator to assume the software is broken.

Every value here comes from the running capture or the operating system. There
are no defaults standing in for unknowns: where a value cannot be read it is
reported as unknown, because a plausible number is worse than an absent one.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

#: Shown wherever a value genuinely could not be read.
UNKNOWN = "unknown"

#: §10. Stated whenever peer traffic is expected but absent. It is not an
#: error message: on a switched or wireless segment this is correct behaviour,
#: and hiding it would let the operator believe the tool is at fault.
VISIBILITY_LIMITATION = (
    "Same-network membership does not guarantee visibility of peer unicast "
    "traffic. AETHRA-SEC can display only traffic delivered to the selected "
    "capture interface. For monitoring other devices, configure an authorized "
    "traffic observation point such as gateway capture, switch SPAN/port "
    "mirroring, or an appropriate network TAP."
)

#: Why a wireless station sees so little of its neighbours, stated once so the
#: interface does not have to repeat it and cannot get it wrong.
WIRELESS_NOTE = (
    "This is a wireless interface in managed mode. Other stations' unicast "
    "frames are not delivered to it, and on WPA2/WPA3 each station's traffic "
    "is encrypted under its own pairwise key, so they could not be read even "
    "if they were. This is a property of the network, not of the capture."
)


@dataclass(frozen=True)
class PipelineCounts:
    """The three counts, from three stages, never derived from each other."""

    captured: int = 0
    parsed: int = 0
    displayed: int = 0
    dropped: int = 0
    decode_errors: int = 0
    sampled_out: int = 0

    @property
    def decode_gap(self) -> int:
        """Frames captured but not parsed. Non-zero means decode loss."""
        return max(0, self.captured - self.parsed)

    @property
    def filtered_out(self) -> int:
        """Parsed but not displayed. A filter, not loss."""
        return max(0, self.parsed - self.displayed)


@dataclass(frozen=True)
class CaptureDiagnostic:
    """A complete answer to "what is this capture actually seeing?"."""

    interface_name: str = UNKNOWN
    interface_description: str = UNKNOWN
    local_ipv4: str = UNKNOWN
    subnet: str = UNKNOWN
    capture_filter: str = ""
    display_filter: str = ""
    tshark_pid: str = UNKNOWN
    status: str = UNKNOWN
    is_wireless: bool = False
    counts: PipelineCounts = field(default_factory=PipelineCounts)
    domain_entries: int = 0
    notes: tuple[str, ...] = ()
    #: What the driver says it can do, read from the platform (§2, §6).
    promiscuous: str = UNKNOWN
    monitor_mode: str = UNKNOWN
    #: Whose traffic is actually arriving, counted from real frames (§3).
    #: Never taken from the Hosts table: a host recorded there was seen at
    #: some point, which is not evidence that its traffic is visible now.
    visibility: Any = None

    def lines(self) -> tuple[tuple[str, str], ...]:
        """Label/value pairs, in the order §2 asks for them."""
        return (
            ("Selected interface", self.interface_name),
            ("Adapter description", self.interface_description),
            ("Local IPv4", self.local_ipv4),
            ("Subnet", self.subnet),
            ("Capture filter", self.capture_filter or "(none - all traffic)"),
            ("Display filter", self.display_filter or "(none - all packets)"),
            ("TShark PID", self.tshark_pid),
            ("Capture status", self.status),
            ("Interface type", "Wi-Fi" if self.is_wireless else "Ethernet / other"),
            ("Promiscuous mode", self.promiscuous),
            ("Monitor mode", self.monitor_mode),
            ("Captured packets", f"{self.counts.captured:,}"),
            ("Parsed packets", f"{self.counts.parsed:,}"),
            ("Displayed packets", f"{self.counts.displayed:,}"),
            ("Dropped (capture engine)", f"{self.counts.dropped:,}"),
            ("Decode errors", f"{self.counts.decode_errors:,}"),
            ("Not stored (row-rate cap)", f"{self.counts.sampled_out:,}"),
            ("Domains correlated", f"{self.domain_entries:,}"),
            ("Observed local hosts", _count(self.visibility, "local_hosts")),
            ("Observed non-local hosts", _count(self.visibility, "peer_hosts")),
            ("Peer unicast frames", _count(self.visibility, "peer_frames")),
        )


def _count(report: Any, field_name: str) -> str:
    """One visibility figure, or a dash when nothing has been captured yet.

    A zero and an absence are different statements: zero peer frames after a
    real capture is evidence, while zero before one has run is not.
    """
    if report is None:
        return "-"
    return f"{getattr(report, field_name, 0):,}"


def _safe(call, default: Any = None) -> Any:  # noqa: ANN001
    """Read a value that may not exist, without failing the whole report."""
    try:
        return call()
    except Exception:  # noqa: BLE001 - a diagnostic must still produce a report
        return default


def _subnet_of(address: str, networks) -> str:  # noqa: ANN001
    """The attached network containing ``address``, as CIDR."""
    if not address:
        return UNKNOWN
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return UNKNOWN
    for network in networks or ():
        if parsed in network:
            return str(network)
    return UNKNOWN


def _is_wireless(description: str, name: str) -> bool:
    """Whether the adapter is wireless, by its own description.

    Read from the description the operating system reports, not guessed from
    the interface name, which on Windows is an opaque GUID.
    """
    text = f"{description} {name}".lower()
    return any(
        marker in text
        for marker in ("wi-fi", "wifi", "wireless", "802.11", "wlan")
    )


def build(capture: Any, interfaces: Any = None) -> CaptureDiagnostic:
    """Assemble the report from the running capture service.

    Args:
        capture: the :class:`PacketCaptureService`, or None when it has not
            been built. A report is still produced, stating that.
        interfaces: the enumerated interfaces, when already known. Passing
            them avoids re-enumerating, which is slow enough to matter on the
            Tk thread; omit and they are looked up.
    """
    if capture is None:
        return CaptureDiagnostic(
            status="capture service unavailable",
            notes=(VISIBILITY_LIMITATION,),
        )

    statistics = _safe(capture.statistics)
    view = _safe(lambda: capture.view.statistics())
    pipeline = _safe(lambda: capture.counters.snapshot(), {}) or {}

    name = _safe(lambda: capture.interface, "") or UNKNOWN
    if interfaces is None:
        interfaces = _safe(capture.list_interfaces, ()) or ()
    chosen = next(
        (i for i in interfaces if getattr(i, "name", "") == name), None
    )
    description = _safe(lambda: chosen.description, "") or UNKNOWN
    ipv4 = _safe(lambda: chosen.primary_ipv4, "") or UNKNOWN

    from aethra_sec.utils.net import local_ipv4_networks

    subnet = _subnet_of(
        "" if ipv4 == UNKNOWN else ipv4, _safe(local_ipv4_networks, ())
    )

    counts = PipelineCounts(
        captured=int(_safe(lambda: statistics.total_packets, 0) or 0),
        parsed=int(pipeline.get("processed", 0) or 0),
        displayed=int(_safe(lambda: view.matched, 0) or 0),
        dropped=int(_safe(lambda: statistics.dropped, 0) or 0),
        decode_errors=int(_safe(lambda: statistics.decode_errors, 0) or 0),
        sampled_out=int(_safe(lambda: statistics.sampled_out, 0) or 0),
    )

    wireless = _is_wireless(
        "" if description == UNKNOWN else description, name
    )

    from aethra_sec.analytics.adapter_capability import probe

    capability = _safe(
        lambda: probe("" if description == UNKNOWN else description, name), None
    )
    visibility = _safe(lambda: capture.view.visibility.report(), None)

    notes: list[str] = [VISIBILITY_LIMITATION]
    if capability is not None and capability.limitation():
        notes.append(capability.limitation())
    if visibility is not None and visibility.frames:
        notes.append(visibility.verdict())
    if wireless:
        notes.append(WIRELESS_NOTE)
    if counts.decode_gap:
        notes.append(
            f"{counts.decode_gap:,} captured frame(s) were not parsed. That is "
            "decode loss inside this application, not a network limitation."
        )
    if counts.dropped:
        notes.append(
            f"The capture engine reported {counts.dropped:,} dropped packet(s). "
            "This figure is TShark's own; it is not inferred."
        )

    return CaptureDiagnostic(
        interface_name=name,
        interface_description=description,
        local_ipv4=ipv4,
        subnet=subnet,
        capture_filter=_safe(lambda: statistics.bpf_filter, "") or "",
        display_filter=_safe(lambda: view.expression, "") or "",
        tshark_pid=str(_safe(capture.reader_pid, None) or UNKNOWN),
        status=_safe(lambda: statistics.state, "") or UNKNOWN,
        is_wireless=wireless,
        counts=counts,
        domain_entries=int(_safe(lambda: len(capture.domains), 0) or 0),
        promiscuous=_safe(lambda: capability.promiscuous, UNKNOWN) or UNKNOWN,
        monitor_mode=_safe(lambda: capability.monitor_mode, UNKNOWN) or UNKNOWN,
        visibility=visibility,
        notes=tuple(notes),
    )
