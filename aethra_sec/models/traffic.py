"""Packet and traffic models produced by the PyShark capture pipeline.

Every field is optional except the capture timestamp and the interface: real
packets frequently lack layers (an ARP frame has no ports, an ICMP packet has no
TCP flags), and the mapper must never fabricate a value to fill a column.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.utils.formatting import tcp_flag_names


@dataclass(slots=True)
class CapturedPacket:
    """Metadata extracted from one real captured packet.

    Attributes:
        captured_at: the packet's own sniff timestamp (never ``now()``).
        raw_summary: TShark's own description of the packet, when available.
        detail_lines: decoded layer/field lines shown in the packet detail
            panel; populated on demand rather than for every packet.
    """

    captured_at: datetime
    interface: str = ""
    number: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ""
    transport: str = ""
    highest_layer: str = ""
    app_protocol: str = ""
    length: int = 0
    ttl: int | None = None
    tcp_flags: int | None = None
    src_mac: str = ""
    dst_mac: str = ""
    ip_version: int | None = None
    layers: tuple[str, ...] = ()
    raw_summary: str = ""
    detail_lines: tuple[tuple[str, str], ...] = ()

    @property
    def flags_text(self) -> str:
        """TCP flag names, or a dash when the packet has no TCP layer."""
        return tcp_flag_names(self.tcp_flags)

    @property
    def is_syn_only(self) -> bool:
        """True for a bare SYN (connection attempt, no ACK)."""
        return self.tcp_flags is not None and (self.tcp_flags & 0x12) == 0x02

    @property
    def is_syn_ack(self) -> bool:
        """True for a SYN/ACK (an accepted connection attempt)."""
        return self.tcp_flags is not None and (self.tcp_flags & 0x12) == 0x12

    @property
    def info(self) -> str:
        """Short description for the live packet table's Info column."""
        if self.raw_summary:
            return self.raw_summary
        parts: list[str] = []
        if self.app_protocol:
            parts.append(self.app_protocol)
        elif self.highest_layer:
            parts.append(self.highest_layer)
        if self.tcp_flags is not None:
            parts.append(f"[{self.flags_text}]")
        if self.length:
            parts.append(f"len={self.length}")
        return " ".join(parts) if parts else "-"

    def endpoint_key(self) -> tuple[str, str]:
        """``(source, destination)`` pair used for conversation grouping."""
        return (self.src_ip or self.src_mac, self.dst_ip or self.dst_mac)


@dataclass
class TrafficRecord:
    """A persisted packet metadata row (``traffic_records``)."""

    id: int | None
    captured_at: datetime
    interface: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ""
    app_protocol: str = ""
    length: int = 0
    ttl: int | None = None
    tcp_flags: int | None = None
    src_mac: str = ""
    dst_mac: str = ""
    info: str = ""


@dataclass
class TrafficAggregate:
    """A persisted interval rollup (``traffic_aggregates``).

    Aggregates are what make long-term traffic charts possible without storing
    every packet forever (§36, §79).
    """

    id: int | None
    interval_start: datetime
    interval_end: datetime
    interface: str = ""
    packet_count: int = 0
    byte_count: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    other_packets: int = 0
    unique_sources: int = 0
    unique_destinations: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    dropped_packets: int = 0

    @property
    def duration_seconds(self) -> float:
        """Length of the aggregation interval."""
        return max(
            0.0, (self.interval_end - self.interval_start).total_seconds()
        )


@dataclass
class ProtocolCount:
    """One protocol's share of observed traffic."""

    protocol: str
    packets: int
    bytes: int = 0

    def share_of(self, total_packets: int) -> float:
        """Percentage of ``total_packets`` this protocol represents."""
        return (self.packets / total_packets * 100.0) if total_packets else 0.0


@dataclass
class TalkerCount:
    """A top-talker entry (source or destination)."""

    address: str
    packets: int
    bytes: int = 0
    hostname: str = ""

    @property
    def label(self) -> str:
        """Hostname when resolved, otherwise the address."""
        return self.hostname or self.address


@dataclass
class PortCount:
    """A frequently observed port."""

    port: int
    protocol: str
    packets: int
    service: str = ""

    @property
    def label(self) -> str:
        """``443/tcp (https)`` style label."""
        base = f"{self.port}/{self.protocol}"
        return f"{base} ({self.service})" if self.service else base


@dataclass
class TimePoint:
    """One point on a time-series chart, derived from real measurements."""

    timestamp: datetime
    value: float


@dataclass
class CaptureStatistics:
    """Live counters owned by the capture service.

    ``dropped`` and ``sampled_out`` are shown in the UI so the operator can see
    when the pipeline is shedding load instead of silently losing data (§106).
    """

    interface: str = ""
    is_running: bool = False
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    total_packets: int = 0
    total_bytes: int = 0
    dropped: int = 0
    sampled_out: int = 0
    persisted_rows: int = 0
    decode_errors: int = 0
    last_packet_at: datetime | None = None
    queue_depth: int = 0
    last_error: str = ""
    bpf_filter: str = ""

    @property
    def status_text(self) -> str:
        """Exact capture status - never optimistic."""
        if self.is_running:
            return "CAPTURING"
        if self.last_error:
            return "ERROR"
        if self.stopped_at:
            return "STOPPED"
        return "NOT STARTED"


@dataclass
class TrafficSnapshotData:
    """Serialisable view of the analyzer state consumed by the UI."""

    generated_at: datetime
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    window_packets: int = 0
    window_bytes: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    active_hosts: int = 0
    protocols: tuple[ProtocolCount, ...] = ()
    top_sources: tuple[TalkerCount, ...] = ()
    top_destinations: tuple[TalkerCount, ...] = ()
    top_dst_ports: tuple[PortCount, ...] = ()
    top_src_ports: tuple[PortCount, ...] = ()
    pps_series: tuple[TimePoint, ...] = ()
    bps_series: tuple[TimePoint, ...] = ()
    conversations: tuple[tuple[str, str, int, int], ...] = field(default_factory=tuple)

    @property
    def has_data(self) -> bool:
        """False when nothing has been captured yet (drives empty states)."""
        return self.total_packets > 0
