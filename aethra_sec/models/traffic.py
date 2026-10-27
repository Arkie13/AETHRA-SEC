"""Packet and traffic models produced by the PyShark capture pipeline.

Every field is optional except the capture timestamp and the interface: real
packets frequently lack layers (an ARP frame has no ports, an ICMP packet has no
TCP flags), and the mapper must never fabricate a value to fill a column.
"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.utils.formatting import tcp_flag_names

#: TLS protocol versions by their wire value.
TLS_VERSION_NAMES: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

#: TLS handshake message types by their wire value.
TLS_HANDSHAKE_NAMES: dict[int, str] = {
    0: "Hello Request",
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    8: "Encrypted Extensions",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
}


def is_grease(value: int | None) -> bool:
    """True for a GREASE placeholder (RFC 8701), e.g. 0x1a1a.

    Clients put these in lists on purpose so servers tolerate unknown values.
    A GREASE entry is not a version anyone speaks, so it is never reported as
    one.
    """
    if value is None:
        return False
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def tls_version_name(value: int | None) -> str:
    """``TLS 1.3`` for 0x0304, the hex value for anything unnamed, ``""`` for None."""
    if value is None:
        return ""
    if is_grease(value):
        return f"GREASE placeholder (0x{value:04x})"
    return TLS_VERSION_NAMES.get(value, f"0x{value:04x}")


#: Protocols whose TShark dissector reads part of a message with the TLS
#: dissector although the frame carries no TLS. A DNS answer of type HTTPS or
#: SVCB parses its ECH configuration that way, which puts ``dns:tls`` in the
#: frame's protocol chain while TShark's own ``tls`` filter does not match the
#: frame - seen on real captures. mDNS and LLMNR use the same dissector.
TLS_PARSED_INSIDE: frozenset[str] = frozenset({"DNS", "MDNS", "LLMNR"})


def without_parsed_tls(layers: tuple[str, ...]) -> tuple[str, ...]:
    """The protocol chain less any TLS entry that is not TLS traffic.

    Only a TLS (or SSL) entry directly under one of :data:`TLS_PARSED_INSIDE`
    is dropped. TLS under TCP, or under QUIC - which carries the TLS handshake -
    is kept.
    """
    chain = tuple(layers)
    return tuple(
        name for position, name in enumerate(chain)
        if not (
            name in ("TLS", "SSL") and position and chain[position - 1] in TLS_PARSED_INSIDE
        )
    )


def tls_layer_in_chain(layers: tuple[str, ...]) -> bool:
    """True when the protocol chain holds TLS that is TLS traffic."""
    return any(name in ("TLS", "SSL") for name in without_parsed_tls(layers))


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
    #: Pcap this frame was written to, and its 1-based position in that file.
    #: Together they are the only handle back to the real bytes: the table row
    #: is a summary, and the inspector re-reads the frame itself from here
    #: rather than presenting the summary as though it were a decode.
    pcap_path: str = ""
    frame_index: int | None = None
    #: Relationship to the capture interface - INCOMING, OUTGOING, TRANSIT,
    #: BROADCAST, LOCAL or UNKNOWN - decided from that interface's own
    #: addresses by :mod:`aethra_sec.analytics.traffic_direction`. Empty until
    #: the packet view has classified the packet.
    direction: str = ""
    #: TShark's own Info column for the frame (``_ws.col.info``).
    tshark_info: str = ""
    # Application-layer fields, each exactly as TShark decoded it for this
    # frame. Empty or None whenever the frame does not carry the value - a
    # missing field is shown as N/A, never filled in.
    http_method: str = ""
    http_uri: str = ""
    http_host: str = ""
    http_version: str = ""
    http_status: int | None = None
    http_phrase: str = ""
    tls_handshake_type: int | None = None
    tls_sni: str = ""
    tls_record_version: int | None = None
    tls_handshake_version: int | None = None
    #: First value of the supported_versions extension. In a Client Hello this
    #: is the first version offered (often a GREASE placeholder); in a Server
    #: Hello it is the version the server selected.
    tls_supported_version: int | None = None
    dns_query: str = ""
    dns_response: bool | None = None
    #: The host an SRV record points at (RFC 2782: "the domain name of the
    #: target host"). On mDNS this is how a device states what it calls
    #: itself, and for most consumer hardware it is the only name it ever
    #: publishes. Deliberately not the service *instance* label beside it,
    #: which devices are free to randomise.
    dns_srv_target: str = ""
    #: The address a DNS answer resolved :attr:`dns_query` to, when this frame
    #: is a response carrying one. The join between a name and the traffic that
    #: follows it: later frames of that flow carry this address and no name.
    #: Empty for a query, and for a response with no A/AAAA record.
    dns_answer_address: str = ""
    icmp_type: int | None = None
    icmp_code: int | None = None
    arp_opcode: int | None = None
    arp_sender_mac: str = ""
    arp_target_mac: str = ""
    tcp_seq: int | None = None
    tcp_ack: int | None = None

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

    def has_layer(self, *names: str) -> bool:
        """True when TShark decoded any of ``names`` (upper-case) for this frame."""
        return any(name in self.layers for name in names)

    @property
    def is_http(self) -> bool:
        """True only when TShark decoded HTTP for this frame.

        Not inferred from a port, and not from the presence of HTTP-style
        fields: SSDP reuses HTTP message syntax and TShark fills those fields
        for it, but its protocol chain says SSDP.
        """
        return "HTTP" in self.layers

    @property
    def is_tls(self) -> bool:
        """True only when TShark identified TLS (or legacy SSL) in this frame.

        Either the protocol chain lists TLS, or TShark's TLS dissector wrote the
        Protocol column - which is how a TCP segment carrying part of a TLS
        record is marked when no complete record was decoded in the frame. A
        TLS entry directly under DNS does not count: see
        :data:`TLS_PARSED_INSIDE`.
        """
        if tls_layer_in_chain(self.layers):
            return True
        column = (self.protocol or "").upper()
        return column == "SSL" or column.startswith("TLSV")

    @property
    def http_summary(self) -> str:
        """``GET /login HTTP/1.1  Host: x`` or ``HTTP/1.1 200 OK``, from real fields.

        Empty for a frame that is not HTTP, and for an HTTP frame that carries
        neither a request line nor a status line (a body segment) - TShark's
        own Info text describes those better than anything assembled here.
        """
        if not self.is_http:
            return ""
        if self.http_method:
            line = " ".join(
                part for part in (self.http_method, self.http_uri, self.http_version) if part
            )
            return f"{line}  Host: {self.http_host}" if self.http_host else line
        if self.http_status is not None:
            return " ".join(
                part
                for part in (self.http_version, str(self.http_status), self.http_phrase)
                if part
            )
        return ""

    @property
    def tls_handshake_name(self) -> str:
        """The handshake message type, named, or ``""`` when there is none."""
        if self.tls_handshake_type is None:
            return ""
        return TLS_HANDSHAKE_NAMES.get(
            self.tls_handshake_type, f"type {self.tls_handshake_type}"
        )

    @property
    def tls_negotiated_version(self) -> str:
        """The version the server selected, when this frame states it.

        Only a Server Hello states a negotiated version: from its
        supported_versions extension (TLS 1.3), or from its legacy version
        field when that extension is absent (TLS 1.2 and earlier). A Client
        Hello only *offers* versions, and an encrypted record states none, so
        both return ``""`` rather than a guess.
        """
        if self.tls_handshake_type != 2:
            return ""
        if self.tls_supported_version is not None and not is_grease(
            self.tls_supported_version
        ):
            return tls_version_name(self.tls_supported_version)
        if self.tls_handshake_version is not None:
            return tls_version_name(self.tls_handshake_version)
        return ""

    @property
    def info(self) -> str:
        """Short description for the live packet table's Info column.

        HTTP request and status lines are assembled from the HTTP fields TShark
        decoded; everything else is TShark's own Info text. Nothing here is
        composed from a guess.

        One addition: a TLS server name TShark decoded but its Info text does
        not mention is put first. TShark describes a QUIC Initial packet that
        carries a Client Hello as "Initial, DCID=..., CRYPTO, PADDING"; on real
        captures every HTTP/3 connection's site name was in the decoded field
        alone, so the table would otherwise list those connections nameless.
        """
        http = self.http_summary
        if http:
            return http
        if self.tshark_info:
            if self.tls_sni and self.tls_sni not in self.tshark_info:
                return f"SNI={self.tls_sni}  ·  {self.tshark_info}"
            return self.tshark_info
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
    #: The pipeline's own state. Set by the capture service, which is the only
    #: thing that knows whether a capture process is really running.
    state: str = ""
    bpf_filter: str = ""

    @property
    def status_text(self) -> str:
        """Exact capture status - never optimistic.

        Reports the pipeline's own state when it has been supplied. The
        fallback below is only for a statistics object built without one, and
        deliberately never says CAPTURING: claiming a live capture is the one
        answer that must be earned rather than assumed.
        """
        if self.state:
            return str(self.state)
        if self.last_error:
            return "FAILED"
        if self.stopped_at:
            return "STOPPED"
        return "IDLE"


class CaptureState(str, Enum):
    """Where the capture pipeline actually is.

    One authority for the whole application. The status used to be inferred
    from whether the reader *thread* was alive, which is not the same question:
    given a filter TShark rejects, dumpcap exits, the thread stays alive
    waiting for packets that never come, and the console reported CAPTURING
    while recording nothing.

    CAPTURING is therefore reached only after the capture process has been
    seen running, and is given up as soon as it is seen gone.
    """

    IDLE = "IDLE"
    STARTING = "STARTING"
    CAPTURING = "CAPTURING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"

    def __str__(self) -> str:
        """The label the interface shows."""
        return self.value

    @property
    def is_active(self) -> bool:
        """True while the pipeline is doing something on the operator's behalf."""
        return self in (CaptureState.STARTING, CaptureState.CAPTURING)


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
