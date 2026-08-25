"""In-memory traffic statistics over real captured packets (§14).

Every figure the dashboard shows for live traffic is computed here from packets
that TShark actually delivered. Nothing is extrapolated or smoothed into
existence: an interval with no packets contributes zero, and a snapshot taken
before any packet arrives reports ``has_data == False`` so the interface can
show "Waiting for live network data..." instead of a flat line.

Memory is bounded by construction: observations are folded into per-second
buckets, buckets outside the retention window are discarded, and each bucket's
cardinality counters are capped.
"""

from __future__ import annotations

import threading
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Iterable

from aethra_sec.models.traffic import (
    CapturedPacket,
    PortCount,
    ProtocolCount,
    TalkerCount,
    TimePoint,
    TrafficSnapshotData,
)
from aethra_sec.utils.net import service_name_for_port
from aethra_sec.utils.timeutil import utcnow

#: Longest window the analyzer keeps per-second detail for.
DEFAULT_WINDOW_SECONDS = 300

#: Maximum distinct keys tracked inside one second bucket. Beyond this the
#: least-seen keys are dropped; top-talker rankings stay accurate because the
#: dropped keys are by definition the rare ones.
MAX_KEYS_PER_BUCKET = 4000


@dataclass
class SecondBucket:
    """Everything observed during one wall-clock second."""

    second: int
    packets: int = 0
    bytes: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    arp: int = 0
    other: int = 0
    syn: int = 0
    syn_ack: int = 0
    sources: Counter = field(default_factory=Counter)
    destinations: Counter = field(default_factory=Counter)
    source_bytes: Counter = field(default_factory=Counter)
    destination_bytes: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)
    src_ports: Counter = field(default_factory=Counter)
    conversations: Counter = field(default_factory=Counter)
    conversation_bytes: Counter = field(default_factory=Counter)
    protocols: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)
    app_protocols: Counter = field(default_factory=Counter)

    def trim(self, limit: int = MAX_KEYS_PER_BUCKET) -> None:
        """Cap cardinality so a scan against thousands of hosts cannot grow
        this bucket without bound."""
        for counter in (
            self.sources, self.destinations, self.source_bytes,
            self.destination_bytes, self.dst_ports, self.src_ports,
            self.conversations, self.conversation_bytes,
        ):
            if len(counter) > limit:
                for key, _ in counter.most_common()[limit:]:
                    del counter[key]


class TrafficAnalyzer:
    """Rolling statistics over observed packets.

    Thread-safe: :meth:`observe` runs on the capture worker while
    :meth:`snapshot` may be called from the scheduler or the UI tick.
    """

    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        rate_window_seconds: int = 5,
    ) -> None:
        """Create an empty analyzer.

        Args:
            window_seconds: how much per-second detail to retain.
            rate_window_seconds: trailing window used for pps/bps.
        """
        self._lock = threading.RLock()
        self._window = max(10, int(window_seconds))
        self._rate_window = max(1, int(rate_window_seconds))
        self._buckets: dict[int, SecondBucket] = {}
        self._bucket_order: Deque[int] = deque()
        self._newest_second: int | None = None
        #: Hard ceiling on retained buckets. One bucket per second inside the
        #: window is the normal case; the margin absorbs out-of-order arrivals.
        self._max_buckets = self._window + 2

        self.total_packets = 0
        self.total_bytes = 0
        self.first_packet_at: datetime | None = None
        self.last_packet_at: datetime | None = None
        self._all_protocols: Counter = Counter()
        self._interfaces: set[str] = set()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def observe(self, packet: CapturedPacket) -> None:
        """Fold one real packet into the rolling statistics."""
        second = int(packet.captured_at.timestamp())
        with self._lock:
            if self._newest_second is None or second > self._newest_second:
                self._newest_second = second

            bucket = self._buckets.get(second)
            if bucket is None and second >= self._newest_second - self._window:
                bucket = SecondBucket(second=second)
                self._buckets[second] = bucket
                self._bucket_order.append(second)
                self._evict()
            if bucket is not None:
                self._fold_into_bucket(bucket, packet)

            self.total_packets += 1
            self.total_bytes += packet.length
            protocol = (packet.protocol or "OTHER").upper()
            self._all_protocols[protocol] += 1
            if packet.interface:
                self._interfaces.add(packet.interface)
            if self.first_packet_at is None:
                self.first_packet_at = packet.captured_at
            self.last_packet_at = packet.captured_at

    def _fold_into_bucket(self, bucket: SecondBucket, packet: CapturedPacket) -> None:
        """Add one packet to the per-second bucket it belongs to.

        A packet whose timestamp falls outside the retention window never
        reaches this method: its detail would be evicted before any query could
        read it. It is still counted in the lifetime totals above.
        """
        protocol = (packet.protocol or "OTHER").upper()
        bucket.packets += 1
        bucket.bytes += packet.length
        bucket.protocols[protocol] += 1
        bucket.protocol_bytes[protocol] += packet.length
        if protocol == "TCP":
            bucket.tcp += 1
            if packet.is_syn_only:
                bucket.syn += 1
            elif packet.is_syn_ack:
                bucket.syn_ack += 1
        elif protocol == "UDP":
            bucket.udp += 1
        elif protocol.startswith("ICMP"):
            bucket.icmp += 1
        elif protocol == "ARP":
            bucket.arp += 1
        else:
            bucket.other += 1

        if packet.app_protocol:
            bucket.app_protocols[packet.app_protocol] += 1

        source = packet.src_ip or packet.src_mac
        destination = packet.dst_ip or packet.dst_mac
        if source:
            bucket.sources[source] += 1
            bucket.source_bytes[source] += packet.length
        if destination:
            bucket.destinations[destination] += 1
            bucket.destination_bytes[destination] += packet.length
        if source and destination:
            key = (source, destination)
            bucket.conversations[key] += 1
            bucket.conversation_bytes[key] += packet.length
        if packet.dst_port is not None:
            bucket.dst_ports[(packet.dst_port, protocol)] += 1
        if packet.src_port is not None:
            bucket.src_ports[(packet.src_port, protocol)] += 1

        bucket.trim()

    def _evict(self) -> None:
        """Discard buckets that fell out of the retention window (§105).

        Eviction is anchored on the newest second observed so far rather than
        on the second just written, so a packet whose timestamp runs backwards
        - reordered on the wire, or carrying a skewed clock - cannot keep stale
        buckets alive. The trailing loop is a hard ceiling for the same reason.
        """
        if self._newest_second is None:
            return
        cutoff = self._newest_second - self._window
        while self._bucket_order and self._bucket_order[0] < cutoff:
            stale = self._bucket_order.popleft()
            self._buckets.pop(stale, None)
        while len(self._bucket_order) > self._max_buckets:
            stale = self._bucket_order.popleft()
            self._buckets.pop(stale, None)

    def reset(self) -> None:
        """Clear every statistic (used by the Clear Display control)."""
        with self._lock:
            self._buckets.clear()
            self._bucket_order.clear()
            self._newest_second = None
            self.total_packets = 0
            self.total_bytes = 0
            self.first_packet_at = None
            self.last_packet_at = None
            self._all_protocols.clear()
            self._interfaces.clear()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def _buckets_in(self, seconds: int, now: datetime | None = None) -> list[SecondBucket]:
        """Buckets inside a trailing window, oldest first."""
        reference = int((now or utcnow()).timestamp())
        # Anchor on the last observed packet when capture has just stopped, so
        # a snapshot taken a moment later still describes the captured traffic.
        if self.last_packet_at is not None:
            reference = max(reference, int(self.last_packet_at.timestamp()))
        cutoff = reference - max(1, seconds)
        return [
            self._buckets[second]
            for second in sorted(self._bucket_order)
            if second >= cutoff and second in self._buckets
        ]

    def packets_per_second(self, window: int | None = None) -> float:
        """Mean packet rate over the trailing window."""
        with self._lock:
            window = window or self._rate_window
            buckets = self._buckets_in(window)
            if not buckets:
                return 0.0
            return sum(b.packets for b in buckets) / float(window)

    def bytes_per_second(self, window: int | None = None) -> float:
        """Mean byte rate over the trailing window."""
        with self._lock:
            window = window or self._rate_window
            buckets = self._buckets_in(window)
            if not buckets:
                return 0.0
            return sum(b.bytes for b in buckets) / float(window)

    def active_hosts(self, window: int | None = None) -> int:
        """Distinct addresses observed in the trailing window."""
        with self._lock:
            buckets = self._buckets_in(window or self._window)
            addresses: set[str] = set()
            for bucket in buckets:
                addresses.update(bucket.sources)
                addresses.update(bucket.destinations)
            return len(addresses)

    def protocol_distribution(self, window: int | None = None) -> list[ProtocolCount]:
        """Protocol mix over the window, most frequent first."""
        with self._lock:
            counts: Counter = Counter()
            byte_counts: Counter = Counter()
            for bucket in self._buckets_in(window or self._window):
                counts.update(bucket.protocols)
                byte_counts.update(bucket.protocol_bytes)
            return [
                ProtocolCount(protocol=name, packets=count, bytes=byte_counts.get(name, 0))
                for name, count in counts.most_common()
            ]

    def application_distribution(self, window: int | None = None) -> list[ProtocolCount]:
        """Application-protocol mix over the window."""
        with self._lock:
            counts: Counter = Counter()
            for bucket in self._buckets_in(window or self._window):
                counts.update(bucket.app_protocols)
            return [
                ProtocolCount(protocol=name, packets=count)
                for name, count in counts.most_common(15)
            ]

    def top_sources(self, limit: int = 10, window: int | None = None) -> list[TalkerCount]:
        """Busiest source addresses in the window."""
        return self._top_talkers("sources", "source_bytes", limit, window)

    def top_destinations(
        self, limit: int = 10, window: int | None = None
    ) -> list[TalkerCount]:
        """Busiest destination addresses in the window."""
        return self._top_talkers("destinations", "destination_bytes", limit, window)

    def _top_talkers(
        self, packet_attr: str, byte_attr: str, limit: int, window: int | None
    ) -> list[TalkerCount]:
        """Shared implementation for the top-talker queries."""
        with self._lock:
            packets: Counter = Counter()
            byte_counts: Counter = Counter()
            for bucket in self._buckets_in(window or self._window):
                packets.update(getattr(bucket, packet_attr))
                byte_counts.update(getattr(bucket, byte_attr))
            return [
                TalkerCount(address=address, packets=count, bytes=byte_counts.get(address, 0))
                for address, count in packets.most_common(max(1, limit))
            ]

    def top_destination_ports(
        self, limit: int = 10, window: int | None = None
    ) -> list[PortCount]:
        """Most contacted destination ports in the window."""
        return self._top_ports("dst_ports", limit, window)

    def top_source_ports(
        self, limit: int = 10, window: int | None = None
    ) -> list[PortCount]:
        """Most active source ports in the window."""
        return self._top_ports("src_ports", limit, window)

    def _top_ports(
        self, attribute: str, limit: int, window: int | None
    ) -> list[PortCount]:
        """Shared implementation for the port-ranking queries."""
        with self._lock:
            counts: Counter = Counter()
            for bucket in self._buckets_in(window or self._window):
                counts.update(getattr(bucket, attribute))
            results: list[PortCount] = []
            for (port, protocol), count in counts.most_common(max(1, limit)):
                results.append(
                    PortCount(
                        port=int(port),
                        protocol=str(protocol).lower(),
                        packets=int(count),
                        service=service_name_for_port(int(port), str(protocol)),
                    )
                )
            return results

    def top_conversations(
        self, limit: int = 10, window: int | None = None
    ) -> list[tuple[str, str, int, int]]:
        """Busiest ``(source, destination, packets, bytes)`` pairs."""
        with self._lock:
            counts: Counter = Counter()
            byte_counts: Counter = Counter()
            for bucket in self._buckets_in(window or self._window):
                counts.update(bucket.conversations)
                byte_counts.update(bucket.conversation_bytes)
            return [
                (pair[0], pair[1], count, byte_counts.get(pair, 0))
                for pair, count in counts.most_common(max(1, limit))
            ]

    def rate_series(
        self, points: int = 60, window: int | None = None
    ) -> tuple[list[TimePoint], list[TimePoint]]:
        """Packet-rate and byte-rate series for the traffic charts.

        Returns:
            ``(pps_series, bps_series)`` downsampled to at most ``points``
            entries. Seconds with no traffic are included as genuine zeros, so
            a quiet period looks quiet rather than being interpolated away.
        """
        with self._lock:
            span = max(1, window or min(self._window, 120))
            reference = int((self.last_packet_at or utcnow()).timestamp())
            start = reference - span + 1
            counts = [
                (second, self._buckets.get(second))
                for second in range(start, reference + 1)
            ]
            if not counts:
                return [], []

            group = max(1, len(counts) // max(1, points))
            pps: list[TimePoint] = []
            bps: list[TimePoint] = []
            for index in range(0, len(counts), group):
                chunk = counts[index : index + group]
                seconds = len(chunk)
                packet_total = sum(b.packets for _, b in chunk if b)
                byte_total = sum(b.bytes for _, b in chunk if b)
                stamp = datetime.fromtimestamp(chunk[0][0], tz=utcnow().tzinfo)
                pps.append(TimePoint(stamp, packet_total / seconds))
                bps.append(TimePoint(stamp, byte_total / seconds))
            return pps, bps

    def snapshot(self, top_n: int = 10, chart_points: int = 60) -> TrafficSnapshotData:
        """Build the complete view the dashboard and monitor screen render."""
        with self._lock:
            pps_series, bps_series = self.rate_series(points=chart_points)
            window_buckets = self._buckets_in(self._window)
            return TrafficSnapshotData(
                generated_at=utcnow(),
                packets_per_second=self.packets_per_second(),
                bytes_per_second=self.bytes_per_second(),
                window_packets=sum(b.packets for b in window_buckets),
                window_bytes=sum(b.bytes for b in window_buckets),
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                active_hosts=self.active_hosts(),
                protocols=tuple(self.protocol_distribution()),
                top_sources=tuple(self.top_sources(top_n)),
                top_destinations=tuple(self.top_destinations(top_n)),
                top_dst_ports=tuple(self.top_destination_ports(top_n)),
                top_src_ports=tuple(self.top_source_ports(top_n)),
                pps_series=tuple(pps_series),
                bps_series=tuple(bps_series),
                conversations=tuple(self.top_conversations(top_n)),
            )

    def interval_totals(
        self, start: datetime, end: datetime
    ) -> dict[str, int | float]:
        """Aggregate one interval for persistence into ``traffic_aggregates``."""
        with self._lock:
            start_second = int(start.timestamp())
            end_second = int(end.timestamp())
            buckets = [
                self._buckets[s]
                for s in sorted(self._bucket_order)
                if start_second <= s < end_second and s in self._buckets
            ]
            sources: set[str] = set()
            destinations: set[str] = set()
            for bucket in buckets:
                sources.update(bucket.sources)
                destinations.update(bucket.destinations)
            duration = max(1.0, (end - start).total_seconds())
            packets = sum(b.packets for b in buckets)
            byte_total = sum(b.bytes for b in buckets)
            return {
                "packet_count": packets,
                "byte_count": byte_total,
                "tcp_packets": sum(b.tcp for b in buckets),
                "udp_packets": sum(b.udp for b in buckets),
                "icmp_packets": sum(b.icmp for b in buckets),
                "arp_packets": sum(b.arp for b in buckets),
                "other_packets": sum(b.other for b in buckets),
                "unique_sources": len(sources),
                "unique_destinations": len(destinations),
                "packets_per_second": packets / duration,
                "bytes_per_second": byte_total / duration,
            }

    def observed_interfaces(self) -> tuple[str, ...]:
        """Interfaces that have produced packets in this session."""
        with self._lock:
            return tuple(sorted(self._interfaces))

    @property
    def has_data(self) -> bool:
        """False until a real packet has been observed."""
        return self.total_packets > 0


def summarise_hosts(packets: Iterable[CapturedPacket]) -> dict[str, dict[str, object]]:
    """Aggregate a packet batch per host for inventory persistence.

    Returns:
        ``{address: {mac, packets_sent, packets_received, bytes_sent,
        bytes_received, first_seen, last_seen, protocols}}``.
    """
    hosts: dict[str, dict[str, object]] = {}

    def entry(address: str) -> dict[str, object]:
        return hosts.setdefault(
            address,
            {
                "mac": "",
                "packets_sent": 0,
                "packets_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "first_seen": None,
                "last_seen": None,
                "protocols": set(),
            },
        )

    for packet in packets:
        for address, mac, sent in (
            (packet.src_ip, packet.src_mac, True),
            (packet.dst_ip, packet.dst_mac, False),
        ):
            if not address:
                continue
            record = entry(address)
            if mac and not record["mac"]:
                record["mac"] = mac
            if sent:
                record["packets_sent"] = int(record["packets_sent"]) + 1
                record["bytes_sent"] = int(record["bytes_sent"]) + packet.length
            else:
                record["packets_received"] = int(record["packets_received"]) + 1
                record["bytes_received"] = int(record["bytes_received"]) + packet.length
            first = record["first_seen"]
            if first is None or packet.captured_at < first:  # type: ignore[operator]
                record["first_seen"] = packet.captured_at
            last = record["last_seen"]
            if last is None or packet.captured_at > last:  # type: ignore[operator]
                record["last_seen"] = packet.captured_at
            if packet.protocol:
                protocols = record["protocols"]
                assert isinstance(protocols, set)
                protocols.add(packet.protocol)
    return hosts
