"""Traffic metadata and aggregate persistence (§13, §36, §79).

Two storage tiers keep a live network from overwhelming MySQL:

* ``traffic_records`` - per-packet metadata, written in batches, rate-capped
  and pruned on a short retention window;
* ``traffic_aggregates`` - interval rollups, always written, kept far longer,
  and the source of every long-range traffic chart.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Sequence

from aethra_sec.database.repositories.base import (
    QueryFilter,
    Repository,
    as_dt,
    as_float,
    as_int,
    as_text,
    limit_clause,
    order_clause,
    period_bounds,
)
from aethra_sec.models.traffic import (
    PortCount,
    ProtocolCount,
    TalkerCount,
    TrafficAggregate,
    TrafficRecord,
)
from aethra_sec.utils.timeutil import to_db

_FILTERABLE = {
    "captured_at", "interface", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "app_protocol", "length", "info",
}
_SORTABLE = {"captured_at", "id", "src_ip", "dst_ip", "protocol", "length"}

_SELECT = (
    "SELECT id, captured_at, interface, src_ip, dst_ip, src_port, dst_port, "
    "protocol, app_protocol, length, ttl, tcp_flags, src_mac, dst_mac, info "
    "FROM traffic_records"
)

_INSERT = (
    "INSERT INTO traffic_records (captured_at, interface, src_ip, dst_ip, "
    "src_port, dst_port, protocol, app_protocol, length, ttl, tcp_flags, "
    "src_mac, dst_mac, info) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


class TrafficRepository(Repository):
    """Persists and queries captured traffic."""

    @staticmethod
    def _map(row: dict[str, Any]) -> TrafficRecord:
        """Map a row to :class:`TrafficRecord`."""
        return TrafficRecord(
            id=as_int(row.get("id")),
            captured_at=as_dt(row.get("captured_at")) or datetime.min,
            interface=as_text(row.get("interface")),
            src_ip=as_text(row.get("src_ip")),
            dst_ip=as_text(row.get("dst_ip")),
            src_port=as_int(row.get("src_port")),
            dst_port=as_int(row.get("dst_port")),
            protocol=as_text(row.get("protocol")),
            app_protocol=as_text(row.get("app_protocol")),
            length=as_int(row.get("length")) or 0,
            ttl=as_int(row.get("ttl")),
            tcp_flags=as_int(row.get("tcp_flags")),
            src_mac=as_text(row.get("src_mac")),
            dst_mac=as_text(row.get("dst_mac")),
            info=as_text(row.get("info")),
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def insert_batch(self, rows: Iterable[Sequence[Any]]) -> int:
        """Batch-insert packet metadata rows produced by the capture worker."""
        payload = list(rows)
        if not payload:
            return 0
        return self.db.execute_many(_INSERT, payload)

    def insert_aggregate(self, aggregate: TrafficAggregate) -> int:
        """Insert or update one interval rollup."""
        return self.db.execute(
            "INSERT INTO traffic_aggregates (interval_start, interval_end, "
            "interface, packet_count, byte_count, tcp_packets, udp_packets, "
            "icmp_packets, arp_packets, other_packets, unique_sources, "
            "unique_destinations, packets_per_second, bytes_per_second, "
            "dropped_packets) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            "interval_end = VALUES(interval_end), "
            "packet_count = packet_count + VALUES(packet_count), "
            "byte_count = byte_count + VALUES(byte_count), "
            "tcp_packets = tcp_packets + VALUES(tcp_packets), "
            "udp_packets = udp_packets + VALUES(udp_packets), "
            "icmp_packets = icmp_packets + VALUES(icmp_packets), "
            "arp_packets = arp_packets + VALUES(arp_packets), "
            "other_packets = other_packets + VALUES(other_packets), "
            "unique_sources = GREATEST(unique_sources, VALUES(unique_sources)), "
            "unique_destinations = GREATEST(unique_destinations, "
            "                               VALUES(unique_destinations)), "
            "packets_per_second = VALUES(packets_per_second), "
            "bytes_per_second = VALUES(bytes_per_second), "
            "dropped_packets = dropped_packets + VALUES(dropped_packets)",
            (
                to_db(aggregate.interval_start), to_db(aggregate.interval_end),
                aggregate.interface[:96], aggregate.packet_count,
                aggregate.byte_count, aggregate.tcp_packets,
                aggregate.udp_packets, aggregate.icmp_packets,
                aggregate.arp_packets, aggregate.other_packets,
                aggregate.unique_sources, aggregate.unique_destinations,
                round(aggregate.packets_per_second, 3),
                round(aggregate.bytes_per_second, 3),
                aggregate.dropped_packets,
            ),
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def search(
        self,
        *,
        text: str = "",
        src_ip: str = "",
        dst_ip: str = "",
        protocol: str = "",
        dst_port: int | None = None,
        interface: str = "",
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "captured_at",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[TrafficRecord]:
        """Search stored packet metadata."""
        query = QueryFilter(_FILTERABLE)
        query.equals("src_ip", src_ip)
        query.equals("dst_ip", dst_ip)
        query.equals("protocol", protocol)
        query.equals("dst_port", dst_port)
        query.equals("interface", interface)
        query.gte("captured_at", to_db(start))
        query.lte("captured_at", to_db(end))
        query.any_of(("src_ip", "dst_ip", "protocol", "app_protocol", "info"), text)
        order = order_clause(sort_by, sort_dir, _SORTABLE, "captured_at")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map)

    def recent_for_host(self, ip_address: str, limit: int = 200) -> list[TrafficRecord]:
        """Recent packets involving a host, for the host detail screen."""
        rows = self.db.query(
            f"{_SELECT} WHERE src_ip = %s OR dst_ip = %s "
            "ORDER BY captured_at DESC LIMIT %s",
            (ip_address, ip_address, max(1, min(int(limit), 5000))),
        )
        return self._map_all(rows, self._map)

    def count_records(self) -> int:
        """Total stored packet metadata rows."""
        return self.count("SELECT COUNT(*) FROM traffic_records")

    def count_since(self, since: datetime) -> int:
        """Packets stored since a point in time."""
        return self.count(
            "SELECT COUNT(*) FROM traffic_records WHERE captured_at >= %s",
            (to_db(since),),
        )

    def packets_in_period(self, start: datetime | None, end: datetime) -> int:
        """Packets captured inside ``[start, end)``, from aggregates.

        Aggregates are authoritative here: they count every observed packet,
        including any that row-level sampling skipped.

        ``start`` of ``None`` means "everything retained up to ``end``", which
        is what the Dashboard's ALL DATA period asks for. There is deliberately
        no open-ended "since" form: an upper bound is what stops a daily figure
        from quietly counting into the next day.
        """
        if start is not None:
            return self.packets_between(start, end)
        value = self.db.query_value(
            "SELECT COALESCE(SUM(packet_count), 0) FROM traffic_aggregates "
            "WHERE interval_start < %s",
            (to_db(end),),
            default=0,
        )
        return int(value or 0)

    def packets_between(self, start: datetime, end: datetime) -> int:
        """Packets captured inside a window, from aggregates."""
        value = self.db.query_value(
            "SELECT COALESCE(SUM(packet_count), 0) FROM traffic_aggregates "
            "WHERE interval_start >= %s AND interval_start < %s",
            (to_db(start), to_db(end)),
            default=0,
        )
        return int(value or 0)

    def measured_rate_for(
        self,
        src_ip: str,
        start: datetime,
        end: datetime,
        *,
        dst_ip: str | None = None,
    ) -> float | None:
        """Packets per second sent BY ``src_ip`` inside ``[start, end]``.

        One-directional - from the source only - so a target's replies are never
        counted as traffic the source produced: a ping flood seen at 432 pps
        from each end is 432, not 865. ``dst_ip`` narrows it to one target.

        ``None`` when the window is empty or nothing from that source was
        retained, so the caller shows "-" rather than a false zero. Row storage
        is capped per minute, so above that cap this is a floor.
        """
        if not src_ip:
            return None
        seconds = (end - start).total_seconds()
        if seconds <= 0:
            return None
        clause = "captured_at >= %s AND captured_at <= %s AND src_ip = %s"
        params: list[Any] = [to_db(start), to_db(end), src_ip]
        if dst_ip:
            clause += " AND dst_ip = %s"
            params.append(dst_ip)
        count = int(self.db.query_value(
            f"SELECT COUNT(*) FROM traffic_records WHERE {clause}",
            tuple(params),
            default=0,
        ) or 0)
        if count <= 0:
            return None
        return round(count / seconds, 1)

    def total_packets_observed(self) -> int:
        """All packets ever observed, from aggregates."""
        value = self.db.query_value(
            "SELECT COALESCE(SUM(packet_count), 0) FROM traffic_aggregates",
            default=0,
        )
        return int(value or 0)

    def earliest_aggregate_time(self) -> datetime | None:
        """Start of the oldest retained aggregation interval.

        Used to decide whether a previous period is comparable at all: with no
        aggregate older than the window, there is nothing to compare against and
        the dashboard shows no trend rather than a misleading one (§1).
        """
        return as_dt(
            self.db.query_value("SELECT MIN(interval_start) FROM traffic_aggregates")
        )

    def last_packet_time(self) -> datetime | None:
        """Timestamp of the most recent stored packet."""
        return as_dt(self.db.query_value("SELECT MAX(captured_at) FROM traffic_records"))

    def last_aggregate_time(self) -> datetime | None:
        """End of the most recent aggregation interval."""
        return as_dt(
            self.db.query_value("SELECT MAX(interval_end) FROM traffic_aggregates")
        )

    def aggregates_between(
        self, start: datetime | None, end: datetime, interface: str = ""
    ) -> list[TrafficAggregate]:
        """Interval rollups inside ``[start, end)``, oldest first.

        The upper bound is exclusive so that an interval beginning exactly at
        midnight belongs to the new day alone; with an inclusive bound it was
        counted in both days' charts.
        """
        params: list[Any] = []
        lower_clause = ""
        if start is not None:
            lower_clause = "interval_start >= %s AND "
            params.append(to_db(start))
        params.append(to_db(end))
        interface_clause = ""
        if interface:
            interface_clause = "AND interface = %s "
            params.append(interface)
        rows = self.db.query(
            "SELECT id, interval_start, interval_end, interface, packet_count, "
            "byte_count, tcp_packets, udp_packets, icmp_packets, arp_packets, "
            "other_packets, unique_sources, unique_destinations, "
            "packets_per_second, bytes_per_second, dropped_packets "
            "FROM traffic_aggregates "
            f"WHERE {lower_clause}interval_start < %s {interface_clause}"
            "ORDER BY interval_start ASC LIMIT 5000",
            params,
        )
        return [
            TrafficAggregate(
                id=as_int(r["id"]),
                interval_start=as_dt(r["interval_start"]) or start,
                interval_end=as_dt(r["interval_end"]) or end,
                interface=as_text(r["interface"]),
                packet_count=as_int(r["packet_count"]) or 0,
                byte_count=as_int(r["byte_count"]) or 0,
                tcp_packets=as_int(r["tcp_packets"]) or 0,
                udp_packets=as_int(r["udp_packets"]) or 0,
                icmp_packets=as_int(r["icmp_packets"]) or 0,
                arp_packets=as_int(r["arp_packets"]) or 0,
                other_packets=as_int(r["other_packets"]) or 0,
                unique_sources=as_int(r["unique_sources"]) or 0,
                unique_destinations=as_int(r["unique_destinations"]) or 0,
                packets_per_second=as_float(r["packets_per_second"]) or 0.0,
                bytes_per_second=as_float(r["bytes_per_second"]) or 0.0,
                dropped_packets=as_int(r["dropped_packets"]) or 0,
            )
            for r in rows
        ]

    def protocol_distribution(
        self, since: datetime | None, end: datetime | None = None
    ) -> list[ProtocolCount]:
        """Protocol mix from aggregates, so it reflects every observed packet.

        ``end`` is exclusive. Passing it is what keeps the Dashboard's protocol
        chart inside its reporting period instead of running on to the present.
        """
        clauses, params = period_bounds("interval_start", since, end)
        row = self.db.query_one(
            "SELECT COALESCE(SUM(tcp_packets),0) AS tcp, "
            "COALESCE(SUM(udp_packets),0) AS udp, "
            "COALESCE(SUM(icmp_packets),0) AS icmp, "
            "COALESCE(SUM(arp_packets),0) AS arp, "
            "COALESCE(SUM(other_packets),0) AS other "
            f"FROM traffic_aggregates {clauses}",
            params,
        )
        if not row:
            return []
        counts = [
            ProtocolCount("TCP", as_int(row["tcp"]) or 0),
            ProtocolCount("UDP", as_int(row["udp"]) or 0),
            ProtocolCount("ICMP", as_int(row["icmp"]) or 0),
            ProtocolCount("ARP", as_int(row["arp"]) or 0),
            ProtocolCount("Other", as_int(row["other"]) or 0),
        ]
        return [c for c in counts if c.packets > 0]

    def top_sources(
        self, since: datetime | None, limit: int = 10, end: datetime | None = None
    ) -> list[TalkerCount]:
        """Busiest source addresses in the stored packet metadata."""
        clauses, params = period_bounds("captured_at", since, end, "src_ip <> ''")
        rows = self.db.query(
            "SELECT src_ip AS address, COUNT(*) AS packets, "
            "COALESCE(SUM(length),0) AS bytes FROM traffic_records "
            f"{clauses} GROUP BY src_ip ORDER BY packets DESC LIMIT %s",
            [*params, max(1, min(int(limit), 100))],
        )
        return [
            TalkerCount(
                address=as_text(r["address"]),
                packets=as_int(r["packets"]) or 0,
                bytes=as_int(r["bytes"]) or 0,
            )
            for r in rows
        ]

    def top_destinations(
        self, since: datetime | None, limit: int = 10, end: datetime | None = None
    ) -> list[TalkerCount]:
        """Busiest destination addresses in the stored packet metadata."""
        clauses, params = period_bounds("captured_at", since, end, "dst_ip <> ''")
        rows = self.db.query(
            "SELECT dst_ip AS address, COUNT(*) AS packets, "
            "COALESCE(SUM(length),0) AS bytes FROM traffic_records "
            f"{clauses} GROUP BY dst_ip ORDER BY packets DESC LIMIT %s",
            [*params, max(1, min(int(limit), 100))],
        )
        return [
            TalkerCount(
                address=as_text(r["address"]),
                packets=as_int(r["packets"]) or 0,
                bytes=as_int(r["bytes"]) or 0,
            )
            for r in rows
        ]

    def top_ports(
        self, since: datetime | None, limit: int = 10, end: datetime | None = None
    ) -> list[PortCount]:
        """Most contacted destination ports in the stored packet metadata."""
        clauses, params = period_bounds("captured_at", since, end, "dst_port IS NOT NULL")
        rows = self.db.query(
            "SELECT dst_port AS port, protocol, COUNT(*) AS packets "
            f"FROM traffic_records {clauses} "
            "GROUP BY dst_port, protocol ORDER BY packets DESC LIMIT %s",
            [*params, max(1, min(int(limit), 100))],
        )
        return [
            PortCount(
                port=as_int(r["port"]) or 0,
                protocol=as_text(r["protocol"]),
                packets=as_int(r["packets"]) or 0,
            )
            for r in rows
        ]

    def distinct_interfaces(self) -> list[str]:
        """Interfaces that have produced stored traffic."""
        rows = self.db.query(
            "SELECT DISTINCT interface FROM traffic_aggregates "
            "WHERE interface <> '' ORDER BY interface LIMIT 100"
        )
        return [as_text(r["interface"]) for r in rows]

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------
    def prune_records_before(self, cutoff: datetime, batch: int = 20_000) -> int:
        """Delete packet metadata older than ``cutoff``, in bounded batches."""
        return self.db.execute(
            "DELETE FROM traffic_records WHERE captured_at < %s LIMIT %s",
            (to_db(cutoff), max(1, int(batch))),
        )

    def prune_aggregates_before(self, cutoff: datetime) -> int:
        """Delete interval rollups older than ``cutoff``."""
        return self.db.execute(
            "DELETE FROM traffic_aggregates WHERE interval_start < %s",
            (to_db(cutoff),),
        )
