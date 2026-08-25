"""Host inventory persistence (§15, §46)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Sequence

from aethra_sec.database.repositories.base import (
    QueryFilter,
    Repository,
    as_bool,
    as_dt,
    as_int,
    as_text,
    limit_clause,
    order_clause,
)
from aethra_sec.models.enums import EvidenceSource, HostStatus, RiskLevel
from aethra_sec.models.host import Host, HostObservation, TrustedHost
from aethra_sec.utils.timeutil import to_db, utcnow

_FILTERABLE = {
    "ip_address", "mac_address", "hostname", "os_name", "status",
    "risk_level", "discovery_source", "is_trusted", "last_seen", "first_seen",
}
_SORTABLE = {
    "ip_address", "hostname", "last_seen", "first_seen", "risk_level", "status",
}
_SELECT = (
    "SELECT id, ip_address, mac_address, hostname, hostname_checked_at, vendor, "
    "os_name, os_accuracy, status, risk_level, discovery_source, is_trusted, "
    "trust_note, first_seen, last_seen, created_at, updated_at FROM hosts"
)


class HostRepository(Repository):
    """Upserts and queries over the observed-host inventory."""

    @staticmethod
    def _map(row: dict[str, Any]) -> Host:
        """Map a row to :class:`Host`."""
        return Host(
            id=as_int(row.get("id")),
            ip_address=as_text(row.get("ip_address")),
            mac_address=as_text(row.get("mac_address")),
            hostname=as_text(row.get("hostname")),
            hostname_checked_at=as_dt(row.get("hostname_checked_at")),
            vendor=as_text(row.get("vendor")),
            os_name=as_text(row.get("os_name")),
            os_accuracy=as_int(row.get("os_accuracy")),
            status=HostStatus.parse(row.get("status"), HostStatus.UNKNOWN),
            risk_level=RiskLevel.parse(row.get("risk_level"), RiskLevel.INFORMATIONAL),
            discovery_source=EvidenceSource.parse(
                row.get("discovery_source"), EvidenceSource.PYSHARK
            ),
            is_trusted=as_bool(row.get("is_trusted")),
            trust_note=as_text(row.get("trust_note")),
            first_seen=as_dt(row.get("first_seen")),
            last_seen=as_dt(row.get("last_seen")),
            created_at=as_dt(row.get("created_at")),
            updated_at=as_dt(row.get("updated_at")),
            open_port_count=as_int(row.get("open_port_count")) or 0,
            alert_count=as_int(row.get("alert_count")) or 0,
            incident_count=as_int(row.get("incident_count")) or 0,
            finding_count=as_int(row.get("finding_count")) or 0,
            packet_count=as_int(row.get("packet_count")) or 0,
        )

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def upsert_observed(
        self,
        ip_address: str,
        *,
        observed_at: datetime,
        mac_address: str = "",
        source: EvidenceSource = EvidenceSource.PYSHARK,
    ) -> int:
        """Record that a host was seen, creating the inventory row if needed.

        Returns:
            The host id.
        """
        stamp = to_db(observed_at)
        self.db.execute(
            "INSERT INTO hosts (ip_address, mac_address, status, "
            "discovery_source, first_seen, last_seen, created_at, updated_at) "
            "VALUES (%s, %s, 'UP', %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            "last_seen = GREATEST(last_seen, VALUES(last_seen)), "
            "mac_address = IF(VALUES(mac_address) = '', mac_address, VALUES(mac_address)), "
            "updated_at = VALUES(updated_at)",
            (ip_address, mac_address, str(source), stamp, stamp, stamp, stamp),
        )
        return int(
            self.db.query_value(
                "SELECT id FROM hosts WHERE ip_address = %s", (ip_address,), default=0
            )
            or 0
        )

    def bulk_upsert_observed(
        self, observations: Iterable[tuple[str, str, datetime]],
        source: EvidenceSource = EvidenceSource.PYSHARK,
    ) -> int:
        """Batch version of :meth:`upsert_observed`.

        Args:
            observations: ``(ip_address, mac_address, last_seen)`` triples.
            source: which subsystem observed the hosts.

        Returns:
            Number of rows affected.
        """
        rows = []
        for ip_address, mac, seen in observations:
            stamp = to_db(seen)
            rows.append((ip_address, mac, str(source), stamp, stamp, stamp, stamp))
        if not rows:
            return 0
        return self.db.execute_many(
            "INSERT INTO hosts (ip_address, mac_address, status, "
            "discovery_source, first_seen, last_seen, created_at, updated_at) "
            "VALUES (%s, %s, 'UP', %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            "last_seen = GREATEST(last_seen, VALUES(last_seen)), "
            "mac_address = IF(VALUES(mac_address) = '', mac_address, VALUES(mac_address)), "
            "updated_at = VALUES(updated_at)",
            rows,
        )

    def update_identity(
        self,
        host_id: int,
        *,
        hostname: str | None = None,
        mac_address: str | None = None,
        vendor: str | None = None,
        os_name: str | None = None,
        os_accuracy: int | None = None,
        status: HostStatus | None = None,
    ) -> None:
        """Update identity fields discovered by a scan.

        Only non-``None`` arguments are written, so a later scan that could not
        determine the OS does not erase a value an earlier scan found.
        """
        assignments: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("hostname", hostname),
            ("mac_address", mac_address),
            ("vendor", vendor),
            ("os_name", os_name),
            ("os_accuracy", os_accuracy),
        ):
            if value is not None and value != "":
                assignments.append(f"{column} = %s")
                params.append(value)
        if status is not None:
            assignments.append("status = %s")
            params.append(str(status))
        if not assignments:
            return
        assignments.append("updated_at = %s")
        params.extend([to_db(utcnow()), host_id])
        self.db.execute(
            f"UPDATE hosts SET {', '.join(assignments)} WHERE id = %s", params
        )

    def mark_hostname_checked(self, host_ids: Sequence[int]) -> int:
        """Record that reverse DNS was attempted for these hosts.

        Written whether or not a name came back: the point is to distinguish
        "no DNS record" from "never looked", and to stop a background resolver
        asking the same nameless addresses on every pass.
        """
        ids = [int(host_id) for host_id in host_ids]
        if not ids:
            return 0
        placeholders = ", ".join(["%s"] * len(ids))
        return self.db.execute(
            f"UPDATE hosts SET hostname_checked_at = %s WHERE id IN ({placeholders})",
            (to_db(utcnow()), *ids),
        )

    def unresolved_hostnames(self, limit: int = 50) -> list[Host]:
        """Hosts with no hostname that have never been looked up.

        Ordered by most recently seen, so a bounded batch spends its lookups
        on the hosts an operator is most likely to be looking at.
        """
        rows = self.db.query(
            f"{_SELECT} WHERE hostname = '' AND hostname_checked_at IS NULL "
            "ORDER BY last_seen DESC LIMIT %s",
            (max(1, int(limit)),),
        )
        return self._map_all(rows, self._map)

    def count_unresolved_hostnames(self) -> int:
        """How many hosts have never had reverse DNS attempted."""
        return self.count(
            "SELECT COUNT(*) FROM hosts "
            "WHERE hostname = '' AND hostname_checked_at IS NULL"
        )

    def set_risk_level(self, host_id: int, risk: RiskLevel) -> None:
        """Store the risk level derived from this host's findings."""
        self.db.execute(
            "UPDATE hosts SET risk_level = %s, updated_at = %s WHERE id = %s",
            (str(risk), to_db(utcnow()), host_id),
        )

    def set_trusted(self, host_id: int, trusted: bool, note: str = "") -> None:
        """Mark or unmark a host as a trusted asset (context, not exemption)."""
        self.db.execute(
            "UPDATE hosts SET is_trusted = %s, trust_note = %s, updated_at = %s "
            "WHERE id = %s",
            (1 if trusted else 0, note[:255], to_db(utcnow()), host_id),
        )

    def record_observation(
        self,
        host_id: int,
        *,
        interface: str,
        protocol: str,
        packets_sent: int,
        packets_received: int,
        bytes_sent: int,
        bytes_received: int,
        first_seen: datetime,
        last_seen: datetime,
    ) -> None:
        """Accumulate a per-host traffic rollup."""
        self.db.execute(
            "INSERT INTO host_observations (host_id, interface, protocol, "
            "packets_sent, packets_received, bytes_sent, bytes_received, "
            "first_seen, last_seen, source) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'PYSHARK') "
            "ON DUPLICATE KEY UPDATE "
            "packets_sent = packets_sent + VALUES(packets_sent), "
            "packets_received = packets_received + VALUES(packets_received), "
            "bytes_sent = bytes_sent + VALUES(bytes_sent), "
            "bytes_received = bytes_received + VALUES(bytes_received), "
            "last_seen = GREATEST(last_seen, VALUES(last_seen))",
            (
                host_id, interface[:96], protocol[:16], packets_sent,
                packets_received, bytes_sent, bytes_received,
                to_db(first_seen), to_db(last_seen),
            ),
        )

    def bulk_record_observations(self, rows: Iterable[tuple[Any, ...]]) -> int:
        """Batch version of :meth:`record_observation`."""
        payload = list(rows)
        if not payload:
            return 0
        return self.db.execute_many(
            "INSERT INTO host_observations (host_id, interface, protocol, "
            "packets_sent, packets_received, bytes_sent, bytes_received, "
            "first_seen, last_seen, source) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'PYSHARK') "
            "ON DUPLICATE KEY UPDATE "
            "packets_sent = packets_sent + VALUES(packets_sent), "
            "packets_received = packets_received + VALUES(packets_received), "
            "bytes_sent = bytes_sent + VALUES(bytes_sent), "
            "bytes_received = bytes_received + VALUES(bytes_received), "
            "last_seen = GREATEST(last_seen, VALUES(last_seen))",
            payload,
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get(self, host_id: int) -> Host | None:
        """Fetch one host by id."""
        row = self.db.query_one(f"{_SELECT} WHERE id = %s", (host_id,))
        return self._map(row) if row else None

    def get_by_ip(self, ip_address: str) -> Host | None:
        """Fetch one host by IP address."""
        row = self.db.query_one(f"{_SELECT} WHERE ip_address = %s", (ip_address,))
        return self._map(row) if row else None

    def find_id_by_ip(self, ip_address: str) -> int | None:
        """Resolve an IP to a host id without loading the whole row."""
        if not ip_address:
            return None
        value = self.db.query_value(
            "SELECT id FROM hosts WHERE ip_address = %s", (ip_address,)
        )
        return as_int(value)

    def search(
        self,
        *,
        text: str = "",
        status: str = "",
        risk_level: str = "",
        trusted_only: bool = False,
        seen_since: datetime | None = None,
        sort_by: str = "last_seen",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[Host]:
        """Search the inventory with counters joined in."""
        query = QueryFilter(_FILTERABLE, prefix="h")
        query.equals("status", status)
        query.equals("risk_level", risk_level)
        query.gte("last_seen", to_db(seen_since))
        if trusted_only:
            query.equals("is_trusted", 1)
        query.any_of(("ip_address", "hostname", "mac_address", "os_name"), text)

        order = order_clause(sort_by, sort_dir, _SORTABLE, "last_seen", "h")
        limit_sql, limit_params = limit_clause(limit, offset)
        # Counters come from correlated sub-selects so a host with no alerts
        # still appears (a LEFT JOIN + GROUP BY would multiply rows).
        sql = (
            "SELECT h.*, "
            "(SELECT COUNT(*) FROM snort_alerts a "
            "  WHERE a.src_host_id = h.id OR a.dst_host_id = h.id) AS alert_count, "
            "(SELECT COUNT(*) FROM incidents i WHERE i.affected_host_id = h.id) "
            "  AS incident_count, "
            "(SELECT COUNT(*) FROM scan_findings f "
            "  WHERE f.host_id = h.id AND f.resolved_at IS NULL) AS finding_count, "
            "(SELECT COUNT(DISTINCT p.port) FROM ports p "
            "  JOIN scan_hosts sh ON sh.id = p.scan_host_id "
            "  WHERE sh.host_id = h.id AND p.state = 'open') AS open_port_count, "
            "(SELECT COALESCE(SUM(o.packets_sent + o.packets_received), 0) "
            "  FROM host_observations o WHERE o.host_id = h.id) AS packet_count "
            f"FROM hosts h {query.where_clause()} {order} {limit_sql}"
        )
        rows = self.db.query(sql, (*query.bound_params(), *limit_params))
        return self._map_all(rows, self._map)

    def count_all(self) -> int:
        """Total number of known hosts."""
        return self.count("SELECT COUNT(*) FROM hosts")

    def count_active_since(self, since: datetime) -> int:
        """Hosts seen since a point in time (drives 'Active hosts')."""
        return self.count(
            "SELECT COUNT(*) FROM hosts WHERE last_seen >= %s", (to_db(since),)
        )

    def observations_for_host(self, host_id: int) -> list[HostObservation]:
        """Traffic rollups recorded for one host."""
        rows = self.db.query(
            "SELECT id, host_id, interface, protocol, packets_sent, "
            "packets_received, bytes_sent, bytes_received, first_seen, "
            "last_seen, source FROM host_observations WHERE host_id = %s "
            "ORDER BY last_seen DESC LIMIT 200",
            (host_id,),
        )
        return [
            HostObservation(
                id=as_int(r["id"]),
                host_id=as_int(r["host_id"]) or 0,
                interface=as_text(r["interface"]),
                protocol=as_text(r["protocol"]),
                packets_sent=as_int(r["packets_sent"]) or 0,
                packets_received=as_int(r["packets_received"]) or 0,
                bytes_sent=as_int(r["bytes_sent"]) or 0,
                bytes_received=as_int(r["bytes_received"]) or 0,
                first_seen=as_dt(r["first_seen"]),
                last_seen=as_dt(r["last_seen"]),
                source=EvidenceSource.parse(r["source"], EvidenceSource.PYSHARK),
            )
            for r in rows
        ]

    def protocols_for_host(self, host_id: int) -> tuple[str, ...]:
        """Distinct protocols observed for a host."""
        rows = self.db.query(
            "SELECT DISTINCT protocol FROM host_observations "
            "WHERE host_id = %s AND protocol <> '' ORDER BY protocol",
            (host_id,),
        )
        return tuple(as_text(r["protocol"]) for r in rows)

    # ------------------------------------------------------------------
    # Trusted assets
    # ------------------------------------------------------------------
    def list_trusted(self) -> list[TrustedHost]:
        """Administrator-maintained trusted asset list."""
        rows = self.db.query(
            "SELECT id, ip_address, label, reason, added_by, created_at, "
            "is_active FROM trusted_hosts ORDER BY ip_address"
        )
        return [
            TrustedHost(
                id=as_int(r["id"]),
                ip_address=as_text(r["ip_address"]),
                label=as_text(r["label"]),
                reason=as_text(r["reason"]),
                added_by=as_int(r["added_by"]),
                created_at=as_dt(r["created_at"]),
                is_active=as_bool(r["is_active"]),
            )
            for r in rows
        ]

    def add_trusted(
        self, ip_address: str, label: str, reason: str, added_by: int | None
    ) -> int:
        """Add or refresh a trusted asset entry and flag the host."""
        trusted_id = self.db.insert(
            "INSERT INTO trusted_hosts (ip_address, label, reason, added_by, "
            "created_at, is_active) VALUES (%s, %s, %s, %s, %s, 1) "
            "ON DUPLICATE KEY UPDATE label = VALUES(label), "
            "reason = VALUES(reason), is_active = 1",
            (ip_address, label[:128], reason[:255], added_by, to_db(utcnow())),
        )
        host_id = self.find_id_by_ip(ip_address)
        if host_id:
            self.set_trusted(host_id, True, label)
        return trusted_id

    def remove_trusted(self, ip_address: str) -> None:
        """Deactivate a trusted asset entry and clear the host flag."""
        self.db.execute(
            "UPDATE trusted_hosts SET is_active = 0 WHERE ip_address = %s",
            (ip_address,),
        )
        host_id = self.find_id_by_ip(ip_address)
        if host_id:
            self.set_trusted(host_id, False, "")

    def trusted_addresses(self) -> set[str]:
        """Active trusted addresses, used as investigation context."""
        rows = self.db.query(
            "SELECT ip_address FROM trusted_hosts WHERE is_active = 1"
        )
        return {as_text(r["ip_address"]) for r in rows}
