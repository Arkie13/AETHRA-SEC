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
    period_bounds,
)
from aethra_sec.models.enums import (
    AssessmentState,
    EvidenceSource,
    HostStatus,
    RiskLevel,
)
from aethra_sec.models.host import (
    CONFIRMED_FINDING_SQL,
    Host,
    HostObservation,
    TrustedHost,
)
from aethra_sec.utils.timeutil import to_db, utcnow

_FILTERABLE = {
    "ip_address", "mac_address", "hostname", "os_name", "status",
    "risk_level", "discovery_source", "is_trusted", "last_seen", "first_seen",
    "assessment_state", "last_assessed_at",
}
_SORTABLE = {
    "ip_address", "hostname", "last_seen", "first_seen", "risk_level", "status",
}
_SELECT = (
    "SELECT id, ip_address, mac_address, hostname, hostname_checked_at, "
    "hostname_source, vendor, "
    "os_name, os_version, os_cpe, os_accuracy, status, risk_level, "
    "discovery_source, discovery_interface, discovery_detail, "
    "assessment_state, last_assessed_at, "
    "assessment_attempts, assessment_detail, last_attempt_at, last_scan_id, "
    "is_trusted, trust_note, first_seen, last_seen, created_at, updated_at "
    "FROM hosts"
)

#: SQL for a finding's §3.9.9 rank: its CVSS band where a real score exists,
#: otherwise the rating it was recorded with. 4 = Critical ... 0 = none/info.
_FINDING_RANK_SQL = (
    "CASE WHEN f.cvss_base_score IS NOT NULL THEN "
    "  CASE WHEN f.cvss_base_score >= 9.0 THEN 4 "
    "       WHEN f.cvss_base_score >= 7.0 THEN 3 "
    "       WHEN f.cvss_base_score >= 4.0 THEN 2 "
    "       WHEN f.cvss_base_score > 0.0 THEN 1 ELSE 0 END "
    "ELSE CASE f.risk_level WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
    "  WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END END"
)
#: Alerts naming this host at either end, counted once.
#:
#: The obvious spelling - ``src_host_id = h.id OR dst_host_id = h.id`` - cannot
#: use either foreign-key index, because an OR across two different columns
#: leaves the optimiser nothing single-column to seek on. Correlated per host
#: row, that became a full scan of snort_alerts for every row on the page:
#: measured here at 1,000 rows it read ~226,000 rows and cost 303ms of a 500ms
#: query (EXPLAIN: type=ALL, key=NULL).
#:
#: Split into one seek per column, each side uses its own index (EXPLAIN:
#: type=ref on fk_alerts_src_host and fk_alerts_dst_host). The second side
#: excludes what the first already counted, so an alert with the same host at
#: both ends is still counted once rather than twice.
_ALERT_COUNT_SQL = (
    "((SELECT COUNT(*) FROM snort_alerts a WHERE a.src_host_id = h.id)"
    " + (SELECT COUNT(*) FROM snort_alerts a WHERE a.dst_host_id = h.id"
    "    AND (a.src_host_id IS NULL OR a.src_host_id <> h.id)))"
)
_RANK_TO_RISK = {
    4: RiskLevel.CRITICAL, 3: RiskLevel.HIGH, 2: RiskLevel.MEDIUM,
    1: RiskLevel.LOW, 0: RiskLevel.INFORMATIONAL,
}


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
            hostname_source=as_text(row.get("hostname_source")),
            vendor=as_text(row.get("vendor")),
            os_name=as_text(row.get("os_name")),
            os_version=as_text(row.get("os_version")),
            os_cpe=as_text(row.get("os_cpe")),
            os_accuracy=as_int(row.get("os_accuracy")),
            status=HostStatus.parse(row.get("status"), HostStatus.UNKNOWN),
            risk_level=RiskLevel.parse(row.get("risk_level"), RiskLevel.INFORMATIONAL),
            assessment_state=AssessmentState.parse(
                row.get("assessment_state"), AssessmentState.DISCOVERED
            ),
            last_assessed_at=as_dt(row.get("last_assessed_at")),
            assessment_attempts=as_int(row.get("assessment_attempts")) or 0,
            assessment_detail=as_text(row.get("assessment_detail")),
            last_attempt_at=as_dt(row.get("last_attempt_at")),
            last_scan_id=as_int(row.get("last_scan_id")),
            # An unreadable or absent source falls back to LEGACY, not to a
            # subsystem: guessing here is exactly how a row acquires a
            # provenance nobody established.
            discovery_source=EvidenceSource.parse(
                row.get("discovery_source"), EvidenceSource.LEGACY
            ),
            discovery_interface=as_text(row.get("discovery_interface")),
            discovery_detail=as_text(row.get("discovery_detail")),
            is_trusted=as_bool(row.get("is_trusted")),
            trust_note=as_text(row.get("trust_note")),
            first_seen=as_dt(row.get("first_seen")),
            last_seen=as_dt(row.get("last_seen")),
            created_at=as_dt(row.get("created_at")),
            updated_at=as_dt(row.get("updated_at")),
            open_port_count=as_int(row.get("open_port_count")) or 0,
            alert_count=as_int(row.get("alert_count")) or 0,
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
        source: EvidenceSource,
        mac_address: str = "",
        interface: str = "",
        detail: str = "",
    ) -> int:
        """Record that a host was *observed*, creating the row if needed.

        Every caller states which subsystem observed it. There is deliberately
        no default: a silent default is how a row acquires provenance nobody
        established, and this column is the answer to "why is this address in
        AETHRA-SEC at all?".

        Call this only for a real observation - the host transmitted, or a scan
        got an answer from it. Probing an address and receiving nothing is not
        an observation, and must not move ``last_seen``.

        Args:
            source: the subsystem that observed it.
            interface: the capture interface, or the tool, it was observed on.
            detail: what established it, e.g. ``"ARP"`` or ``"scan reply"``.

        Returns:
            The host id.
        """
        stamp = to_db(observed_at)
        self.db.execute(
            "INSERT INTO hosts (ip_address, mac_address, status, "
            "discovery_source, discovery_interface, discovery_detail, "
            "first_seen, last_seen, created_at, updated_at) "
            "VALUES (%s, %s, 'UP', %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            # Evaluated before `status` below, so it still sees the stored
            # value: a host coming back from OFFLINE drops the note the
            # assessment queue left explaining that it was offline. Without
            # this the row read "Host: UP" beside "offline: not observed
            # recently" - two subsystems' answers from different moments,
            # presented as one state.
            "assessment_detail = IF(status = 'DOWN', '', assessment_detail), "
            "last_seen = GREATEST(last_seen, VALUES(last_seen)), "
            "mac_address = IF(VALUES(mac_address) = '', mac_address, VALUES(mac_address)), "
            "discovery_interface = IF(VALUES(discovery_interface) = '', "
            "  discovery_interface, VALUES(discovery_interface)), "
            "discovery_detail = IF(VALUES(discovery_detail) = '', "
            "  discovery_detail, VALUES(discovery_detail)), "
            # A legacy row whose origin was never established earns a real
            # source the moment something is genuinely observed from it.
            "discovery_source = IF(discovery_source = 'LEGACY', "
            "  VALUES(discovery_source), discovery_source), "
            # A host that put a frame on the wire is up, by definition. Restoring
            # UP here is what lets a host return from OFFLINE the moment it is
            # seen again, rather than staying OFFLINE until the next scan.
            "status = 'UP', "
            "updated_at = VALUES(updated_at)",
            (
                ip_address, mac_address, str(source), interface, detail,
                stamp, stamp, stamp, stamp,
            ),
        )
        return int(
            self.db.query_value(
                "SELECT id FROM hosts WHERE ip_address = %s", (ip_address,), default=0
            )
            or 0
        )

    def existing_addresses(self, addresses: Sequence[str]) -> set[str]:
        """Which of ``addresses`` are already in the inventory."""
        unique = list(dict.fromkeys(a for a in addresses if a))
        found: set[str] = set()
        for start in range(0, len(unique), 500):
            chunk = unique[start : start + 500]
            placeholders = ", ".join(["%s"] * len(chunk))
            rows = self.db.query(
                f"SELECT ip_address FROM hosts WHERE ip_address IN ({placeholders})",
                tuple(chunk),
            )
            found.update(as_text(row.get("ip_address")) for row in rows)
        return found

    def bulk_upsert_observed(
        self, observations: Iterable[tuple[str, str, datetime]],
        source: EvidenceSource,
        *,
        interface: str = "",
        detail: str = "",
    ) -> int:
        """Batch version of :meth:`upsert_observed`.

        Args:
            observations: ``(ip_address, mac_address, last_seen)`` triples,
                each one a host actually seen transmitting.
            source: which subsystem observed the hosts.
            interface: the capture interface they were observed on.
            detail: what established them, e.g. the protocol.

        Returns:
            Number of rows affected.
        """
        rows = []
        for ip_address, mac, seen in observations:
            stamp = to_db(seen)
            rows.append((
                ip_address, mac, str(source), interface, detail,
                stamp, stamp, stamp, stamp,
            ))
        if not rows:
            return 0
        return self.db.execute_many(
            "INSERT INTO hosts (ip_address, mac_address, status, "
            "discovery_source, discovery_interface, discovery_detail, "
            "first_seen, last_seen, created_at, updated_at) "
            "VALUES (%s, %s, 'UP', %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE "
            # See upsert_observed: this must precede `status`, so that a host
            # returning from OFFLINE drops the queue's stale offline note.
            "assessment_detail = IF(status = 'DOWN', '', assessment_detail), "
            "last_seen = GREATEST(last_seen, VALUES(last_seen)), "
            "mac_address = IF(VALUES(mac_address) = '', mac_address, VALUES(mac_address)), "
            "discovery_interface = IF(VALUES(discovery_interface) = '', "
            "  discovery_interface, VALUES(discovery_interface)), "
            "discovery_detail = IF(VALUES(discovery_detail) = '', "
            "  discovery_detail, VALUES(discovery_detail)), "
            "discovery_source = IF(discovery_source = 'LEGACY', "
            "  VALUES(discovery_source), discovery_source), "
            # A host seen transmitting is up; this returns it from OFFLINE.
            "status = 'UP', "
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
        os_version: str | None = None,
        os_cpe: str | None = None,
        os_accuracy: int | None = None,
        status: HostStatus | None = None,
    ) -> None:
        """Update identity fields discovered by a scan.

        Only non-``None`` arguments are written, so a later scan that could not
        determine the OS does not erase a value an earlier scan found.

        The operating system is written separately and only when it is at
        least as well established as what is already stored. Answers now
        arrive with very different confidence behind them - a raw-socket
        fingerprint, a service banner, a reply TTL - and without the guard an
        unprivileged re-scan would quietly replace a measured fingerprint with
        a hop-count inference. The inventory keeps the best answer anyone has
        obtained, not the most recent one.
        """
        assignments: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("hostname", hostname),
            ("mac_address", mac_address),
            ("vendor", vendor),
        ):
            if value is not None and value != "":
                assignments.append(f"{column} = %s")
                params.append(value)
        if status is not None:
            assignments.append("status = %s")
            params.append(str(status))
        if assignments:
            assignments.append("updated_at = %s")
            params.extend([to_db(utcnow()), host_id])
            self.db.execute(
                f"UPDATE hosts SET {', '.join(assignments)} WHERE id = %s", params
            )
        self._update_os(
            host_id,
            os_name=os_name,
            os_version=os_version,
            os_cpe=os_cpe,
            os_accuracy=os_accuracy,
        )

    def _update_os(
        self,
        host_id: int,
        *,
        os_name: str | None,
        os_version: str | None,
        os_cpe: str | None,
        os_accuracy: int | None,
    ) -> None:
        """Store an OS result only if it improves on what is already known.

        The whole OS group is written together: a name, its version and its
        CPE describe one conclusion, and mixing a new name with a previous
        conclusion's CPE would produce a record no scan ever reported.
        """
        if not os_name:
            return
        confidence = int(os_accuracy or 0)
        self.db.execute(
            "UPDATE hosts SET os_name = %s, os_version = %s, os_cpe = %s, "
            "os_accuracy = %s, updated_at = %s "
            "WHERE id = %s AND (os_name = '' OR COALESCE(os_accuracy, 0) <= %s)",
            (
                os_name,
                os_version or "",
                os_cpe or "",
                os_accuracy,
                to_db(utcnow()),
                host_id,
                confidence,
            ),
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
            f"{_ALERT_COUNT_SQL} AS alert_count, "
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
        """Hosts seen since a point in time (drives 'Active hosts').

        Current state - "what is live on the network now" - so it keeps its own
        trailing recency window and is not bounded by a reporting period.
        """
        return self.count(
            "SELECT COUNT(*) FROM hosts WHERE last_seen >= %s", (to_db(since),)
        )

    def assessment_candidates(
        self,
        limit: int = 200,
        *,
        ranges: Sequence[tuple[int, int]] | None = None,
    ) -> list[Host]:
        """Hosts worth considering for assessment, most recently seen first.

        Deliberately does *not* decide eligibility - that is policy and lives
        in the service. This only narrows the inventory to rows that could
        plausibly be due, so a cycle does not read thousands of hosts to reject
        nearly all of them.

        Args:
            ranges: integer IPv4 bounds of the automatic assessment scope. Only
                hosts inside them are returned, selected in SQL, so an address
                outside the monitored network is never even read by the cycle.
                A SKIPPED host inside the scope *is* returned: it may have been
                skipped under an earlier, narrower scope and deserves to be
                re-decided rather than left out forever. ``None`` keeps the
                historical behaviour of not filtering by address.
        """
        bounded = max(1, min(int(limit), 2000))
        if ranges is None:
            rows = self.db.query(
                f"{_SELECT} WHERE assessment_state NOT IN ('SCANNING', 'SKIPPED') "
                "ORDER BY last_seen DESC LIMIT %s",
                (bounded,),
            )
            return self._map_all(rows, self._map)
        if not ranges:
            return []
        clauses = " OR ".join(
            "(INET_ATON(ip_address) BETWEEN %s AND %s)" for _ in ranges
        )
        params: list[Any] = [value for pair in ranges for value in pair]
        rows = self.db.query(
            f"{_SELECT} WHERE assessment_state <> 'SCANNING' "
            "AND ip_address NOT LIKE '%%:%%' "
            f"AND ({clauses}) ORDER BY last_seen DESC LIMIT %s",
            (*params, bounded),
        )
        return self._map_all(rows, self._map)

    def set_assessment_state(
        self,
        host_id: int,
        state: AssessmentState,
        *,
        assessed: bool = False,
        attempt: bool = False,
        scan_id: int | None = None,
        detail: str | None = None,
        attempt_started: bool = False,
    ) -> None:
        """Record where a host stands in the assessment cycle.

        ``assessed`` stamps the completion time, which is what the cooldown is
        measured from; ``attempt`` increments the failure counter that
        eventually stops a host being retried forever. Neither is inferred
        from the state, because a host can reach COMPLETED without this call
        being the one that finished it.

        ``detail`` stores why the host is in this state; ``attempt_started``
        stamps when automation started an attempt, which the retry back-off is
        measured from.
        """
        sets = ["assessment_state = %s", "updated_at = %s"]
        params: list[Any] = [str(state), to_db(utcnow())]
        if assessed:
            sets.append("last_assessed_at = %s")
            params.append(to_db(utcnow()))
            sets.append("assessment_attempts = 0")
        if attempt:
            sets.append("assessment_attempts = assessment_attempts + 1")
        if attempt_started:
            sets.append("last_attempt_at = %s")
            params.append(to_db(utcnow()))
        if detail is not None:
            sets.append("assessment_detail = %s")
            params.append(detail[:255])
        if scan_id is not None:
            sets.append("last_scan_id = %s")
            params.append(int(scan_id))
        params.append(host_id)
        self.db.execute(
            f"UPDATE hosts SET {', '.join(sets)} WHERE id = %s", params
        )

    def record_scan_result(self, host_id: int, scan_id: int) -> None:
        """Point a host at the scan that just produced its results.

        Called when a scan persists a live host, so a host assessed by *any*
        scan - manual or automatic - shows its real result in the automatic
        table, and the cooldown is measured from a real assessment.

        Guarded on ``assessment_state <> 'SCANNING'`` so it never races the
        automatic queue: a host the queue marked SCANNING is settled by the
        queue's own reap (which frees its concurrency slot), and this leaves it
        untouched rather than settling it early and stranding the slot.
        """
        if not host_id or not scan_id:
            return
        self.db.execute(
            "UPDATE hosts SET last_scan_id = %s, last_assessed_at = %s, "
            "assessment_state = %s, assessment_attempts = 0, updated_at = %s "
            "WHERE id = %s AND assessment_state <> %s",
            (
                int(scan_id),
                to_db(utcnow()),
                str(AssessmentState.COMPLETED),
                to_db(utcnow()),
                host_id,
                str(AssessmentState.SCANNING),
            ),
        )

    def assessment_state_counts(self) -> dict[str, int]:
        """How many hosts sit in each assessment state."""
        rows = self.db.query(
            "SELECT assessment_state AS state, COUNT(*) AS c FROM hosts "
            "GROUP BY assessment_state"
        )
        return {as_text(r["state"]): as_int(r["c"]) or 0 for r in rows}

    def last_assessment_time(self) -> datetime | None:
        """When a host was most recently assessed."""
        return as_dt(self.db.query_value("SELECT MAX(last_assessed_at) FROM hosts"))

    def last_discovery_time(self) -> datetime | None:
        """When a host was most recently seen for the first time."""
        return as_dt(self.db.query_value("SELECT MAX(first_seen) FROM hosts"))

    def reset_stuck_assessments(self) -> int:
        """Release hosts left SCANNING by a process that did not finish.

        A crash or a forced shutdown mid-scan leaves the row claiming a scan is
        running that no longer is. Without this they would never be assessed
        again, because a SCANNING host is skipped as already in progress.
        """
        return self.db.execute(
            "UPDATE hosts SET assessment_state = %s, updated_at = %s "
            "WHERE assessment_state = %s",
            (str(AssessmentState.DISCOVERED), to_db(utcnow()),
             str(AssessmentState.SCANNING)),
        )

    def record_announced_hostname(
        self, ip_address: str, hostname: str, source: str
    ) -> bool:
        """Store a name a device published about itself, with its source.

        First-party evidence: the device stated this name on the wire, which
        is stronger than any lookup of it. It is written for an address the
        inventory already holds - a name is not a reason to enrol a host, only
        to identify one that is already there for a reason of its own.

        The write is conditional so a device announcing every few seconds does
        not generate an UPDATE per frame; only a change is written.

        Returns:
            True when a row was actually changed.
        """
        if not ip_address or not hostname:
            return False
        return bool(
            self.db.execute(
                "UPDATE hosts SET hostname = %s, hostname_source = %s, "
                "hostname_checked_at = %s, updated_at = %s "
                "WHERE ip_address = %s "
                "AND (hostname <> %s OR hostname_source <> %s)",
                (
                    hostname[:190], source[:64], to_db(utcnow()), to_db(utcnow()),
                    ip_address, hostname[:190], source[:64],
                ),
            )
        )

    def mark_stale_offline(self, not_seen_since: datetime) -> int:
        """Mark hosts not observed since ``not_seen_since`` as OFFLINE (§20).

        Sets ``status`` to DOWN for hosts whose ``last_seen`` predates the
        cutoff and are not already DOWN. Nothing else is touched: ``first_seen``,
        ``last_seen``, the assessment state and every stored assessment and
        finding are retained. A host returns to UP through
        :meth:`upsert_observed` the moment it is seen transmitting again.

        Returns:
            How many hosts were transitioned to OFFLINE.
        """
        return self.db.execute(
            "UPDATE hosts SET status = %s, updated_at = %s "
            "WHERE last_seen < %s AND status <> %s",
            (
                str(HostStatus.DOWN),
                to_db(utcnow()),
                to_db(not_seen_since),
                str(HostStatus.DOWN),
            ),
        )

    def count_vulnerable(self) -> int:
        """Hosts classified VULNERABLE under §3.9.9.

        A host is vulnerable when at least one unresolved finding is rated High
        or Critical - by its CVSS v3.1 band where a real score exists,
        otherwise by the rating it was recorded with. It is a real count of
        hosts against which an assessment recorded such a finding, never an
        inference from a state name. It matches the VULNERABLE rows of
        :meth:`assessment_overview`, which apply the same rank.
        """
        return self.count(
            "SELECT COUNT(DISTINCT host_id) FROM scan_findings f "
            "WHERE f.resolved_at IS NULL AND f.host_id IS NOT NULL "
            f"AND ({_FINDING_RANK_SQL}) >= 3"
        )

    def assessment_summary_hosts(self) -> list[Host]:
        """Every host with just the facts its security result depends on.

        Uncapped and lean on purpose. The Vulnerability Assessment tiles and
        the Dashboard both count from this, so neither can be truncated by a
        display limit - a tile once read "DISCOVERED HOSTS 1000" on an
        inventory of 2,002 because it counted the rows a capped table loaded.
        Aggregates are joined once per query rather than as a subquery per row.
        """
        rows = self.db.query(
            "SELECT h.id, h.ip_address, h.status, h.assessment_state, "
            "h.last_assessed_at, h.assessment_attempts, h.assessment_detail, "
            "h.last_attempt_at, h.last_scan_id, h.first_seen, h.last_seen, "
            "s.status AS last_scan_status, s.hosts_up AS last_scan_hosts_up, "
            "COALESCE(fx.finding_count, 0) AS finding_count, "
            "fx.highest_rank AS highest_rank, fx.highest_cvss AS highest_cvss, "
            "COALESCE(fx.scored, 0) AS scored_finding_count, "
            "COALESCE(fx.confirmed, 0) AS confirmed_finding_count "
            "FROM hosts h "
            "LEFT JOIN scans s ON s.id = h.last_scan_id "
            "LEFT JOIN ("
            "  SELECT f.host_id, COUNT(*) AS finding_count, "
            f"  MAX({_FINDING_RANK_SQL}) AS highest_rank, "
            "  MAX(f.cvss_base_score) AS highest_cvss, "
            "  SUM(f.cvss_base_score IS NOT NULL) AS scored, "
            # Exposure is not vulnerability: only a finding the scanner can
            # point evidence at counts here. See is_confirmed_vulnerability.
            f"  SUM({CONFIRMED_FINDING_SQL}) AS confirmed "
            "  FROM scan_findings f WHERE f.resolved_at IS NULL "
            "  AND f.host_id IS NOT NULL GROUP BY f.host_id"
            ") fx ON fx.host_id = h.id"
        )
        hosts: list[Host] = []
        for row in rows:
            host = self._map(row)
            self._apply_assessment_facts(host, row)
            hosts.append(host)
        return hosts

    @staticmethod
    def _with_ranges(where: str, ranges: Sequence[tuple[int, int]] | None) -> str:
        """Append an IPv4 range restriction to a WHERE clause."""
        if ranges is None:
            return where
        if not ranges:
            clause = "1 = 0"
        else:
            clause = "h.ip_address NOT LIKE '%%:%%' AND (" + " OR ".join(
                "(INET_ATON(h.ip_address) BETWEEN %s AND %s)" for _ in ranges
            ) + ")"
        if where.strip():
            return f"{where} AND {clause}"
        return f"WHERE {clause}"

    @staticmethod
    def _apply_assessment_facts(host: Host, row: dict[str, Any]) -> None:
        """Copy the joined scan and finding facts onto a mapped host."""
        host.last_scan_status = as_text(row.get("last_scan_status"))
        host.last_scan_hosts_up = as_int(row.get("last_scan_hosts_up"))
        host.last_scan_finished_at = as_dt(row.get("last_scan_finished_at"))
        rank = as_int(row.get("highest_rank"))
        host.highest_finding = _RANK_TO_RISK.get(rank) if rank is not None else None
        cvss = row.get("highest_cvss")
        host.highest_cvss = float(cvss) if cvss is not None else None
        host.scored_finding_count = as_int(row.get("scored_finding_count")) or 0
        host.confirmed_finding_count = (
            as_int(row.get("confirmed_finding_count")) or 0
        )

    def assessment_overview(
        self,
        *,
        text: str = "",
        limit: int = 1000,
        ranges: Sequence[tuple[int, int]] | None = None,
    ) -> list[Host]:
        """Every host with the facts the automatic-assessment table shows.

        ``ranges`` restricts the rows to integer IPv4 bounds in SQL - the
        monitored authorised network - so a display limit is applied *after*
        scoping and can never push an in-scope host off the table in favour of
        a more recently contacted address outside it.

        Returns hosts joined to their derived counters and to their most recent
        scan, so a caller can render the three separate concepts the interface
        keeps apart - host status, assessment status and security result -
        without a query per row. The security result itself is derived on the
        :class:`~aethra_sec.models.host.Host`, from these fields, so the count
        and the label can never disagree.

        Nothing here is invented: ``last_scan_status`` and ``last_scan_hosts_up``
        come from the scan row the host's ``last_scan_id`` points at, and are
        left empty when the host has never been scanned.
        """
        query = QueryFilter(_FILTERABLE, prefix="h")
        query.any_of(("ip_address", "hostname", "mac_address", "os_name"), text)
        limit_sql, limit_params = limit_clause(max(1, min(int(limit), 5000)), 0)
        sql = (
            "SELECT h.*, "
            "s.status AS last_scan_status, s.hosts_up AS last_scan_hosts_up, "
            "s.finished_at AS last_scan_finished_at, "
            f"{_ALERT_COUNT_SQL} AS alert_count, "
            "(SELECT COUNT(*) FROM scan_findings f "
            "  WHERE f.host_id = h.id AND f.resolved_at IS NULL) AS finding_count, "
            f"(SELECT MAX({_FINDING_RANK_SQL}) FROM scan_findings f "
            "  WHERE f.host_id = h.id AND f.resolved_at IS NULL) AS highest_rank, "
            "(SELECT MAX(f.cvss_base_score) FROM scan_findings f "
            "  WHERE f.host_id = h.id AND f.resolved_at IS NULL) AS highest_cvss, "
            "(SELECT COUNT(f.cvss_base_score) FROM scan_findings f "
            "  WHERE f.host_id = h.id AND f.resolved_at IS NULL) "
            "  AS scored_finding_count, "
            "(SELECT COUNT(*) FROM scan_findings f "
            "  WHERE f.host_id = h.id AND f.resolved_at IS NULL "
            f"  AND ({CONFIRMED_FINDING_SQL})) AS confirmed_finding_count, "
            "(SELECT COUNT(DISTINCT p.port) FROM ports p "
            "  JOIN scan_hosts sh ON sh.id = p.scan_host_id "
            "  WHERE sh.host_id = h.id AND p.state = 'open') AS open_port_count, "
            "(SELECT COALESCE(SUM(o.packets_sent + o.packets_received), 0) "
            "  FROM host_observations o WHERE o.host_id = h.id) AS packet_count "
            "FROM hosts h LEFT JOIN scans s ON s.id = h.last_scan_id "
            f"{self._with_ranges(query.where_clause(), ranges)} "
            f"ORDER BY h.last_seen DESC {limit_sql}"
        )
        range_params = [v for pair in (ranges or ()) for v in pair]
        rows = self.db.query(
            sql, (*query.bound_params(), *range_params, *limit_params)
        )
        hosts: list[Host] = []
        for row in rows:
            host = self._map(row)
            self._apply_assessment_facts(host, row)
            hosts.append(host)
        return hosts

    def count_seen_in_period(
        self, start: datetime | None, end: datetime | None = None
    ) -> int:
        """Hosts observed inside ``[start, end)``.

        Bounded on ``last_seen``: a host counts for the period if it was seen
        during it. This is the period counterpart to
        :meth:`count_active_since`, and unlike that figure it genuinely returns
        to zero when a new day begins with no traffic yet.
        """
        clauses, params = period_bounds("last_seen", start, end)
        return self.count(f"SELECT COUNT(*) FROM hosts {clauses}", params)

    def count_first_seen_in_period(
        self, start: datetime | None, end: datetime | None = None
    ) -> int:
        """Hosts *discovered* inside ``[start, end)`` - seen for the first
        time, rather than merely seen again."""
        clauses, params = period_bounds("first_seen", start, end)
        return self.count(f"SELECT COUNT(*) FROM hosts {clauses}", params)

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
