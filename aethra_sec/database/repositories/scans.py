"""Nmap scan, port and finding persistence (§18, §45)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aethra_sec.database.repositories.base import (
    QueryFilter,
    Repository,
    as_bool,
    as_dt,
    as_float,
    as_int,
    as_text,
    limit_clause,
    order_clause,
)
from aethra_sec.models.enums import (
    EvidenceSource,
    HostStatus,
    RiskLevel,
    ScanStatus,
)
from aethra_sec.models.scan import (
    PortResult,
    Scan,
    ScanComparison,
    ScanFinding,
    ScanHostResult,
)
from aethra_sec.utils.timeutil import to_db, utcnow

_SCAN_SORTABLE = {"created_at", "started_at", "finished_at", "target", "status", "id"}
_SCAN_FILTERABLE = {"status", "target", "profile", "initiated_by", "created_at"}
_FINDING_FILTERABLE = {
    "risk_level", "ip_address", "service", "protocol", "port", "created_at",
    "resolved_at", "scan_id", "host_id", "title",
}
_FINDING_SORTABLE = {"created_at", "risk_level", "ip_address", "port", "id"}

_SCAN_SELECT = (
    "SELECT s.id, s.target, s.target_kind, s.profile, s.profile_label, "
    "s.port_spec, s.timing, s.arguments, s.status, s.started_at, s.finished_at, "
    "s.duration_seconds, s.hosts_total, s.hosts_up, s.open_ports, "
    "s.findings_count, s.error_message, s.nmap_version, s.command_line, "
    "s.initiated_by, s.created_at, u.username AS initiated_by_username "
    "FROM scans s LEFT JOIN users u ON u.id = s.initiated_by"
)

_FINDING_SELECT = (
    "SELECT id, scan_id, scan_host_id, host_id, ip_address, port, protocol, "
    "service, title, observation, concern, risk_level, risk_rationale, "
    "evidence, reference_id, reference_source, verification_required, source, "
    "resolved_at, created_at FROM scan_findings"
)


class ScanRepository(Repository):
    """Persists assessment runs and their real results."""

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------
    @staticmethod
    def _map_scan(row: dict[str, Any]) -> Scan:
        """Map a joined scan row to :class:`Scan`."""
        return Scan(
            id=as_int(row.get("id")),
            target=as_text(row.get("target")),
            target_kind=as_text(row.get("target_kind")),
            profile=as_text(row.get("profile")),
            profile_label=as_text(row.get("profile_label")),
            port_spec=as_text(row.get("port_spec")),
            timing=as_text(row.get("timing")),
            arguments=as_text(row.get("arguments")),
            status=ScanStatus.parse(row.get("status"), ScanStatus.QUEUED),
            started_at=as_dt(row.get("started_at")),
            finished_at=as_dt(row.get("finished_at")),
            duration_seconds=as_float(row.get("duration_seconds")),
            hosts_total=as_int(row.get("hosts_total")) or 0,
            hosts_up=as_int(row.get("hosts_up")) or 0,
            open_ports=as_int(row.get("open_ports")) or 0,
            findings_count=as_int(row.get("findings_count")) or 0,
            error_message=as_text(row.get("error_message")),
            nmap_version=as_text(row.get("nmap_version")),
            command_line=as_text(row.get("command_line")),
            initiated_by=as_int(row.get("initiated_by")),
            initiated_by_username=as_text(row.get("initiated_by_username")),
            created_at=as_dt(row.get("created_at")),
        )

    @staticmethod
    def _map_port(row: dict[str, Any]) -> PortResult:
        """Map a row to :class:`PortResult`."""
        return PortResult(
            id=as_int(row.get("id")),
            scan_host_id=as_int(row.get("scan_host_id")),
            port=as_int(row.get("port")) or 0,
            protocol=as_text(row.get("protocol")),
            state=as_text(row.get("state")),
            service=as_text(row.get("service")),
            product=as_text(row.get("product")),
            version=as_text(row.get("version")),
            extra_info=as_text(row.get("extra_info")),
            cpe=as_text(row.get("cpe")),
            reason=as_text(row.get("reason")),
            tunnel=as_text(row.get("tunnel")),
        )

    @staticmethod
    def _map_finding(row: dict[str, Any]) -> ScanFinding:
        """Map a row to :class:`ScanFinding`."""
        return ScanFinding(
            id=as_int(row.get("id")),
            scan_id=as_int(row.get("scan_id")),
            scan_host_id=as_int(row.get("scan_host_id")),
            host_id=as_int(row.get("host_id")),
            ip_address=as_text(row.get("ip_address")),
            port=as_int(row.get("port")),
            protocol=as_text(row.get("protocol")),
            service=as_text(row.get("service")),
            title=as_text(row.get("title")),
            observation=as_text(row.get("observation")),
            concern=as_text(row.get("concern")),
            risk_level=RiskLevel.parse(row.get("risk_level"), RiskLevel.INFORMATIONAL),
            risk_rationale=as_text(row.get("risk_rationale")),
            evidence=as_text(row.get("evidence")),
            reference=as_text(row.get("reference_id")),
            reference_source=as_text(row.get("reference_source")),
            verification_required=as_bool(row.get("verification_required")),
            source=EvidenceSource.parse(row.get("source"), EvidenceSource.NMAP),
            resolved_at=as_dt(row.get("resolved_at")),
            created_at=as_dt(row.get("created_at")),
        )

    @staticmethod
    def _map_scan_host(row: dict[str, Any]) -> ScanHostResult:
        """Map a row to :class:`ScanHostResult`.

        A scan row records what *that run* observed, which is often less than
        the inventory already knows: a discovery sweep resolves no hostname, an
        unprivileged scan attempts no OS fingerprint. Where the scan row is
        empty the value the inventory holds for the same host is used instead,
        so the results show what has genuinely been observed about the device
        rather than a dash. Both come from real observations; nothing is
        invented, and a value the scan did record is never overwritten.
        """
        return ScanHostResult(
            id=as_int(row.get("id")),
            scan_id=as_int(row.get("scan_id")),
            host_id=as_int(row.get("host_id")),
            ip_address=as_text(row.get("ip_address")),
            hostname=as_text(row.get("hostname")) or as_text(row.get("known_hostname")),
            mac_address=(
                as_text(row.get("mac_address")) or as_text(row.get("known_mac"))
            ),
            vendor=as_text(row.get("vendor")) or as_text(row.get("known_vendor")),
            status=HostStatus.parse(row.get("status"), HostStatus.UNKNOWN),
            os_name=as_text(row.get("os_name")) or as_text(row.get("known_os_name")),
            os_accuracy=(
                as_int(row.get("os_accuracy"))
                if as_text(row.get("os_name"))
                else as_int(row.get("known_os_accuracy"))
            ),
            os_family=as_text(row.get("os_family")),
        )

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def create_scan(self, scan: Scan) -> int:
        """Insert a queued scan and return its id."""
        return self.db.insert(
            "INSERT INTO scans (target, target_kind, profile, profile_label, "
            "port_spec, timing, arguments, status, initiated_by, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                scan.target[:255], scan.target_kind[:16], scan.profile[:32],
                scan.profile_label[:96], scan.port_spec[:255], scan.timing[:8],
                scan.arguments[:512], str(scan.status), scan.initiated_by,
                to_db(scan.created_at or utcnow()),
            ),
        )

    def mark_running(self, scan_id: int, command_line: str, nmap_version: str) -> None:
        """Record that the Nmap process actually started."""
        self.db.execute(
            "UPDATE scans SET status = 'RUNNING', started_at = %s, "
            "command_line = %s, nmap_version = %s WHERE id = %s",
            (to_db(utcnow()), command_line[:512], nmap_version[:64], scan_id),
        )

    def mark_completed(
        self,
        scan_id: int,
        *,
        hosts_total: int,
        hosts_up: int,
        open_ports: int,
        findings_count: int,
        duration_seconds: float,
    ) -> None:
        """Record real result counts for a finished scan."""
        self.db.execute(
            "UPDATE scans SET status = 'COMPLETED', finished_at = %s, "
            "duration_seconds = %s, hosts_total = %s, hosts_up = %s, "
            "open_ports = %s, findings_count = %s WHERE id = %s",
            (
                to_db(utcnow()), round(duration_seconds, 3), hosts_total,
                hosts_up, open_ports, findings_count, scan_id,
            ),
        )

    def mark_failed(self, scan_id: int, error: str) -> None:
        """Record a scan failure with the real error text."""
        self.db.execute(
            "UPDATE scans SET status = 'FAILED', finished_at = %s, "
            "error_message = %s WHERE id = %s",
            (to_db(utcnow()), error[:512], scan_id),
        )

    def mark_cancelled(self, scan_id: int) -> None:
        """Record that the operator stopped the scan."""
        self.db.execute(
            "UPDATE scans SET status = 'CANCELLED', finished_at = %s WHERE id = %s",
            (to_db(utcnow()), scan_id),
        )

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def add_scan_host(self, scan_id: int, host: ScanHostResult) -> int:
        """Insert one host result and return its row id."""
        return self.db.insert(
            "INSERT INTO scan_hosts (scan_id, host_id, ip_address, hostname, "
            "mac_address, vendor, status, os_name, os_accuracy, os_family) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE hostname = VALUES(hostname), "
            "mac_address = VALUES(mac_address), status = VALUES(status), "
            "os_name = VALUES(os_name), os_accuracy = VALUES(os_accuracy)",
            (
                scan_id, host.host_id, host.ip_address[:45], host.hostname[:190],
                host.mac_address[:17], host.vendor[:128], str(host.status),
                host.os_name[:190], host.os_accuracy, host.os_family[:96],
            ),
        )

    def add_ports(self, scan_host_id: int, ports: list[PortResult]) -> int:
        """Batch-insert the ports reported for one host."""
        if not ports:
            return 0
        return self.db.execute_many(
            "INSERT INTO ports (scan_host_id, port, protocol, state, service, "
            "product, version, extra_info, cpe, reason, tunnel) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE state = VALUES(state), "
            "service = VALUES(service), product = VALUES(product), "
            "version = VALUES(version), extra_info = VALUES(extra_info)",
            [
                (
                    scan_host_id, p.port, p.protocol[:8], p.state[:16],
                    p.service[:64], p.product[:128], p.version[:128],
                    p.extra_info[:255], p.cpe[:255], p.reason[:64], p.tunnel[:32],
                )
                for p in ports
            ],
        )

    def add_findings(self, findings: list[ScanFinding]) -> int:
        """Batch-insert derived security findings."""
        if not findings:
            return 0
        now = to_db(utcnow())
        return self.db.execute_many(
            "INSERT INTO scan_findings (scan_id, scan_host_id, host_id, "
            "ip_address, port, protocol, service, title, observation, concern, "
            "risk_level, risk_rationale, evidence, reference_id, "
            "reference_source, verification_required, source, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s)",
            [
                (
                    f.scan_id, f.scan_host_id, f.host_id, f.ip_address[:45],
                    f.port, f.protocol[:8], f.service[:64], f.title[:190],
                    f.observation, f.concern, str(f.risk_level),
                    f.risk_rationale, f.evidence, f.reference[:64],
                    f.reference_source[:64],
                    1 if f.verification_required else 0, str(f.source), now,
                )
                for f in findings
            ],
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get_scan(self, scan_id: int) -> Scan | None:
        """Fetch one scan without its host results."""
        row = self.db.query_one(f"{_SCAN_SELECT} WHERE s.id = %s", (scan_id,))
        return self._map_scan(row) if row else None

    def get_scan_with_results(self, scan_id: int) -> Scan | None:
        """Fetch one scan with hosts, ports and findings attached."""
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        host_rows = self.db.query(
            "SELECT sh.id, sh.scan_id, sh.host_id, sh.ip_address, sh.hostname, "
            "sh.mac_address, sh.vendor, sh.status, sh.os_name, sh.os_accuracy, "
            "sh.os_family, h.hostname AS known_hostname, "
            "h.mac_address AS known_mac, h.vendor AS known_vendor, "
            "h.os_name AS known_os_name, h.os_accuracy AS known_os_accuracy "
            "FROM scan_hosts sh LEFT JOIN hosts h ON h.id = sh.host_id "
            "WHERE sh.scan_id = %s "
            "ORDER BY INET_ATON(sh.ip_address), sh.ip_address",
            (scan_id,),
        )
        hosts = self._map_all(host_rows, self._map_scan_host)
        findings = self.findings_for_scan(scan_id)
        for host in hosts:
            host.ports = self.ports_for_scan_host(int(host.id or 0))
            host.findings = [f for f in findings if f.scan_host_id == host.id]
        scan.hosts = hosts
        return scan

    def ports_for_scan_host(self, scan_host_id: int) -> list[PortResult]:
        """All ports recorded for one scanned host."""
        rows = self.db.query(
            "SELECT id, scan_host_id, port, protocol, state, service, product, "
            "version, extra_info, cpe, reason, tunnel FROM ports "
            "WHERE scan_host_id = %s ORDER BY protocol, port",
            (scan_host_id,),
        )
        return self._map_all(rows, self._map_port)

    def findings_for_scan(self, scan_id: int) -> list[ScanFinding]:
        """All findings derived from one scan."""
        rows = self.db.query(
            f"{_FINDING_SELECT} WHERE scan_id = %s "
            "ORDER BY FIELD(risk_level,'CRITICAL','HIGH','MEDIUM','LOW',"
            "'INFORMATIONAL'), ip_address, port",
            (scan_id,),
        )
        return self._map_all(rows, self._map_finding)

    def findings_for_host(self, host_id: int, limit: int = 200) -> list[ScanFinding]:
        """Findings recorded against one inventory host."""
        rows = self.db.query(
            f"{_FINDING_SELECT} WHERE host_id = %s ORDER BY created_at DESC LIMIT %s",
            (host_id, max(1, min(int(limit), 2000))),
        )
        return self._map_all(rows, self._map_finding)

    def search_findings(
        self,
        *,
        text: str = "",
        risk_level: str = "",
        ip_address: str = "",
        service: str = "",
        unresolved_only: bool = False,
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "created_at",
        sort_dir: str = "DESC",
        limit: int = 500,
        offset: int = 0,
    ) -> list[ScanFinding]:
        """Search derived findings."""
        query = QueryFilter(_FINDING_FILTERABLE)
        query.equals("risk_level", risk_level)
        query.equals("ip_address", ip_address)
        query.equals("service", service)
        query.gte("created_at", to_db(start))
        query.lte("created_at", to_db(end))
        if unresolved_only:
            query.is_null("resolved_at", True)
        query.any_of(("title", "ip_address", "service", "observation"), text)
        order = order_clause(sort_by, sort_dir, _FINDING_SORTABLE, "created_at")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_FINDING_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map_finding)

    def search_scans(
        self,
        *,
        text: str = "",
        status: str = "",
        initiated_by: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        sort_by: str = "created_at",
        sort_dir: str = "DESC",
        limit: int = 200,
        offset: int = 0,
    ) -> list[Scan]:
        """Search scan history."""
        query = QueryFilter(_SCAN_FILTERABLE, prefix="s")
        query.equals("status", status)
        query.equals("initiated_by", initiated_by)
        query.gte("created_at", to_db(start))
        query.lte("created_at", to_db(end))
        query.any_of(("target", "profile"), text)
        order = order_clause(sort_by, sort_dir, _SCAN_SORTABLE, "created_at", "s")
        limit_sql, limit_params = limit_clause(limit, offset)
        rows = self.db.query(
            f"{_SCAN_SELECT} {query.where_clause()} {order} {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map_scan)

    def latest_scans_for_target(self, target: str, limit: int = 10) -> list[Scan]:
        """Completed scans of one target, newest first (for comparison)."""
        rows = self.db.query(
            f"{_SCAN_SELECT} WHERE s.target = %s AND s.status = 'COMPLETED' "
            "ORDER BY s.finished_at DESC LIMIT %s",
            (target, max(1, min(int(limit), 100))),
        )
        return self._map_all(rows, self._map_scan)

    def resolve_finding(self, finding_id: int) -> None:
        """Mark a finding as resolved (evidence is retained, not deleted)."""
        self.db.execute(
            "UPDATE scan_findings SET resolved_at = %s WHERE id = %s",
            (to_db(utcnow()), finding_id),
        )

    def reopen_finding(self, finding_id: int) -> None:
        """Clear a finding's resolved timestamp."""
        self.db.execute(
            "UPDATE scan_findings SET resolved_at = NULL WHERE id = %s", (finding_id,)
        )

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------
    def count_scans(self) -> int:
        """Total scans recorded."""
        return self.count("SELECT COUNT(*) FROM scans")

    def count_open_findings(self) -> int:
        """Findings not yet marked resolved."""
        return self.count(
            "SELECT COUNT(*) FROM scan_findings WHERE resolved_at IS NULL"
        )

    def count_findings_by_risk(self) -> dict[str, int]:
        """Open finding counts by risk level."""
        rows = self.db.query(
            "SELECT risk_level, COUNT(*) AS c FROM scan_findings "
            "WHERE resolved_at IS NULL GROUP BY risk_level"
        )
        return {as_text(r["risk_level"]): as_int(r["c"]) or 0 for r in rows}

    def count_open_ports(self) -> int:
        """Distinct open ports across the most recent scan of each host."""
        return self.count(
            "SELECT COUNT(*) FROM ports p "
            "JOIN scan_hosts sh ON sh.id = p.scan_host_id "
            "WHERE p.state = 'open' AND sh.id IN ("
            "  SELECT MAX(sh2.id) FROM scan_hosts sh2 GROUP BY sh2.ip_address"
            ")"
        )

    def last_scan_time(self) -> datetime | None:
        """Timestamp of the most recent completed scan."""
        value = self.db.query_value(
            "SELECT MAX(finished_at) FROM scans WHERE status = 'COMPLETED'"
        )
        return as_dt(value)

    def open_ports_for_host(self, host_id: int) -> list[PortResult]:
        """Open ports from the most recent scan that included this host."""
        row = self.db.query_one(
            "SELECT id FROM scan_hosts WHERE host_id = %s ORDER BY id DESC LIMIT 1",
            (host_id,),
        )
        if not row:
            return []
        return [p for p in self.ports_for_scan_host(int(row["id"])) if p.is_open]

    def scans_for_host(self, host_id: int, limit: int = 20) -> list[Scan]:
        """Scans that included a given host."""
        rows = self.db.query(
            f"{_SCAN_SELECT} JOIN scan_hosts sh ON sh.scan_id = s.id "
            "WHERE sh.host_id = %s ORDER BY s.created_at DESC LIMIT %s",
            (host_id, max(1, min(int(limit), 200))),
        )
        return self._map_all(rows, self._map_scan)

    # ------------------------------------------------------------------
    # Comparison (§45)
    # ------------------------------------------------------------------
    def compare_scans(self, baseline_id: int, current_id: int) -> ScanComparison:
        """Diff two scans of the same target using only stored results."""
        def port_map(scan_id: int) -> dict[tuple[str, int, str], tuple[str, str]]:
            rows = self.db.query(
                "SELECT sh.ip_address, p.port, p.protocol, p.state, p.service, "
                "p.product, p.version FROM ports p "
                "JOIN scan_hosts sh ON sh.id = p.scan_host_id "
                "WHERE sh.scan_id = %s",
                (scan_id,),
            )
            return {
                (
                    as_text(r["ip_address"]),
                    as_int(r["port"]) or 0,
                    as_text(r["protocol"]),
                ): (
                    as_text(r["state"]),
                    " ".join(
                        x
                        for x in (
                            as_text(r["service"]),
                            as_text(r["product"]),
                            as_text(r["version"]),
                        )
                        if x
                    ),
                )
                for r in rows
            }

        baseline = port_map(baseline_id)
        current = port_map(current_id)

        newly_open = tuple(
            (ip, port, proto)
            for (ip, port, proto), (state, _) in current.items()
            if state == "open"
            and baseline.get((ip, port, proto), ("", ""))[0] != "open"
        )
        closed = tuple(
            (ip, port, proto)
            for (ip, port, proto), (state, _) in baseline.items()
            if state == "open"
            and current.get((ip, port, proto), ("", ""))[0] != "open"
        )
        changed = tuple(
            (ip, port, proto, baseline[(ip, port, proto)][1], service)
            for (ip, port, proto), (_, service) in current.items()
            if (ip, port, proto) in baseline
            and baseline[(ip, port, proto)][1] != service
            and service
        )

        def host_set(scan_id: int) -> set[str]:
            rows = self.db.query(
                "SELECT ip_address FROM scan_hosts WHERE scan_id = %s AND status = 'UP'",
                (scan_id,),
            )
            return {as_text(r["ip_address"]) for r in rows}

        baseline_hosts, current_hosts = host_set(baseline_id), host_set(current_id)

        baseline_titles = {f.title for f in self.findings_for_scan(baseline_id)}
        current_titles = {f.title for f in self.findings_for_scan(current_id)}

        return ScanComparison(
            baseline_scan_id=baseline_id,
            current_scan_id=current_id,
            newly_open_ports=newly_open,
            closed_ports=closed,
            changed_services=changed,
            new_hosts=tuple(sorted(current_hosts - baseline_hosts)),
            missing_hosts=tuple(sorted(baseline_hosts - current_hosts)),
            recurring_findings=tuple(sorted(baseline_titles & current_titles)),
        )

    def prune_before(self, cutoff: datetime) -> int:
        """Delete scan history older than ``cutoff`` (cascades to results)."""
        return self.db.execute(
            "DELETE FROM scans WHERE created_at < %s", (to_db(cutoff),)
        )
