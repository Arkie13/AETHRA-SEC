"""Host inventory service (§46, §47, §93)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Sequence

from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.alerts import AlertRepository
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.database.repositories.traffic import TrafficRepository
from aethra_sec.models.host import (
    AssessmentSummary,
    Host,
    TrustedHost,
    summarize_assessment,
)
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import resolve_hostname
from aethra_sec.utils.validation import ValidationError, validate_ip

LOGGER = get_logger("services.hosts")

#: Most hosts one operator-triggered resolve may look up. A large inventory
#: should not turn a single click into thousands of DNS queries.
MAX_RESOLVE_BATCH = 256

#: Most hosts the background resolver takes per pass.
AUTO_RESOLVE_BATCH = 25

#: Concurrent lookups. Reverse DNS is latency rather than work, so a handful
#: at a time turns a minute of waiting into a few seconds without loading
#: either this machine or the resolver.
RESOLVE_WORKERS = 8


@dataclass
class ResolveResult:
    """What one round of reverse resolution actually achieved."""

    attempted: int = 0
    resolved: int = 0
    #: ``(address, hostname)`` for each name that came back.
    names: list[tuple[str, str]] = field(default_factory=list)

    @property
    def without_record(self) -> int:
        """Addresses that answered with no name."""
        return max(0, self.attempted - self.resolved)

    def summary(self) -> str:
        """One line describing the round, for the audit trail and the screen."""
        if not self.attempted:
            return "No hosts were waiting for a hostname lookup."
        return (
            f"Reverse DNS attempted for {self.attempted} host(s): "
            f"{self.resolved} resolved, {self.without_record} with no DNS record."
        )


class HostService:
    """Queries and maintains the observed-host inventory."""

    def __init__(
        self,
        hosts: HostRepository,
        scans: ScanRepository,
        alerts: AlertRepository,
        traffic: TrafficRepository,
        audit: AuditService,
        access: AccessControl,
    ) -> None:
        """Wire the service to its collaborators."""
        self._hosts = hosts
        self._scans = scans
        self._alerts = alerts
        self._traffic = traffic
        self._audit = audit
        self._access = access

    def search(self, session: Session, **filters: Any) -> list[Host]:
        """Search the inventory."""
        self._access.require(session, Permission.HOST_VIEW)
        return self._hosts.search(**filters)

    def assessment_overview(
        self,
        session: Session,
        *,
        text: str = "",
        limit: int = 1000,
        scope: Any = None,
        in_scope_only: bool = False,
    ) -> list[Host]:
        """The host inventory with assessment state and security result.

        Feeds the automatic-assessment table: every observed host, its current
        reachability, where it stands in the assessment cycle, and what the
        assessment concluded - each derived from stored evidence, none typed by
        an operator (§4). When a resolved scope is given, each host is marked
        in or out of it; ``in_scope_only`` selects only in-scope hosts in SQL.
        """
        self._access.require(session, Permission.HOST_VIEW)
        ranges = None
        if in_scope_only and scope is not None and getattr(scope, "available", False):
            ranges = scope.address_ranges
        hosts = self._hosts.assessment_overview(text=text, limit=limit, ranges=ranges)
        if scope is not None and getattr(scope, "available", False):
            for host in hosts:
                host.in_scope = bool(scope.contains(host.ip_address))
        return hosts

    def assessment_summary(self, session: Session, scope: Any = None) -> AssessmentSummary:
        """Assessment counts over the whole inventory, inside ``scope``.

        The single source for the Vulnerability Assessment tiles and the
        Dashboard. Uncapped: it counts every host, not the rows a table loaded.
        """
        self._access.require(session, Permission.HOST_VIEW)
        return summarize_assessment(self._hosts.assessment_summary_hosts(), scope)

    def get(self, session: Session, host_id: int) -> Host | None:
        """Fetch one host."""
        self._access.require(session, Permission.HOST_VIEW, target=str(host_id))
        return self._hosts.get(host_id)

    def detail(self, session: Session, host_id: int) -> dict[str, Any]:
        """Assemble everything the host detail screen shows (§47)."""
        self._access.require(session, Permission.HOST_VIEW, target=str(host_id))
        host = self._hosts.get(host_id)
        if host is None:
            return {}
        host.protocols_observed = self._hosts.protocols_for_host(host_id)
        return {
            "host": host,
            "observations": self._hosts.observations_for_host(host_id),
            "open_ports": self._scans.open_ports_for_host(host_id),
            "scans": self._scans.scans_for_host(host_id, limit=20),
            "findings": self._scans.findings_for_host(host_id, limit=100),
            "alerts": self._alerts.alerts_for_host(host_id, limit=100),
            "recent_traffic": self._traffic.recent_for_host(host.ip_address, limit=100),
            "timeline": self._timeline(host_id, host.ip_address),
        }

    def _timeline(self, host_id: int, ip_address: str) -> list[dict[str, Any]]:
        """Chronological host activity from real record timestamps."""
        entries: list[dict[str, Any]] = []
        for scan in self._scans.scans_for_host(host_id, limit=20):
            entries.append(
                {
                    "at": scan.finished_at or scan.created_at,
                    "source": "Nmap",
                    "summary": f"Assessment {scan.id}: {scan.summary_line}",
                }
            )
        for alert in self._alerts.alerts_for_host(host_id, limit=50):
            entries.append(
                {
                    "at": alert.effective_time,
                    "source": "Snort",
                    "summary": f"[{alert.severity}] {alert.message}",
                }
            )
        for finding in self._scans.findings_for_host(host_id, limit=50):
            entries.append(
                {
                    "at": finding.created_at,
                    "source": "Nmap",
                    "summary": f"Finding [{finding.risk_level}] {finding.title}",
                }
            )
        entries.sort(key=lambda e: (e["at"] is None, e["at"]), reverse=True)
        return entries[:100]

    def resolve_hostname(self, session: Session, host_id: int) -> str:
        """Attempt reverse DNS for a host and store any result.

        A failed lookup stores nothing: the interface keeps showing the IP
        address rather than an invented name (§15).
        """
        live = self._access.require(
            session, Permission.HOST_MANAGE, target=str(host_id)
        )
        host = self._hosts.get(host_id)
        if host is None:
            return ""
        hostname = resolve_hostname(host.ip_address)
        if hostname:
            self._hosts.update_identity(host_id, hostname=hostname)
            self._audit.record(
                AuditAction.USER_UPDATED,
                session=live,
                category=AuditCategory.MONITORING,
                target_type="host",
                target_id=host_id,
                detail=f"Resolved {host.ip_address} to '{hostname}'.",
            )
        return hostname

    def resolve_hostnames(
        self,
        session: Session,
        host_ids: Sequence[int] | None = None,
        *,
        limit: int = MAX_RESOLVE_BATCH,
    ) -> ResolveResult:
        """Reverse-resolve many hosts at once.

        Capture records an address and a MAC; it cannot record a hostname. A
        button that resolves one row at a time is therefore no use against an
        inventory a capture built - ninety-four hosts is ninety-four clicks -
        which is why this takes a batch.

        Args:
            host_ids: the hosts to look up. When omitted, the hosts that have
                no hostname and have never been looked up are used, most
                recently seen first.
            limit: ceiling on lookups in one call, so a large inventory cannot
                turn one click into thousands of DNS queries.

        Returns:
            A :class:`ResolveResult` counting what actually happened. A failed
            lookup stores nothing: the interface keeps showing the address
            rather than inventing a name (§15).
        """
        live = self._access.require(session, Permission.HOST_MANAGE, target="hostnames")
        if host_ids is None:
            targets = self._hosts.unresolved_hostnames(limit=limit)
        else:
            wanted = list(dict.fromkeys(int(host_id) for host_id in host_ids))[:limit]
            targets = [host for host in (self._hosts.get(i) for i in wanted) if host]
        if not targets:
            return ResolveResult()

        # Reverse DNS is latency, not work: a lookup that times out costs a
        # second of waiting and nothing else, so they run side by side.
        workers = min(RESOLVE_WORKERS, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            names = list(pool.map(lambda host: resolve_hostname(host.ip_address), targets))

        result = ResolveResult(attempted=len(targets))
        for host, name in zip(targets, names):
            if not name or host.id is None:
                continue
            self._hosts.update_identity(host.id, hostname=name)
            result.resolved += 1
            result.names.append((host.ip_address, name))
        self._hosts.mark_hostname_checked(
            [host.id for host in targets if host.id is not None]
        )

        self._audit.record(
            AuditAction.USER_UPDATED,
            session=live,
            category=AuditCategory.MONITORING,
            target_type="host",
            target_id="hostnames",
            detail=result.summary(),
        )
        LOGGER.info(result.summary())
        return result

    def unresolved_hostname_count(self, session: Session) -> int:
        """How many hosts have never had reverse DNS attempted."""
        self._access.require(session, Permission.HOST_VIEW)
        return self._hosts.count_unresolved_hostnames()

    def resolve_pending(self, limit: int = AUTO_RESOLVE_BATCH) -> ResolveResult:
        """Resolve a bounded batch as the system itself, for the scheduler.

        Runs without a session because no operator is present; it is bounded
        so a busy network cannot turn the inventory into a DNS flood, and it
        only ever looks at hosts nobody has looked up before.
        """
        targets = self._hosts.unresolved_hostnames(limit=limit)
        if not targets:
            return ResolveResult()
        workers = min(RESOLVE_WORKERS, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            names = list(pool.map(lambda host: resolve_hostname(host.ip_address), targets))

        result = ResolveResult(attempted=len(targets))
        for host, name in zip(targets, names):
            if not name or host.id is None:
                continue
            self._hosts.update_identity(host.id, hostname=name)
            result.resolved += 1
        self._hosts.mark_hostname_checked(
            [host.id for host in targets if host.id is not None]
        )
        if result.resolved:
            LOGGER.info("Background hostname resolution: %s", result.summary())
        return result

    # ------------------------------------------------------------------
    # Trusted assets (§93)
    # ------------------------------------------------------------------
    def list_trusted(self, session: Session) -> list[TrustedHost]:
        """Administrator-maintained trusted asset list."""
        self._access.require(session, Permission.HOST_VIEW)
        return self._hosts.list_trusted()

    def add_trusted(
        self, session: Session, ip_address: str, label: str, reason: str
    ) -> int:
        """Register a trusted asset.

        Trust is context, not an exemption: traffic from a trusted asset is
        still analysed and still raises anomalies; the trust flag appears in
        the evidence so an analyst can weigh it.
        """
        live = self._access.require(
            session, Permission.HOST_MANAGE, target=ip_address
        )
        try:
            address = validate_ip(ip_address)
        except ValidationError as exc:
            from aethra_sec.core.errors import ValidationFailedError

            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        trusted_id = self._hosts.add_trusted(address, label, reason, live.user_id)
        self._audit.record(
            AuditAction.TRUSTED_HOST_ADDED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="trusted_host",
            target_id=address,
            detail=f"Registered '{label}' as a trusted asset. Reason: {reason}",
        )
        return trusted_id

    def remove_trusted(self, session: Session, ip_address: str) -> None:
        """Remove a trusted asset registration."""
        live = self._access.require(
            session, Permission.HOST_MANAGE, target=ip_address
        )
        self._hosts.remove_trusted(ip_address)
        self._audit.record(
            AuditAction.TRUSTED_HOST_REMOVED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="trusted_host",
            target_id=ip_address,
            detail=f"Removed trusted asset registration for {ip_address}.",
        )

    def statistics(self, session: Session) -> dict[str, int]:
        """Inventory counters."""
        self._access.require(session, Permission.HOST_VIEW)
        from datetime import timedelta

        from aethra_sec.utils.timeutil import utcnow

        return {
            "total": self._hosts.count_all(),
            "active_24h": self._hosts.count_active_since(utcnow() - timedelta(hours=24)),
            "trusted": len(self._hosts.trusted_addresses()),
        }
