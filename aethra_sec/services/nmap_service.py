"""Vulnerability assessment service (§16, §17, §65).

Responsibilities:

* enforce the **authorisation boundary** - a target outside the configured
  authorised networks is refused and the refusal is audited (§2);
* enforce RBAC - only sessions holding ``scan.run`` may start a scan;
* run Nmap on a worker thread so the interface stays responsive (§37);
* persist real results and derive explainable findings;
* publish lifecycle events so the dashboard reflects reality.

There is no exploitation capability here. Nmap is invoked for discovery, port
state, service/version detection and OS fingerprinting only (§89).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.config.settings import AuthorizationSettings, ToolSettings
from aethra_sec.core.errors import (
    AuthorizationBoundaryError,
    ScanError,
    ToolUnavailableError,
    ValidationFailedError,
)
from aethra_sec.core.event_bus import EventBus
from aethra_sec.core.events import (
    EventType,
    ScanCompletedPayload,
    ScanFailedPayload,
    ScanProgressPayload,
)
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.database.repositories.scans import ScanRepository
from aethra_sec.integrations.nmap import (
    FindingBuilder,
    NmapRunner,
    ScanRequest,
    VulnKnowledgeEntry,
    build_scan_request,
    extract_script_references,
    parse_scan_result,
    probe_nmap,
)
from aethra_sec.models.enums import EvidenceSource, HostStatus, RiskLevel, ScanStatus
from aethra_sec.models.scan import Scan, ScanHostResult
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import is_authorized_target, unauthorized_addresses
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.utils.validation import ValidationError, validate_target

LOGGER = get_logger("services.nmap")


@dataclass
class RunningScan:
    """Bookkeeping for a scan currently executing."""

    scan_id: int
    target: str
    runner: NmapRunner
    thread: threading.Thread
    started_at: datetime
    started_by: str = ""


class NmapService:
    """Runs authorised assessments and stores their real results."""

    def __init__(
        self,
        scans: ScanRepository,
        hosts: HostRepository,
        event_bus: EventBus,
        audit: AuditService,
        access: AccessControl,
        tools: ToolSettings,
        authorization: AuthorizationSettings,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        """Wire the service to its collaborators."""
        self._scans = scans
        self._hosts = hosts
        self._bus = event_bus
        self._audit = audit
        self._access = access
        self._tools = tools
        self._authorization = authorization
        self._risk = risk_engine or RiskEngine()
        self._running: dict[int, RunningScan] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def availability(self) -> Any:
        """Probe the real Nmap installation (§10, §101)."""
        return probe_nmap(self._tools.nmap_path)

    @property
    def running_scans(self) -> tuple[RunningScan, ...]:
        """Scans currently executing."""
        with self._lock:
            return tuple(self._running.values())

    def is_running(self, scan_id: int) -> bool:
        """True while a specific scan is still executing."""
        with self._lock:
            return scan_id in self._running

    # ------------------------------------------------------------------
    # Authorisation boundary (§2)
    # ------------------------------------------------------------------
    def validate_and_authorize(self, target: str) -> tuple[str, str, tuple[str, ...]]:
        """Validate a target and confirm it is inside an authorised network.

        Hostnames are resolved first, because authorisation must be decided on
        the address that will actually be contacted rather than on a name.

        Returns:
            ``(canonical_target, kind, addresses)``.

        Raises:
            ValidationFailedError: on malformed input.
            AuthorizationBoundaryError: when any address lies outside the
                configured authorised networks.
        """
        try:
            spec = validate_target(target)
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        addresses = spec.addresses
        if spec.kind == "hostname":
            resolved = self._resolve(spec.raw)
            if not resolved:
                raise ValidationFailedError(
                    f"'{spec.raw}' could not be resolved.",
                    user_message=(
                        f"The hostname '{spec.raw}' could not be resolved. "
                        "Check the name or enter an IP address."
                    ),
                )
            addresses = resolved

        outside = unauthorized_addresses(addresses, self._authorization)
        if outside:
            allowed = ", ".join(str(n) for n in self._authorization.parsed_networks)
            raise AuthorizationBoundaryError(
                f"Target addresses outside authorised networks: {', '.join(outside[:5])}",
                user_message=(
                    "Assessment refused. "
                    f"{len(outside)} address(es) in this target are outside the "
                    f"networks this installation is authorised to assess "
                    f"({allowed}). Adjust AETHRA_AUTHORIZED_NETWORKS in .env "
                    "only if you are authorised to assess the additional range."
                ),
            )
        return spec.raw, spec.kind, addresses

    @staticmethod
    def _resolve(hostname: str) -> tuple[str, ...]:
        """Resolve a hostname to every address it maps to."""
        try:
            infos = socket.getaddrinfo(hostname, None)
        except (OSError, UnicodeError):
            return ()
        addresses: list[str] = []
        for info in infos:
            address = info[4][0]
            if address and address not in addresses:
                addresses.append(str(address))
        return tuple(addresses)

    def authorization_summary(self) -> str:
        """Readable description of the configured boundary, for the scan page."""
        networks = ", ".join(str(n) for n in self._authorization.parsed_networks)
        if self._authorization.allow_public:
            return (
                "Public targets are ENABLED for this installation "
                "(AETHRA_ALLOW_PUBLIC_TARGETS=true). Only scan systems you are "
                "authorised to assess."
            )
        return f"Authorised networks: {networks or '(none configured)'}"

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def start_scan(
        self,
        session: Session,
        target: str,
        *,
        profile_key: str = "standard",
        port_spec: str = "",
        timing: str = "T3",
        script_categories: tuple[str, ...] = (),
    ) -> int:
        """Validate, authorise and start an assessment on a worker thread.

        Returns:
            The new scan id. Progress arrives as events; results are queried
            from the repository when the completion event fires.

        Raises:
            PermissionDeniedError, ValidationFailedError,
            AuthorizationBoundaryError, ToolUnavailableError.
        """
        live = self._access.require(session, Permission.SCAN_RUN, target=target)

        availability = self.availability()
        if not availability.available:
            self._audit.record(
                AuditAction.SCAN_REFUSED,
                session=live,
                category=AuditCategory.ASSESSMENT,
                target_type="target",
                target_id=target,
                result="FAILURE",
                detail=f"Nmap unavailable: {availability.detail}",
            )
            raise ToolUnavailableError(
                "Nmap", availability.detail, user_message=availability.detail
            )

        try:
            canonical, kind, addresses = self.validate_and_authorize(target)
        except (ValidationFailedError, AuthorizationBoundaryError) as exc:
            self._audit.record(
                AuditAction.SCAN_REFUSED,
                session=live,
                category=AuditCategory.ASSESSMENT,
                target_type="target",
                target_id=target,
                result="DENIED",
                detail=exc.user_message,
            )
            raise

        try:
            request = build_scan_request(
                canonical, profile_key, port_spec, timing, script_categories
            )
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        scan = Scan(
            target=canonical,
            target_kind=kind,
            profile=request.profile.key,
            profile_label=request.profile.label,
            port_spec=request.port_spec,
            timing=request.timing,
            arguments=request.argument_string,
            status=ScanStatus.QUEUED,
            initiated_by=live.user_id,
            created_at=utcnow(),
        )
        scan_id = self._scans.create_scan(scan)

        self._audit.record(
            AuditAction.SCAN_STARTED,
            session=live,
            category=AuditCategory.ASSESSMENT,
            target_type="scan",
            target_id=scan_id,
            detail=(
                f"Assessment of '{canonical}' ({len(addresses) or 'unknown'} "
                f"address(es)) using profile '{request.profile.key}' with "
                f"arguments: {request.argument_string}"
            ),
        )

        runner = NmapRunner(self._tools.nmap_path)
        thread = threading.Thread(
            target=self._execute,
            args=(scan_id, request, runner, live.username),
            name=f"nmap-scan-{scan_id}",
            daemon=True,
        )
        with self._lock:
            self._running[scan_id] = RunningScan(
                scan_id=scan_id,
                target=canonical,
                runner=runner,
                thread=thread,
                started_at=utcnow(),
                started_by=live.username,
            )
        thread.start()

        self._bus.publish(
            EventType.NMAP_SCAN_STARTED,
            ScanProgressPayload(
                scan_id=scan_id,
                target=canonical,
                status="RUNNING",
                detail=f"Running {request.profile.label}",
            ),
        )
        return scan_id

    def stop_scan(self, session: Session, scan_id: int) -> bool:
        """Request cancellation of a running scan.

        Nmap runs as a synchronous child process, so cancellation takes effect
        when the current invocation returns; the scan is then marked CANCELLED
        and its partial results are discarded rather than stored as if complete.
        """
        live = self._access.require(session, Permission.SCAN_STOP, target=str(scan_id))
        with self._lock:
            running = self._running.get(scan_id)
        if running is None:
            return False
        running.runner.cancel()
        self._audit.record(
            AuditAction.SCAN_STOPPED,
            session=live,
            category=AuditCategory.ASSESSMENT,
            target_type="scan",
            target_id=scan_id,
            detail="Operator requested that the assessment stop.",
        )
        return True

    def _execute(
        self, scan_id: int, request: ScanRequest, runner: NmapRunner, username: str
    ) -> None:
        """Worker body: run Nmap, persist real results, publish the outcome."""
        try:
            self._scans.mark_running(scan_id, "", "")
            result = runner.run(request)
            self._scans.mark_running(
                scan_id, result.command_line, result.nmap_version
            )

            hosts = parse_scan_result(result.scan_data)
            counts = self._persist_results(scan_id, result.scan_data, hosts)

            self._scans.mark_completed(
                scan_id,
                hosts_total=len(hosts),
                hosts_up=counts["hosts_up"],
                open_ports=counts["open_ports"],
                findings_count=counts["findings"],
                duration_seconds=result.duration_seconds,
            )
            self._audit.record(
                AuditAction.SCAN_COMPLETED,
                username=username,
                category=AuditCategory.ASSESSMENT,
                target_type="scan",
                target_id=scan_id,
                detail=(
                    f"Assessment completed in {result.duration_seconds:.2f}s: "
                    f"{counts['hosts_up']} host(s) up, {counts['open_ports']} "
                    f"open port(s), {counts['findings']} finding(s)."
                ),
            )
            self._bus.publish(
                EventType.NMAP_SCAN_COMPLETED,
                ScanCompletedPayload(
                    scan_id=scan_id,
                    target=request.target,
                    hosts_up=counts["hosts_up"],
                    open_ports=counts["open_ports"],
                    findings=counts["findings"],
                    duration_seconds=result.duration_seconds,
                ),
            )
        except ScanError as exc:
            if runner.is_cancelled:
                self._scans.mark_cancelled(scan_id)
                self._bus.publish(
                    EventType.NMAP_SCAN_FAILED,
                    ScanFailedPayload(scan_id, request.target, "Stopped by operator."),
                )
            else:
                self._fail(scan_id, request.target, username, exc.user_message)
        except ToolUnavailableError as exc:
            self._fail(scan_id, request.target, username, exc.user_message)
        except Exception as exc:  # noqa: BLE001 - a worker must never die silently
            LOGGER.exception("Unexpected failure in scan %s", scan_id)
            self._fail(scan_id, request.target, username, str(exc))
        finally:
            with self._lock:
                self._running.pop(scan_id, None)

    def _fail(self, scan_id: int, target: str, username: str, message: str) -> None:
        """Record a scan failure with the real error text."""
        try:
            self._scans.mark_failed(scan_id, message)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not record the scan failure for %s", scan_id)
        self._audit.record(
            AuditAction.SCAN_FAILED,
            username=username,
            category=AuditCategory.ASSESSMENT,
            target_type="scan",
            target_id=scan_id,
            result="FAILURE",
            detail=message,
        )
        self._bus.publish(
            EventType.NMAP_SCAN_FAILED, ScanFailedPayload(scan_id, target, message)
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _persist_results(
        self,
        scan_id: int,
        scan_data: dict[str, Any],
        hosts: list[ScanHostResult],
    ) -> dict[str, int]:
        """Store hosts, ports and derived findings; update the inventory."""
        knowledge = self._load_knowledge()
        builder = FindingBuilder(self._risk, knowledge)
        trusted = self._hosts.trusted_addresses()
        raw_hosts = scan_data.get("scan") or {}

        hosts_up = 0
        open_ports = 0
        total_findings = 0

        for host in hosts:
            if host.status is HostStatus.UP:
                hosts_up += 1

            host_id = self._hosts.upsert_observed(
                host.ip_address,
                observed_at=utcnow(),
                mac_address=host.mac_address,
                source=EvidenceSource.NMAP,
            )
            host.host_id = host_id or None
            self._hosts.update_identity(
                host_id,
                hostname=host.hostname or None,
                mac_address=host.mac_address or None,
                vendor=host.vendor or None,
                os_name=host.os_name or None,
                os_accuracy=host.os_accuracy,
                status=host.status,
            )

            scan_host_id = self._scans.add_scan_host(scan_id, host)
            host.id = scan_host_id
            if host.ports:
                self._scans.add_ports(scan_host_id, host.ports)
            open_ports += len(host.open_ports)

            raw_entry = raw_hosts.get(host.ip_address) if isinstance(raw_hosts, dict) else None
            references = (
                extract_script_references(raw_entry)
                if isinstance(raw_entry, dict)
                else {}
            )

            findings = builder.build_for_host(
                host,
                scan_id=scan_id,
                script_references=references,
                host_is_trusted=host.ip_address in trusted,
            )
            for finding in findings:
                finding.scan_host_id = scan_host_id
                finding.host_id = host_id or None
            if findings:
                self._scans.add_findings(findings)
                total_findings += len(findings)
                self._hosts.set_risk_level(
                    host_id, self._risk.host_risk_level([f.risk_level for f in findings])
                )
            elif host.status is HostStatus.UP:
                self._hosts.set_risk_level(host_id, RiskLevel.INFORMATIONAL)
            host.findings = findings

        return {
            "hosts_up": hosts_up,
            "open_ports": open_ports,
            "findings": total_findings,
        }

    def _load_knowledge(self) -> tuple[VulnKnowledgeEntry, ...]:
        """Load administrator-configured vulnerability knowledge (§19).

        Returns an empty tuple when the table is empty, which is the normal
        state on a fresh install. Findings then honestly report that further
        verification is required instead of citing an invented identifier.
        """
        try:
            rows = self._scans.db.query(
                "SELECT service, product_pattern, version_pattern, port, title, "
                "concern, risk_level, reference_id, reference_source "
                "FROM vuln_knowledge WHERE is_active = 1 LIMIT 2000"
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Vulnerability knowledge unavailable.", exc_info=True)
            return ()
        entries: list[VulnKnowledgeEntry] = []
        for row in rows:
            try:
                entries.append(
                    VulnKnowledgeEntry(
                        service=str(row.get("service") or ""),
                        product_pattern=str(row.get("product_pattern") or ""),
                        version_pattern=str(row.get("version_pattern") or ""),
                        port=int(row["port"]) if row.get("port") is not None else None,
                        title=str(row.get("title") or ""),
                        concern=str(row.get("concern") or ""),
                        risk_level=RiskLevel.parse(
                            row.get("risk_level"), RiskLevel.MEDIUM
                        ),
                        reference=str(row.get("reference_id") or ""),
                        reference_source=str(row.get("reference_source") or ""),
                    )
                )
            except Exception:  # noqa: BLE001
                LOGGER.exception("Skipping a malformed vulnerability knowledge row.")
        return tuple(entries)

    # ------------------------------------------------------------------
    # Reads (permission-checked)
    # ------------------------------------------------------------------
    def get_scan(self, session: Session, scan_id: int) -> Scan | None:
        """Fetch one scan with its full results."""
        self._access.require(session, Permission.SCAN_VIEW, target=str(scan_id))
        return self._scans.get_scan_with_results(scan_id)

    def scan_history(self, session: Session, **filters: Any) -> list[Scan]:
        """Search scan history."""
        self._access.require(session, Permission.SCAN_VIEW)
        return self._scans.search_scans(**filters)

    def compare(self, session: Session, baseline_id: int, current_id: int) -> Any:
        """Compare two scans of the same target (§45)."""
        self._access.require(session, Permission.SCAN_VIEW)
        return self._scans.compare_scans(baseline_id, current_id)

    def findings(self, session: Session, **filters: Any) -> list[Any]:
        """Search derived security findings."""
        self._access.require(session, Permission.SCAN_VIEW)
        return self._scans.search_findings(**filters)

    def resolve_finding(self, session: Session, finding_id: int) -> None:
        """Mark a finding as resolved (evidence retained, never deleted)."""
        live = self._access.require(
            session, Permission.SCAN_VIEW, target=str(finding_id)
        )
        self._scans.resolve_finding(finding_id)
        self._audit.record(
            AuditAction.FINDING_RESOLVED,
            session=live,
            category=AuditCategory.ASSESSMENT,
            target_type="finding",
            target_id=finding_id,
            detail="Finding marked resolved by the operator.",
        )

    def shutdown(self, timeout: float = 5.0) -> None:
        """Cancel and join running scans during application shutdown."""
        with self._lock:
            running = list(self._running.values())
        for scan in running:
            scan.runner.cancel()
        for scan in running:
            scan.thread.join(timeout=timeout)
