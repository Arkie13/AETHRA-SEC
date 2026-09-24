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

import socket
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from aethra_sec.analytics.risk_engine import RiskEngine
from aethra_sec.config.settings import AuthorizationSettings, ToolSettings
from aethra_sec.core.errors import (
    AuthorizationBoundaryError,
    ScanError,
    ScanTimeoutError,
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
    extract_script_scores,
    has_raw_socket_privilege,
    parse_scan_result,
    probe_nmap,
)
from aethra_sec.integrations.nmap.routing import RouteChoice, resolve_route
from aethra_sec.integrations.nmap.identity import (
    IDENTITY_MAX_HOSTS,
    identity_from_scan,
    identity_request,
    mdns_hostname,
    reverse_dns,
    validated_target,
)
from aethra_sec.integrations.nmap.osfingerprint import infer_os, parse_xml_evidence
from aethra_sec.models.enums import ScanTrigger, EvidenceSource, HostStatus, RiskLevel, ScanStatus
from aethra_sec.models.scan import Scan, ScanHostResult
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import unauthorized_addresses
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


def is_parser_failure(reported_up: int, persisted_up: int) -> bool:
    """True when Nmap found live hosts that we failed to read.

    Nmap's own run statistics are the check on our parsing. When it reports
    live hosts but none survived into the stored result, the scan did not find
    nothing - we failed to read what it found. Recording that as "0 hosts up"
    would file a parsing fault as a fact about the network, which is the one
    outcome this must never produce.

    The reverse is not a fault: Nmap reporting nothing up and nothing being
    stored is a genuine result about a target that did not answer.
    """
    return reported_up > 0 and persisted_up <= 0

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
        discover_identity: bool = True,
        timeout_provider: Any = None,
    ) -> None:
        """Wire the service to its collaborators.

        Args:
            discover_identity: run the follow-up hostname/OS probe after a
                scan. On by default because without it both columns are empty
                for any host without a PTR record; tests turn it off to keep a
                parser test from touching the network.
            timeout_provider: returns the wall-clock limit, in seconds, for one
                Nmap run. Read at the start of every scan so a change in
                Settings applies to the next scan. ``None`` means no limit
                beyond Nmap's own ``--host-timeout``.
        """
        self._timeout_provider = timeout_provider
        self._scans = scans
        self._hosts = hosts
        self._bus = event_bus
        self._audit = audit
        self._access = access
        self._tools = tools
        self._authorization = authorization
        self._risk = risk_engine or RiskEngine()
        self._discover_identity = discover_identity
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
                    f"({allowed}). Adjust AETHRA_AUTHORIZED_NETWORKS in the "
                    "configuration file "
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
        skip_host_discovery: bool = False,
        interface: str = "",
        trigger: ScanTrigger = ScanTrigger.MANUAL,
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

        # Interface selection. Left to Nmap, probes leave on whichever adapter
        # wins its route metric, and where two adapters claim one subnet that
        # is silently the wrong one: on this machine a scan of a live host
        # leaving on the VMware adapter reports it down, while the same scan
        # pinned to the Wi-Fi adapter reports it up. So when the operator has
        # not pinned an interface, ask the OS which one actually reaches the
        # target and pin that.
        route = RouteChoice()
        chosen_interface = interface
        if not interface:
            route = resolve_route(
                canonical, configured_path=self._tools.nmap_path
            )
            if route.resolved:
                chosen_interface = route.device
                LOGGER.info(
                    "Route-based interface for %s: %s", canonical, route.reason
                )
            else:
                LOGGER.info(
                    "No route-based interface for %s: %s", canonical, route.reason
                )

        try:
            request = build_scan_request(
                canonical, profile_key, port_spec, timing, script_categories,
                skip_host_discovery=skip_host_discovery,
                interface=chosen_interface,
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
            trigger_source=trigger,
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
            result = runner.run(request, timeout_seconds=self._scan_timeout())
            # Only the command and version are added now. Calling mark_running
            # again here is what used to overwrite started_at with the moment
            # Nmap finished.
            self._scans.record_command(
                scan_id, result.command_line, result.nmap_version
            )

            hosts = parse_scan_result(result.scan_data)
            # A host Nmap abandoned on --host-timeout is still reported "up"
            # with whatever partial port list it had. Storing that would turn
            # an unfinished assessment into a finished one with fewer ports -
            # and, with none, into "no findings". Those hosts are held back.
            abandoned = set(result.timed_out_hosts)
            if abandoned:
                hosts = [h for h in hosts if h.ip_address not in abandoned]
                if not hosts:
                    raise ScanTimeoutError(
                        f"Nmap abandoned {', '.join(sorted(abandoned))} on "
                        "--host-timeout.",
                        user_message=(
                            "The assessment timed out: Nmap stopped assessing "
                            f"{', '.join(sorted(abandoned))} when its host "
                            "timeout expired. Nothing was recorded as a result, "
                            "because an unfinished scan says nothing about "
                            "what the host exposes."
                        ),
                    )
            # A device discovered by ARP demonstrably exists: something
            # answered for that address on this link. Nmap's own host
            # discovery is a different question, and phones, printers and
            # anything with a firewall routinely fail it while being perfectly
            # present. Where that happens, one controlled retry with -Pn asks
            # the port question directly instead of recording "no response"
            # against a device we have hardware evidence for.
            #
            # Deliberately narrow: only when the first pass found nothing at
            # all, only for a target we discovered ourselves, and only once.
            # "Nothing answered" is no host *up*, not an empty list: Nmap
            # still emits a <host> element with state="down", so testing the
            # list itself meant the retry never fired at all.
            answered_first_pass = any(
                h.status is HostStatus.UP for h in hosts
            )
            if not answered_first_pass and self._should_retry_unreachable(request):
                retry = replace(
                    request,
                    arguments=tuple(request.arguments) + ("-Pn",),
                )
                LOGGER.info(
                    "Nmap host discovery found nothing at %s; retrying with "
                    "-Pn because the address was discovered on this link.",
                    request.target,
                )
                retried = runner.run(retry, timeout_seconds=self._scan_timeout())
                retried_hosts = [
                    h for h in parse_scan_result(retried.scan_data)
                    if h.ip_address not in set(retried.timed_out_hosts)
                ]
                # -Pn tells Nmap to skip host discovery, so it reports *every*
                # target as up whether or not anything is there. Its "1 host
                # up" is therefore not evidence the host answered, and taking
                # it as such would turn an absent device into a completed scan
                # of a live host - which is to say, into "Safe".
                #
                # The retry is only adopted when it produced something that
                # genuinely came back: an open port. Otherwise the original
                # result stands, and the host is honestly recorded as not
                # having answered.
                answered = [h for h in retried_hosts if h.open_ports]
                if answered:
                    result, hosts = retried, answered
                    self._scans.record_command(
                        scan_id, result.command_line, result.nmap_version
                    )
                else:
                    LOGGER.info(
                        "-Pn retry of %s returned no open port; the host is "
                        "recorded as not having answered.", request.target,
                    )

            self._discover_identities(hosts, runner, result.raw_xml)
            counts = self._persist_results(scan_id, result.scan_data, hosts)

            # Nmap's own run statistics are the check on our parsing. When it
            # reports live hosts but none survived into the result, the scan
            # did not find nothing - we failed to read what it found. Recording
            # that as "0 hosts up" would file a parser bug as a fact about the
            # network, which is the one outcome this must never produce.
            # Hosts deliberately held back above are not a parsing failure.
            reported_up = max(
                0, int(result.statistics.get("up", 0) or 0) - len(abandoned)
            )
            if is_parser_failure(reported_up, counts["hosts_up"]):
                raise ScanError(
                    f"Nmap reported {reported_up} host(s) up but none could be "
                    "read from its output.",
                    user_message=(
                        f"Result parsing failed. Nmap reported {reported_up} "
                        "host(s) up, but AETHRA-SEC could not read any host "
                        "from its output, so nothing was recorded. This is a "
                        "parsing fault, not a finding about the target - the "
                        "scan itself succeeded. The command that ran was:\n\n"
                        f"{result.command_line}"
                    ),
                )

            # ``hosts_total`` is what Nmap probed, not what it could parse.
            # A target reported down yields no <host> element, so len(hosts)
            # is 0 - recording that as the total would erase the fact that an
            # address was scanned at all, which is exactly what the Results
            # tab needs in order to explain a "0 hosts up" outcome.
            probed = result.statistics.get("total", 0) or len(hosts)
            self._scans.mark_completed(
                scan_id,
                hosts_total=probed,
                hosts_up=counts["hosts_up"],
                open_ports=counts["open_ports"],
                findings_count=counts["findings"],
                duration_seconds=result.duration_seconds,
            )
            if abandoned:
                self._scans.note_error(
                    scan_id,
                    f"{len(abandoned)} host(s) timed out and were not recorded: "
                    + ", ".join(sorted(abandoned)),
                )
            if counts["findings"]:
                self._audit.record(
                    AuditAction.FINDING_RECORDED,
                    username=username,
                    category=AuditCategory.ASSESSMENT,
                    target_type="scan",
                    target_id=scan_id,
                    detail=(
                        f"{counts['findings']} finding(s) recorded from scan "
                        f"{scan_id} of {request.target}."
                    ),
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
        except ScanTimeoutError as exc:
            self._timeout(scan_id, request.target, username, exc.user_message)
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

    def _should_retry_unreachable(self, request: ScanRequest) -> bool:
        """Whether a fruitless scan earns one ``-Pn`` retry.

        Three conditions, all of them about not turning this into a blanket
        "ignore host discovery" setting:

        * the target is a single address, not a range - retrying a /24 with
          -Pn would scan every address in it whether or not anything is there;
        * -Pn is not already in the arguments, so this can happen only once;
        * AETHRA-SEC discovered the address itself, which means something
          answered for it on this link and the device is known to exist.

        Without the last condition this would be probing addresses on no
        evidence, which is the behaviour the inventory rules exist to prevent.
        """
        if "-Pn" in request.arguments:
            return False
        target = (request.target or "").strip()
        if not target or "/" in target or "-" in target:
            return False
        try:
            host_id = self._hosts.find_id_by_ip(target)
        except Exception:  # noqa: BLE001 - a lookup failure is not a reason to retry
            return False
        return bool(host_id)

    def _scan_timeout(self) -> float:
        """The wall-clock limit for the next Nmap run, or 0 for none."""
        if self._timeout_provider is None:
            return 0.0
        try:
            return max(0.0, float(self._timeout_provider()))
        except Exception:  # noqa: BLE001 - a bad setting must not stop scanning
            LOGGER.debug("Scan timeout setting unreadable.", exc_info=True)
            return 0.0

    def _timeout(self, scan_id: int, target: str, username: str, message: str) -> None:
        """Record a scan that did not finish in time, with its real reason."""
        try:
            self._scans.mark_timeout(scan_id, message)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not record the scan timeout for %s", scan_id)
        self._audit.record(
            AuditAction.SCAN_TIMED_OUT,
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
    # Identity discovery
    # ------------------------------------------------------------------
    def _discover_identities(
        self, hosts: list[ScanHostResult], runner: Any, scan_xml: str = ""
    ) -> None:
        """Find the hostname and operating system a port scan does not give.

        A port scan answers "what is listening", not "what is this machine".
        Most scan profiles carry no ``-O``, so Nmap emits no fingerprint at
        all, and a device with no PTR record has no name for Nmap's reverse
        lookup to find - which is why both columns arrived empty however good
        the parser was.

        So each host that is up and still missing either field gets one bounded
        follow-up probe: NetBIOS and SMB name queries, plus OS fingerprinting
        where the process has the privileges for it. Anything discovered is
        merged in; anything not is recorded as a note explaining why, and the
        field stays empty so the interface can honestly say "Unknown".

        A failure here never fails the scan. The port results are already good,
        and losing them because a name lookup timed out would be the wrong
        trade.
        """
        if not self._discover_identity:
            return
        pending = [
            host for host in hosts
            if host.status is HostStatus.UP
            and (not host.hostname or not host.os_name)
        ]
        if not pending:
            return
        limit = IDENTITY_MAX_HOSTS
        if len(pending) > limit:
            LOGGER.warning(
                "%d hosts need identity discovery; probing the first %d. The "
                "rest keep their port results and report Unknown.",
                len(pending),
                limit,
            )
        LOGGER.info(
            "Identity discovery for %d host(s) missing a hostname or OS.",
            min(len(pending), limit),
        )
        for host in pending[:limit]:
            try:
                self._discover_one_identity(host, runner, scan_xml)
            except Exception as exc:  # noqa: BLE001 - never fail a scan for this
                LOGGER.warning(
                    "Identity discovery failed for %s: %s", host.ip_address, exc
                )
                host.identity_notes = (
                    *host.identity_notes,
                    f"Identity probe failed: {exc}",
                )

    def _discover_one_identity(
        self, host: ScanHostResult, runner: Any, scan_xml: str = ""
    ) -> None:
        """Probe one host and merge whatever it reported about itself."""
        address = validated_target(host.ip_address)
        privileged = has_raw_socket_privilege()
        request = identity_request(address, privileged)
        result = runner.run(request)
        entry = (result.scan_data.get("scan") or {}).get(address) or {}

        identity = identity_from_scan(entry)
        if not identity.hostname:
            # Two more ways to be told a name, in decreasing authority. The
            # local resolver is a second opinion on Nmap's own lookup - the two
            # differ when a profile passes -n, or when the name lives only in a
            # hosts file. mDNS then covers the devices that answer to a name
            # without any of them: Apple hardware, printers, Avahi on Linux.
            for lookup, source in (
                (reverse_dns, "reverse DNS (local resolver)"),
                (mdns_hostname, "mDNS"),
            ):
                found = lookup(address)
                if found:
                    identity.hostname = found
                    identity.hostname_source = source
                    identity.notes = [
                        note for note in identity.notes
                        if not note.startswith("No hostname")
                    ]
                    break

        if identity.hostname and not host.hostname:
            host.hostname = identity.hostname
            host.hostname_source = identity.hostname_source
        if identity.os_name and not host.os_name:
            host.os_name = identity.os_name
            host.os_version = identity.os_version
            host.os_cpe = identity.os_cpe
            host.os_family = identity.os_family or host.os_family
            host.os_accuracy = identity.os_accuracy
            host.os_source = identity.os_source

        if not host.os_name:
            self._infer_os_from_evidence(host, address, scan_xml, result, identity)
        host.identity_notes = (*host.identity_notes, *identity.notes)

    def _infer_os_from_evidence(
        self,
        host: ScanHostResult,
        address: str,
        scan_xml: str,
        probe_result: Any,
        identity: Any,
    ) -> None:
        """Identify the OS from what the scan already collected.

        This is the answer for the common case, not a consolation prize.
        ``-O`` needs raw sockets and ``smb-os-discovery`` needs a host that
        will talk to an anonymous session, so between them they leave most
        machines unidentified for most operators. But a service scan has
        already gathered several things that name an operating system, and
        ``python-nmap`` discards them before the application ever sees them -
        the reply TTL, the service ``ostype`` attribute, and every service CPE
        but the last. Reading Nmap's own XML recovers them.

        Evidence from the whole scan is pooled: the main scan saw the host's
        real open ports, the identity probe saw 135/139/445. Either can be the
        one that names the platform.

        Every conclusion carries its confidence and the evidence it rests on,
        and a weak signal stays weak - a reply TTL narrows the family and is
        reported as narrowing the family, never promoted to fill a blank cell.
        """
        evidence = parse_xml_evidence(scan_xml, address)
        probe_evidence = parse_xml_evidence(
            getattr(probe_result, "raw_xml", "") or "", address
        )
        evidence.os_cpes.extend(probe_evidence.os_cpes)
        evidence.ostypes.extend(probe_evidence.ostypes)
        evidence.ttls.extend(probe_evidence.ttls)
        evidence.banners.extend(probe_evidence.banners)

        if evidence.is_empty:
            return

        guess = infer_os(evidence)
        if not guess.found:
            return

        host.os_name = guess.name
        host.os_version = guess.version
        host.os_cpe = guess.cpe
        host.os_family = guess.family or host.os_family
        host.os_accuracy = guess.confidence
        host.os_source = "scan evidence"
        identity.notes = [
            note for note in identity.notes
            if not note.startswith("No operating system")
        ]
        identity.notes.append(f"Operating system from {guess.basis}")
        LOGGER.info(
            "OS for %s inferred from scan evidence: %s (%d%%) - %s",
            address,
            guess.name,
            guess.confidence,
            guess.basis,
        )
        LOGGER.info("Identity for %s: %s", host.ip_address, identity.summary())

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
            answered = host.status is HostStatus.UP
            if answered:
                hosts_up += 1

            if answered:
                # The host replied: that is a real observation of it, on this
                # tool, right now.
                host_id = self._hosts.upsert_observed(
                    host.ip_address,
                    observed_at=utcnow(),
                    mac_address=host.mac_address,
                    source=EvidenceSource.NMAP,
                    interface="nmap",
                    detail="answered a scan probe",
                )
            else:
                # Nmap reporting an address *down* is the absence of evidence,
                # not evidence. It must not create an inventory row - that is
                # how scanning a /24 enrols 254 addresses - and it must not
                # move last_seen, which means "when this host was last
                # observed", not "when we last looked for it".
                host_id = self._hosts.find_id_by_ip(host.ip_address) or 0
            host.host_id = host_id or None
            if host_id:
                self._hosts.update_identity(
                    host_id,
                    hostname=host.hostname or None,
                    mac_address=host.mac_address or None,
                    vendor=host.vendor or None,
                    os_name=host.os_name or None,
                    os_version=host.os_version or None,
                    os_cpe=host.os_cpe or None,
                    os_accuracy=host.os_accuracy,
                    status=host.status,
                )
                if answered and self._discover_identity:
                    # Mark the lookup as done whether or not it found a name.
                    #
                    # This used to be `if host.hostname`, so only a *successful*
                    # lookup was recorded. A host with no PTR record was
                    # therefore reported as "Not checked" for ever, however
                    # many times it had in fact been looked up - on this
                    # installation, 1,984 of 2,010 hosts. Recording the attempt
                    # is what lets the interface distinguish "nobody has asked"
                    # from "asked, and this address has no name", which are
                    # different facts and only one of them is worth acting on.
                    self._hosts.mark_hostname_checked([host_id])

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
            scores = (
                extract_script_scores(raw_entry) if isinstance(raw_entry, dict) else {}
            )

            findings = builder.build_for_host(
                host,
                scan_id=scan_id,
                script_references=references,
                host_is_trusted=host.ip_address in trusted,
                script_scores=scores,
            )
            for finding in findings:
                finding.scan_host_id = scan_host_id
                finding.host_id = host_id or None

            # This assessment is now the current picture of the host, so the
            # previous one's findings stop being open. Done before the new
            # rows are written, and deliberately *outside* the "if findings"
            # below: a host that answered and exposes nothing any more is the
            # case that most needs the old set closed.
            #
            # Guarded on `answered`. A scan the host did not reply to observed
            # nothing, so it must never close known exposure - that would let
            # a single unanswered probe erase a real finding.
            if host_id and answered:
                superseded = self._scans.supersede_host_findings(host_id, scan_id)
                if superseded:
                    LOGGER.info(
                        "Superseded %d earlier finding(s) for %s; scan %s is "
                        "now the current assessment.",
                        superseded, host.ip_address, scan_id,
                    )

            if findings:
                self._scans.add_findings(findings)
                total_findings += len(findings)
                self._hosts.set_risk_level(
                    host_id,
                    self._risk.host_risk_level([f.effective_rating for f in findings]),
                )
            elif host.status is HostStatus.UP:
                self._hosts.set_risk_level(host_id, RiskLevel.INFORMATIONAL)
            host.findings = findings

            # Record that this host now has a real assessment result, so it
            # shows in the automatic-assessment table whether the scan was
            # manual or automatic. Guarded against SCANNING hosts inside the
            # repository, so it never races the automatic queue's own settle.
            if host_id:
                self._hosts.record_scan_result(host_id, scan_id)

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
                "concern, risk_level, reference_id, reference_source, "
                "cvss_base_score "
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
                        cvss_base_score=(
                            float(row["cvss_base_score"])
                            if row.get("cvss_base_score") is not None
                            else None
                        ),
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

    def host_evidence(
        self, session: Session, host_id: int, scan_id: int | None
    ) -> tuple[list[Any], Scan | None]:
        """Everything behind one host's security result.

        Returns its open findings and the assessment that produced them, so a
        detail view can show the evidence rather than restating the verdict.
        Both come from stored records; nothing here derives or infers.

        Returns:
            ``(open findings, last scan or None)``.
        """
        self._access.require(session, Permission.SCAN_VIEW, target=str(host_id))
        findings = [
            f for f in self._scans.findings_for_host(int(host_id))
            if f.resolved_at is None
        ]
        scan = self._scans.get_scan(int(scan_id)) if scan_id else None
        # Belt and braces for rows written before findings were superseded on
        # each new scan: an open finding from an *earlier* assessment than the
        # host's latest is stale, and showing it beside the current one made
        # the same port appear once per scan ever run. The stored rows are
        # untouched here - this only decides what the detail view presents as
        # current.
        if scan_id:
            current = [f for f in findings if f.scan_id == int(scan_id)]
            older = len(findings) - len(current)
            if older:
                LOGGER.debug(
                    "Host %s has %d open finding(s) from assessments earlier "
                    "than scan %s; showing only the current assessment.",
                    host_id, older, scan_id,
                )
                findings = current
        return findings, scan

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
