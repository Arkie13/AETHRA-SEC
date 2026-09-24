"""Automatic assessment of hosts the sensor has actually observed (§124).

Vulnerability assessment required an operator to type an address. Every host
in the inventory arrived there because PyShark saw it send a frame, so the
address was already known - the operator was retyping something the system had
observed minutes earlier.

This service closes that loop::

    PyShark observes a frame
        -> host upserted into the inventory (packet_capture)
        -> this service selects hosts that are due
        -> NmapService.start_scan  (the existing, authorised path)
        -> results persisted by NmapService
        -> Hosts, Vulnerabilities and Dashboard read them back

Two things it is deliberately not
--------------------------------
**It is not a scanner.** It selects targets and hands each to
:class:`~aethra_sec.services.nmap_service.NmapService`, which already
validates the target, enforces the authorised networks, checks the
``scan.run`` permission, audits the decision and runs Nmap on a worker
thread. Re-implementing any of that here would create a second path to the
same subprocess with different rules - and only one of them would have been
reviewed.

**It is not a host discoverer.** Discovery is what the capture pipeline
already does from real packets. This reads the inventory that produces; it
never invents a host, never sweeps a range, and never adds an address that
was not observed.

What keeps it from becoming a network scanner
---------------------------------------------
Independent limits, each of which alone would stop a runaway:

* **Scope.** Only hosts inside the *monitored* authorised network are ever
  selected - the subnet of the adapter capture is using, intersected with the
  configured authorised ranges (:mod:`aethra_sec.analytics.assessment_scope`).
  When that cannot be determined, automatic assessment stops and says so.
* **Cooldown.** A host assessed inside the reassessment interval is not due,
  so a chatty host cannot trigger a scan per packet.
* **Concurrency.** At most ``max_concurrent`` scans run at once, so a burst of
  new hosts becomes a queue rather than a hundred processes.
* **Back-off and attempt cap.** A failed or timed-out assessment is retried
  after a growing delay, and after the cap only at the reassessment interval,
  instead of every cycle.
* **Liveness.** A host not observed recently is not scanned; it is assessed
  when it transmits again.

State lives on the host row, not in memory, so a restart resumes rather than
rescanning the network from scratch.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from aethra_sec.analytics.assessment_scope import UNAVAILABLE_MESSAGE, AssessmentScope
from aethra_sec.core.errors import AethraError, SessionExpiredError
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.hosts import HostRepository
from aethra_sec.models.enums import (
    AssessmentState,
    EvidenceSource,
    HostStatus,
    ScanTrigger,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import local_ipv4_networks
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.assessment_queue")

#: Settings keys, so the screen and this service cannot disagree about them.
SETTING_ENABLED = "assessment.auto_enabled"
SETTING_NEW_HOSTS = "assessment.auto_new_hosts"
SETTING_INTERVAL_HOURS = "assessment.reassess_hours"
SETTING_MAX_CONCURRENT = "assessment.max_concurrent"
SETTING_PROFILE = "assessment.auto_profile"
SETTING_SCRIPTS = "assessment.script_categories"
SETTING_EXCLUDED = "assessment.excluded_addresses"
SETTING_MAX_ATTEMPTS = "assessment.max_attempts"
SETTING_RETRY_MINUTES = "assessment.retry_base_minutes"

#: How long a resolved scope is reused. Resolving reads the adapter table, and
#: the screen asks for statistics every few seconds.
SCOPE_CACHE_SECONDS = 30.0

#: Terminal scan statuses that settle a host.
_TERMINAL = ("COMPLETED", "FAILED", "CANCELLED", "TIMEOUT")


@dataclass
class QueueStatistics:
    """What the automation is doing, counted from the inventory."""

    enabled: bool = False
    discovered: int = 0
    queued: int = 0
    scanning: int = 0
    completed: int = 0
    failed: int = 0
    timeout: int = 0
    skipped: int = 0
    cooldown: int = 0
    due_now: int = 0
    last_assessment_at: Any = None
    last_discovery_at: Any = None
    detail: str = ""
    #: Whether automatic assessment has a usable scope, and what it is.
    scope_available: bool = True
    scope_text: str = ""

    @property
    def total(self) -> int:
        """Hosts in the inventory, whatever their state."""
        return (
            self.discovered + self.queued + self.scanning + self.completed
            + self.failed + self.timeout + self.skipped + self.cooldown
        )


class AssessmentQueueService:
    """Selects observed hosts for assessment and hands them to Nmap."""

    def __init__(
        self,
        hosts: HostRepository,
        nmap: Any,
        settings: Any,
        *,
        authorized_networks: tuple[str, ...] = (),
        scope_provider: Callable[[], AssessmentScope] | None = None,
        audit: Any = None,
        sessions: Any = None,
    ) -> None:
        """Wire the service to the inventory, Nmap and the settings.

        Args:
            authorized_networks: configured authorised ranges. Used on their
                own only when no ``scope_provider`` is given.
            scope_provider: resolves the monitored authorised network. The
                application always supplies one; without it the service falls
                back to the configured ranges alone.
            audit: records scope transitions and queued assessments.
            sessions: the session manager, used only to keep the automation's
                own session from idling out between due hosts. Optional so
                existing callers and tests keep working; without it the cycle
                simply does not refresh, which is the old behaviour.
        """
        self._hosts = hosts
        self._nmap = nmap
        self._settings = settings
        self._authorized = tuple(authorized_networks)
        self._scope_provider = scope_provider
        self._audit = audit
        self._sessions = sessions
        self._lock = threading.Lock()
        #: Scan id -> host id, so a completion can be attributed back.
        self._in_flight: dict[int, int] = {}
        self._session: Session | None = None
        self._last_detail = "Automatic assessment has not run yet."
        self._scope: AssessmentScope | None = None
        self._scope_at = 0.0
        self._scope_signature = ""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def attach_session(self, session: Session | None) -> None:
        """Provide the session automatic scans run under.

        Automatic assessment still runs *as somebody*: the scan is audited
        against that session and refused if it lacks ``scan.run``. Without a
        session the service stays idle rather than scanning unattributed.
        """
        self._session = session

    @property
    def enabled(self) -> bool:
        """Whether automatic assessment is switched on.

        The fallback matches the seeded default (:data:`SETTING_ENABLED` is on):
        an installation that has never touched the setting gets automatic
        assessment, bounded by the monitored authorised network - which does
        nothing until capture runs on an interface inside a configured range.
        """
        return bool(self._settings.get_bool(SETTING_ENABLED, True))

    def set_enabled(self, session: Session, enabled: bool) -> None:
        """Pause or resume automatic assessment.

        Goes through the settings service, so the change needs
        ``settings.manage``, is audited, and survives a restart. Pausing an
        automatic scanner is a security-relevant act in both directions and
        should not be a private flag on this object.
        """
        self._settings.set(session, SETTING_ENABLED, bool(enabled))

    def _script_categories(self) -> tuple[str, ...]:
        """NSE categories for automatic assessment, as configured.

        Whatever is returned is validated again by ``build_scan_request``
        against the allowed list, so a category an administrator should not be
        able to run is refused there even if it is typed in here.
        """
        try:
            raw = str(self._settings.get(SETTING_SCRIPTS, "vuln") or "")
        except Exception:  # noqa: BLE001 - a bad setting must not stop scanning
            return ("vuln",)
        return tuple(part.strip() for part in raw.split(",") if part.strip())

    def _interval(self) -> timedelta:
        """How long before an assessed host is due again."""
        hours = max(1, self._settings.get_int(SETTING_INTERVAL_HOURS, 6))
        return timedelta(hours=hours)

    def _max_concurrent(self) -> int:
        """How many assessments may run at once."""
        return max(1, min(self._settings.get_int(SETTING_MAX_CONCURRENT, 2), 8))

    def _excluded(self) -> set[str]:
        """Addresses an operator has excluded from automatic assessment."""
        raw = str(self._settings.get(SETTING_EXCLUDED, "") or "")
        return {part.strip() for part in raw.replace(";", ",").split(",") if part.strip()}

    def _retry_delay(self, attempts: int) -> timedelta:
        """Back-off before retrying a failed or timed-out assessment.

        Doubles per consecutive failure, from the configured base, and never
        exceeds the reassessment interval.
        """
        base = max(1, self._settings.get_int(SETTING_RETRY_MINUTES, 5))
        interval = self._interval()
        # The exponent is capped: an attempt counter in the hundreds would
        # otherwise overflow timedelta long before the interval cap applied.
        exponent = min(max(0, attempts - 1), 20)
        minutes = base * (2**exponent)
        if minutes * 60 >= interval.total_seconds():
            return interval
        return timedelta(minutes=minutes)

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    def scope(self, *, refresh: bool = False) -> AssessmentScope | None:
        """The current automatic assessment scope, or ``None`` in legacy mode."""
        if self._scope_provider is None:
            return None
        now = time.monotonic()
        if refresh or self._scope is None or (now - self._scope_at) > SCOPE_CACHE_SECONDS:
            try:
                self._scope = self._scope_provider()
            except Exception as exc:  # noqa: BLE001 - never break the scheduler
                LOGGER.exception("Could not resolve the assessment scope.")
                self._scope = AssessmentScope(
                    available=False, reason=f"The scope could not be resolved: {exc}"
                )
            self._scope_at = now
            self._note_scope_change(self._scope)
        return self._scope

    def _note_scope_change(self, scope: AssessmentScope) -> None:
        """Log and audit a scope transition once, not on every cycle."""
        signature = scope.signature
        if signature == self._scope_signature:
            return
        self._scope_signature = signature
        LOGGER.info(scope.describe())
        if self._audit is None:
            return
        try:
            from aethra_sec.security.audit import AuditAction, AuditCategory

            self._audit.record(
                AuditAction.ASSESSMENT_SCOPE_CHANGED
                if scope.available
                else AuditAction.ASSESSMENT_SCOPE_UNAVAILABLE,
                category=AuditCategory.ASSESSMENT,
                target_type="assessment_scope",
                target_id=",".join(str(n) for n in scope.networks) or "none",
                result="SUCCESS" if scope.available else "FAILURE",
                detail=scope.describe(),
            )
        except Exception:  # noqa: BLE001 - auditing must not stop the cycle
            LOGGER.debug("Could not audit the scope change.", exc_info=True)

    # ------------------------------------------------------------------
    # Eligibility
    # ------------------------------------------------------------------
    def is_authorized(self, address: str) -> bool:
        """True when an address lies inside the automatic assessment boundary.

        With a scope provider this is the monitored authorised network; without
        one, the configured authorised ranges.
        """
        scope = self.scope()
        if scope is not None:
            return scope.is_assessable_address(address)
        if not address:
            return False
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        for network in self._authorized:
            try:
                if parsed in ipaddress.ip_network(network, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _is_own_address(self, address: str) -> bool:
        """True for one of the monitoring machine's own addresses."""
        scope = self._scope
        if scope is not None and address in scope.own_addresses:
            return True
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        for network in local_ipv4_networks():
            if parsed == network.network_address:
                return True
        try:
            import psutil
            import socket

            for entries in psutil.net_if_addrs().values():
                for entry in entries:
                    if entry.family == socket.AF_INET and entry.address == address:
                        return True
        except Exception:  # noqa: BLE001
            return False
        return False

    def eligibility(self, host: Any) -> tuple[bool, AssessmentState, str]:
        """Whether one host may be assessed now, and why not when it may not.

        Returns:
            ``(due, state, reason)``. ``state`` is what the host row should be
            set to, so a refusal is recorded rather than being re-decided on
            every cycle.
        """
        address = str(getattr(host, "ip_address", "") or "")
        current = getattr(host, "assessment_state", AssessmentState.DISCOVERED)
        if not address:
            return False, AssessmentState.SKIPPED, "no address"
        if address in self._excluded():
            return False, AssessmentState.SKIPPED, "excluded by configuration"
        if not self.is_authorized(address):
            if self._scope_provider is not None:
                scope = self._scope
                if scope is not None and scope.contains(address):
                    return (
                        False,
                        AssessmentState.SKIPPED,
                        "not a unicast host address (network, broadcast or multicast)",
                    )
                return (
                    False,
                    AssessmentState.SKIPPED,
                    "outside the monitored authorised network",
                )
            return (
                False,
                AssessmentState.SKIPPED,
                "outside the authorised networks",
            )
        if self._is_own_address(address):
            return False, AssessmentState.SKIPPED, "the monitoring host itself"

        # A row this installation cannot vouch for is not a scanning target.
        # These are addresses an older pipeline entered after seeing them
        # merely named on the wire - the destinations of an ARP sweep, mostly -
        # and nothing has ever been observed transmitting from them. Scanning
        # them would probe addresses on no evidence that anything is there,
        # and on this installation that is 1,565 of 2,005 rows. They are kept
        # for their history; they are simply never queued.
        if getattr(host, "discovery_source", None) is EvidenceSource.LEGACY:
            return (
                False,
                AssessmentState.SKIPPED,
                "legacy record - origin unknown, never observed transmitting",
            )

        if current in (AssessmentState.QUEUED, AssessmentState.SCANNING):
            return False, current, "already queued or scanning"

        # A host that has stopped transmitting is not *re*-scanned: the scan
        # would only confirm it is gone, and an automatic scanner should not
        # keep probing an address nobody is using.
        #
        # But a host that has never been assessed at all is different. ARP
        # discovery proved a device answered for that address, and a device
        # can go quiet between being discovered and the queue reaching it -
        # phones do this constantly. Skipping it there left it at DISCOVERED
        # permanently: on this installation 42 of 83 hosts on the monitored
        # subnet had never been assessed once, every one of them for this
        # reason. So a first attempt is always made; only re-assessment waits
        # for the host to be seen again.
        never_assessed = (
            int(getattr(host, "assessment_attempts", 0) or 0) == 0
            and getattr(host, "last_assessed_at", None) is None
            and getattr(host, "last_scan_id", None) is None
        )
        if getattr(host, "status", None) is HostStatus.DOWN and not never_assessed:
            waiting = (
                current if current is not AssessmentState.SKIPPED
                else AssessmentState.DISCOVERED
            )
            return False, waiting, "offline: not observed recently"

        now = utcnow()
        attempts = int(getattr(host, "assessment_attempts", 0) or 0)
        last = getattr(host, "last_assessed_at", None)
        last_attempt = getattr(host, "last_attempt_at", None)
        cap = max(1, self._settings.get_int(SETTING_MAX_ATTEMPTS, 3))
        unfinished = last_attempt is not None and (last is None or last_attempt > last)
        if current in (AssessmentState.FAILED, AssessmentState.TIMEOUT) or unfinished:
            if attempts >= cap:
                wait = self._interval()
                why = f"retry limit reached after {attempts} attempt(s)"
            else:
                wait = self._retry_delay(attempts)
                why = "retry back-off"
            if last_attempt is not None and (now - last_attempt) < wait:
                keep = (
                    current
                    if current in (AssessmentState.FAILED, AssessmentState.TIMEOUT)
                    else AssessmentState.DISCOVERED
                )
                remaining = int((wait - (now - last_attempt)).total_seconds() // 60) + 1
                return False, keep, f"{why}; next attempt in about {remaining} min"
            if last_attempt is None and attempts >= cap:
                # Legacy rows with no attempt time: honour the cap without
                # retrying on every cycle.
                keep = (
                    current
                    if current in (AssessmentState.FAILED, AssessmentState.TIMEOUT)
                    else AssessmentState.DISCOVERED
                )
                return False, keep, why
            return True, AssessmentState.QUEUED, "retry"

        if last is not None and (now - last) < self._interval():
            return False, AssessmentState.COOLDOWN, "assessed recently"

        if last is None and not self._settings.get_bool(SETTING_NEW_HOSTS, True):
            return (
                False,
                AssessmentState.DISCOVERED,
                "assessment of new hosts is switched off",
            )
        return True, AssessmentState.QUEUED, "due"

    @staticmethod
    def _priority(host: Any) -> tuple[int, float]:
        """Order due hosts: never assessed first, then retries, then reassessment.

        Inside each group the most recently seen host goes first, because it is
        the one most likely to still be there when Nmap reaches it.
        """
        state = getattr(host, "assessment_state", AssessmentState.DISCOVERED)
        if getattr(host, "last_assessed_at", None) is None and state not in (
            AssessmentState.FAILED, AssessmentState.TIMEOUT,
        ):
            group = 0
        elif state in (AssessmentState.FAILED, AssessmentState.TIMEOUT):
            group = 1
        else:
            group = 2
        seen = getattr(host, "last_seen", None)
        return group, -(seen.timestamp() if seen is not None else 0.0)

    # ------------------------------------------------------------------
    # The cycle
    # ------------------------------------------------------------------
    def run_cycle(self) -> int:
        """Assess the hosts that are due, within the concurrency limit.

        Called from the background scheduler. Never raises: a failure here
        must not stop capture, correlation or the interface.

        Returns:
            How many assessments were started this cycle.
        """
        if not self.enabled:
            self._last_detail = "Automatic assessment is paused."
            return 0
        session = self._session
        if session is None:
            self._last_detail = "No session: automatic assessment is idle."
            return 0
        # Keep this cycle's own session alive. It is the queue's session, not
        # the operator's console session, so refreshing it here does not hold
        # an unattended interface signed in - see ApplicationContext.set_session.
        #
        # Without this the session idled out between due hosts: the cooldown is
        # measured in hours and the idle timeout in minutes, so every scan
        # after the first quiet hour was refused and its host recorded as
        # SKIPPED. That is an artificial timeout on the automation, and the
        # hosts it skipped were never the problem.
        self._touch_session(session)

        try:
            # Settle first, so a finished scan frees its slot even while the
            # scope is unavailable.
            self._reap_finished()
            scope = self.scope(refresh=True)
            if scope is not None and not scope.available:
                self._last_detail = f"{UNAVAILABLE_MESSAGE} {scope.reason}".strip()
                return 0
            free = self._max_concurrent() - len(self._in_flight)
            if free <= 0:
                self._last_detail = (
                    f"{len(self._in_flight)} assessment(s) running; at the limit."
                )
                return 0
            if scope is None:
                candidates = self._hosts.assessment_candidates(limit=200)
            else:
                candidates = self._hosts.assessment_candidates(
                    limit=500, ranges=scope.address_ranges
                )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not select hosts for assessment.")
            return 0

        started = 0
        for host in sorted(candidates, key=self._priority):
            if started >= free:
                break
            due, state, reason = self.eligibility(host)
            host_id = int(getattr(host, "id", 0) or 0)
            if not due:
                # Record the decision so an operator can see why a host was
                # passed over rather than wondering whether it was missed.
                if state is not getattr(host, "assessment_state", None) or (
                    reason != getattr(host, "assessment_detail", reason)
                ):
                    self._safe_state(host_id, state, detail=reason)
                continue
            if self._start(session, host, reason):
                started += 1

        if started:
            self._last_detail = f"Started {started} assessment(s)."
        elif not self._in_flight:
            self._last_detail = "No hosts are due for assessment."
        return started

    def _start(self, session: Session, host: Any, reason: str) -> bool:
        """Hand one host to Nmap through the existing authorised path."""
        address = str(getattr(host, "ip_address", "") or "")
        host_id = int(getattr(host, "id", 0) or 0)
        first_time = getattr(host, "last_assessed_at", None) is None
        trigger = (
            ScanTrigger.AUTOMATIC_DISCOVERY
            if first_time
            else ScanTrigger.SCHEDULED_REASSESSMENT
        )
        self._safe_state(
            host_id, AssessmentState.QUEUED, detail=reason, attempt_started=True
        )
        self._audit_queued(session, host_id, address, trigger, reason)
        try:
            scan_id = self._nmap.start_scan(
                session,
                address,
                profile_key=str(
                    self._settings.get(SETTING_PROFILE, "standard") or "standard"
                ),
                # Without these the assessment can only report which ports are
                # open. That is exposure; a host is classified Vulnerable only
                # on evidence a scanner can point at, and for Nmap that
                # evidence comes from the vuln scripts.
                script_categories=self._script_categories(),
                trigger=trigger,
            )
        except SessionExpiredError as exc:
            # Nothing about the host. The automation's own credentials lapsed,
            # and recording that as SKIPPED blamed the device for a fault on
            # this side - which is how real hosts came to sit permanently
            # "skipped" with a session error as their reason. The host is left
            # where it was so the next cycle reconsiders it normally.
            LOGGER.warning(
                "Automatic assessment of %s could not be authorised: %s",
                address, exc.user_message,
            )
            self._safe_state(
                host_id, AssessmentState.DISCOVERED,
                detail="waiting: the automation session needs to be re-established",
            )
            return False
        except AethraError as exc:
            # A refusal that *is* about the target: unauthorised, out of scope
            # or unresolvable. It will refuse identically next cycle, so it is
            # recorded rather than retried blindly.
            LOGGER.warning(
                "Automatic assessment of %s refused: %s", address, exc.user_message
            )
            self._safe_state(
                host_id, AssessmentState.SKIPPED, attempt=True,
                detail=f"refused: {exc.user_message}",
            )
            return False
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Automatic assessment of %s could not start.", address)
            self._safe_state(
                host_id, AssessmentState.FAILED, attempt=True,
                detail=f"could not start: {exc}",
            )
            return False

        with self._lock:
            self._in_flight[int(scan_id)] = host_id
        self._safe_state(
            host_id, AssessmentState.SCANNING, scan_id=int(scan_id),
            detail=f"scan {scan_id} running",
        )
        LOGGER.info(
            "Automatic assessment %s started for %s (%s, %s).",
            scan_id, address, trigger, reason,
        )
        return True

    def _touch_session(self, session: Session) -> None:
        """Refresh the automation session's idle clock, if it is still live.

        A revoked or already-expired session is left alone: the next scan will
        be refused, which is the correct outcome, and reviving it here would
        let automation outlive the sign-in that authorised it.
        """
        sessions = self._sessions
        if sessions is None:
            return
        try:
            live = sessions.get(session.token)
            if live is not None:
                live.touch(sessions.timeout_minutes)
        except Exception:  # noqa: BLE001 - a refresh must never stop the cycle
            LOGGER.debug("Could not refresh the automation session.", exc_info=True)

    def _audit_queued(
        self, session: Session, host_id: int, address: str, trigger: Any, reason: str
    ) -> None:
        """Record that automation queued an assessment, and why."""
        if self._audit is None:
            return
        try:
            from aethra_sec.security.audit import AuditAction, AuditCategory

            self._audit.record(
                AuditAction.ASSESSMENT_QUEUED,
                session=session,
                category=AuditCategory.ASSESSMENT,
                target_type="host",
                target_id=host_id or address,
                detail=(
                    f"Automatic assessment queued for {address} "
                    f"({trigger}; {reason})."
                ),
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not audit the queued assessment.", exc_info=True)

    def _reap_finished(self) -> None:
        """Settle every host whose scan has reached a terminal state.

        Driven by the *scan row*, not by in-memory bookkeeping. An earlier
        version compared against ``NmapService.running_scans()``, which is a
        live structure owned by another service: when a scan left it at a
        moment this did not observe, the host stayed SCANNING for good - and
        because a SCANNING host is skipped as already in progress, it would
        never have been assessed again.

        Reading the row also settles hosts left behind by a process that was
        killed mid-scan, which no in-memory list could know about.
        """
        db = getattr(self._hosts, "db", None)
        if db is None:
            return
        try:
            rows = db.query(
                "SELECT h.id AS host_id, s.id AS scan_id, s.status AS status, "
                "s.hosts_up AS hosts_up, s.error_message AS error_message "
                "FROM hosts h JOIN scans s ON s.id = h.last_scan_id "
                "WHERE h.assessment_state = %s AND s.status IN "
                "('COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT')",
                (str(AssessmentState.SCANNING),),
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not settle finished assessments.", exc_info=True)
            return

        for row in rows:
            scan_id = int(row["scan_id"])
            host_id = int(row["host_id"])
            status = str(row["status"]).upper()
            error = str(row.get("error_message") or "")
            with self._lock:
                self._in_flight.pop(scan_id, None)
            if status == "COMPLETED":
                # Nmap finishing and the host answering are two different
                # facts. A scan that completed against a host that never
                # replied examined nothing, so it settles as NO_RESPONSE:
                # recording it as COMPLETED beside "0 open ports, 0 findings"
                # presented an unexamined host as a clean one.
                #
                # The attempt counter is deliberately not advanced, because a
                # silent host is not a failing scan and burning the attempt
                # cap on it would stop it ever being tried again once it came
                # back. It is still stamped as assessed, so the reassessment
                # cooldown paces it: without that stamp the scan counts as
                # unfinished and the host is re-queued every few minutes for
                # as long as it stays quiet, which on a subnet of mostly
                # silent addresses is a scan storm.
                answered = int(row.get("hosts_up") or 0) > 0
                if answered:
                    self._safe_state(
                        host_id, AssessmentState.COMPLETED, assessed=True,
                        detail=f"scan {scan_id} completed",
                    )
                else:
                    self._safe_state(
                        host_id, AssessmentState.NO_RESPONSE, assessed=True,
                        detail=(
                            f"scan {scan_id} completed; the host did not "
                            "answer, so nothing was examined"
                        ),
                    )
            elif status == "TIMEOUT":
                self._safe_state(
                    host_id, AssessmentState.TIMEOUT, attempt=True,
                    detail=f"scan {scan_id} timed out",
                )
            elif status == "CANCELLED":
                # Stopped by an operator or by shutdown: not a failure of the
                # host, so the attempt counter is left alone.
                self._safe_state(
                    host_id, AssessmentState.DISCOVERED,
                    detail=f"scan {scan_id} was cancelled",
                )
            else:
                self._safe_state(
                    host_id, AssessmentState.FAILED, attempt=True,
                    detail=f"scan {scan_id} failed: {error}"[:255],
                )
            LOGGER.info(
                "Assessment %s for host %s settled as %s.", scan_id, host_id, status
            )

    def _safe_state(
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
        """Record a state change, never raising into the scheduler."""
        if not host_id:
            return
        try:
            self._hosts.set_assessment_state(
                host_id, state, assessed=assessed, attempt=attempt,
                scan_id=scan_id, detail=detail, attempt_started=attempt_started,
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not update assessment state.", exc_info=True)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def statistics(self) -> QueueStatistics:
        """Counted from the inventory, never from an in-memory tally."""
        stats = QueueStatistics(enabled=self.enabled, detail=self._last_detail)
        scope = self.scope()
        if scope is not None:
            stats.scope_available = scope.available
            stats.scope_text = scope.describe()
        try:
            counts = self._hosts.assessment_state_counts()
        except Exception:  # noqa: BLE001
            stats.detail = "The host inventory could not be read."
            return stats
        stats.discovered = counts.get(str(AssessmentState.DISCOVERED), 0)
        stats.queued = counts.get(str(AssessmentState.QUEUED), 0)
        stats.scanning = counts.get(str(AssessmentState.SCANNING), 0)
        stats.completed = counts.get(str(AssessmentState.COMPLETED), 0)
        stats.failed = counts.get(str(AssessmentState.FAILED), 0)
        stats.timeout = counts.get(str(AssessmentState.TIMEOUT), 0)
        stats.skipped = counts.get(str(AssessmentState.SKIPPED), 0)
        stats.cooldown = counts.get(str(AssessmentState.COOLDOWN), 0)
        try:
            stats.last_assessment_at = self._hosts.last_assessment_time()
            stats.last_discovery_at = self._hosts.last_discovery_time()
            if scope is None:
                candidates = self._hosts.assessment_candidates(limit=500)
            elif scope.available:
                candidates = self._hosts.assessment_candidates(
                    limit=500, ranges=scope.address_ranges
                )
            else:
                candidates = []
            stats.due_now = sum(1 for host in candidates if self.eligibility(host)[0])
        except Exception:  # noqa: BLE001
            pass
        return stats
