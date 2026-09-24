"""Network host inventory models (§15, §46, §47)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.models.enums import (
    AssessmentState,
    EvidenceSource,
    HostStatus,
    RiskLevel,
)


@dataclass(frozen=True)
class SecurityResult:
    """What an assessment concluded about a host, stated honestly.

    ``tone`` is a display hint - ``critical``/``warning``/``ok``/``info``/
    ``muted`` - not a second severity. The point of this type is that missing
    or failed evidence is never rendered as safety: only :data:`NO_FINDINGS`
    means "the assessment ran, the host answered, and it reported nothing", and
    it is reachable by exactly one path below.
    """

    code: str
    label: str
    tone: str


#: The assessment ran against a host that answered and reported no findings.
#: It means exactly that - the configured assessment found nothing - and never
#: "this host is secure".
NO_FINDINGS = SecurityResult("NO_FINDINGS", "No findings", "ok")
#: §3.9.9: the highest open finding is rated High or Critical (CVSS >= 7.0).
VULNERABLE = SecurityResult("VULNERABLE", "Vulnerable", "critical")
#: §3.9.9: the highest open finding is rated Medium (CVSS 4.0-6.9).
AT_RISK = SecurityResult("AT_RISK", "At risk", "warning")
#: §3.9.9 "Safe" band with findings present: every open finding is below
#: Medium (CVSS < 4.0). Named for what it is rather than "Safe", because an
#: exposure rated Low is still an exposure.
LOW_FINDINGS = SecurityResult("LOW_FINDINGS", "Low-rated findings only", "ok")
SCANNING = SecurityResult("SCANNING", "Scanning", "info")
QUEUED = SecurityResult("QUEUED", "Queued", "info")
NOT_ASSESSED = SecurityResult("NOT_ASSESSED", "Not assessed", "muted")
#: A completed scan in which the host did not answer (Nmap: 0 hosts up).
#:
#: Labelled for the *assessment*, not the host. "Offline (no scan response)"
#: mixed the two: it read as a claim about the device when it is a statement
#: that the scan got nothing back, and the host's own UP/OFFLINE state is a
#: separate column.
OFFLINE = SecurityResult("OFFLINE", "No response", "warning")
#: Retained name: earlier code and tests call the same result NO_RESPONSE.
NO_RESPONSE = OFFLINE
#: Nmap did not finish in its time limit, or abandoned the host.
TIMEOUT = SecurityResult("TIMEOUT", "Timeout", "warning")
SCAN_FAILED = SecurityResult("SCAN_FAILED", "Scan failed", "warning")
SCAN_CANCELLED = SecurityResult("CANCELLED", "Scan cancelled", "muted")
# SKIPPED inside the scope means excluded by configuration or the monitor's own
# address; the reason is stored beside the state and shown with it.
NOT_AUTHORISED = SecurityResult("NOT_AUTHORISED", "Skipped", "muted")
#: Not inside the monitored authorised network, so automation never touches it.
OUT_OF_SCOPE = SecurityResult("OUT_OF_SCOPE", "Outside assessment scope", "muted")
RESULT_UNKNOWN = SecurityResult("UNKNOWN", "Unknown", "muted")

#: Results that describe a host an assessment has judged, in severity order.
FINDING_RESULTS: tuple[SecurityResult, ...] = (VULNERABLE, AT_RISK, LOW_FINDINGS)

#: A completed assessment that found no *confirmed* vulnerability.
#:
#: The only security result the interface colours. It says what was
#: established - the configured assessment completed and nothing it can
#: confirm was found - and never that the host is secure in general. Open
#: ports may still be listed against it as exposure; an exposure is not a
#: vulnerability.
SAFE = SecurityResult("SAFE", "Safe", "ok")

#: The assessment did not reach a conclusion, so there is nothing to state.
#:
#: Queued, scanning, no response, timed out, failed: each has its own
#: assessment status, and the security column stays empty rather than
#: borrowing one of the two conclusions it has not earned.
NOT_DETERMINED = SecurityResult("NOT_DETERMINED", "-", "muted")


def is_confirmed_vulnerability(
    *,
    verification_required: bool,
    cvss_base_score: float | None,
    risk_level: "RiskLevel | None",
    reference_id: str = "",
) -> bool:
    """Whether one finding is evidence of a vulnerability, not just exposure.

    The distinction this function exists to keep:

    * **Exposure** - Nmap saw a port open and named the service. True, worth
      recording, and by itself no evidence that anything is wrong. Most of an
      ordinary network looks like this.
    * **Vulnerability** - something the scanner can point at: a CVE an NSE
      script reported, a CVSS score, or a configured knowledge-base entry
      matching the detected product and version.

    Only the second may make a host "Vulnerable". An open RDP port is not a
    vulnerability, and neither is an unidentified service, a device type or a
    version the scanner merely printed.

    ``verification_required`` is the parser's own answer: it is set false only
    when a reference was attached, so it already carries the distinction.
    """
    if reference_id.strip():
        return True
    if not verification_required:
        return True
    if cvss_base_score is not None:
        return True
    return risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


#: SQL for the same rule, so the column and the Python agree by construction.
#: ``f`` is the ``scan_findings`` alias in the caller's query.
CONFIRMED_FINDING_SQL = (
    "(f.reference_id IS NOT NULL AND f.reference_id <> '') "
    "OR f.verification_required = 0 "
    "OR f.cvss_base_score IS NOT NULL "
    "OR f.risk_level IN ('HIGH', 'CRITICAL')"
)


def cvss_band(score: float | None) -> RiskLevel | None:
    """The CVSS v3.1 qualitative rating for a base score (FIRST, 2019).

    None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9),
    Critical (9.0-10.0). ``None`` when no score exists - never a default.
    """
    if score is None:
        return None
    if score >= 9.0:
        return RiskLevel.CRITICAL
    if score >= 7.0:
        return RiskLevel.HIGH
    if score >= 4.0:
        return RiskLevel.MEDIUM
    if score > 0.0:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL


def classify_by_highest_finding(highest: RiskLevel | None) -> SecurityResult:
    """§3.9.9: the host class follows its highest-rated open finding."""
    if highest in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return VULNERABLE
    if highest is RiskLevel.MEDIUM:
        return AT_RISK
    return LOW_FINDINGS


def derive_security_result(
    assessment_state: "AssessmentState",
    *,
    finding_count: int,
    last_scan_status: str,
    last_scan_hosts_up: int | None,
    last_assessed_at: datetime | None,
    highest_finding: RiskLevel | None = None,
    confirmed_finding_count: int = 0,
) -> SecurityResult:
    """Decide a host's security result from real assessment evidence only.

    There are exactly three answers, and two of them require a completed
    assessment:

    * **Vulnerable** - the assessment completed and the scanner produced
      evidence of a vulnerability it can point at: a CVE from an NSE script,
      a CVSS score, or a configured knowledge-base entry. An open port is not
      such evidence, however exposed it is.
    * **Safe** - the assessment completed, the host answered, and none of its
      findings is confirmed. It says the configured assessment found nothing
      it can confirm, not that the host is secure.
    * **-** (:data:`NOT_DETERMINED`) - everything else. Queued, scanning, no
      response, timed out, failed: the assessment reached no conclusion, so
      the column states none. The assessment status beside it says which.

    An unreachable host is never Safe, and a failed scan is never Safe. Both
    are simply undetermined, which is the honest answer when nothing was
    established.

    Args:
        confirmed_finding_count: open findings that are evidence of a
            vulnerability rather than of exposure. See
            :func:`is_confirmed_vulnerability`.
        finding_count: all open findings, confirmed or not. Used only to
            distinguish "nothing found" from "exposure recorded" in the
            detail view; it never makes a host Vulnerable on its own.
        highest_finding: retained for the detail view and reports, which still
            grade exposures by §3.9.9. It does not decide this result.
    """
    # Confirmed evidence outranks every lifecycle state. A stored confirmed
    # finding is itself proof that an assessment ran and found it, so the
    # verdict survives a re-scan in progress, a pruned scan row, and the host
    # going offline afterwards. Suppressing a known vulnerability because the
    # queue happens to be re-scanning would hide the one thing worth showing;
    # the assessment column still reports SCANNING beside it.
    if confirmed_finding_count > 0:
        return VULNERABLE

    if assessment_state is AssessmentState.SCANNING:
        return SCANNING
    if assessment_state is AssessmentState.QUEUED:
        return QUEUED
    if assessment_state is AssessmentState.SKIPPED:
        return NOT_AUTHORISED
    if assessment_state is AssessmentState.FAILED:
        return SCAN_FAILED
    if assessment_state is AssessmentState.TIMEOUT:
        return TIMEOUT
    if assessment_state is AssessmentState.NO_RESPONSE:
        # Stated explicitly rather than inferred from the scan row, so the
        # answer survives the scan being pruned by retention. A host that
        # never answered is never Safe.
        return NO_RESPONSE

    status = (last_scan_status or "").upper()
    assessed = assessment_state in (
        AssessmentState.COMPLETED,
        AssessmentState.COOLDOWN,
    ) or last_assessed_at is not None

    if status == "FAILED":
        return SCAN_FAILED
    if status == "TIMEOUT":
        return TIMEOUT
    if status == "CANCELLED":
        return SCAN_CANCELLED
    if not assessed:
        return NOT_ASSESSED

    if status == "COMPLETED":
        # A completed scan in which nothing answered establishes nothing
        # about the host's security. It is not Safe; it is undetermined.
        if (last_scan_hosts_up or 0) <= 0:
            return NOT_DETERMINED
        return SAFE

    # Assessed at some point, but the last scan's outcome is not recorded (an
    # older record, or a scan row that has gone). Do not guess safety.
    return NOT_DETERMINED


@dataclass
class Host:
    """A host AETHRA-SEC has actually observed or scanned.

    Every field is populated from a real observation. ``hostname`` stays empty
    when reverse resolution fails - the UI then shows the IP address rather
    than inventing a name (§15).
    """

    id: int | None
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    #: When reverse DNS was last attempted. ``None`` means never, which is why
    #: an empty hostname is not by itself evidence that the address has no name.
    hostname_checked_at: datetime | None = None
    #: How the stored name was obtained - a reverse lookup, a NetBIOS reply,
    #: or the device's own mDNS announcement. Empty when the name predates
    #: this being recorded, or when there is no name.
    hostname_source: str = ""
    vendor: str = ""
    os_name: str = ""
    os_version: str = ""
    os_cpe: str = ""
    os_accuracy: int | None = None
    status: HostStatus = HostStatus.UNKNOWN
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    #: Which subsystem established that this host exists. LEGACY is the
    #: honest default: a row that names no source was not discovered by
    #: anything this installation can vouch for.
    discovery_source: EvidenceSource = EvidenceSource.LEGACY
    #: The capture interface, or the tool, it was observed on.
    discovery_interface: str = ""
    #: What established it - "seen transmitting", "answered a scan probe".
    discovery_detail: str = ""
    #: Where the host stands in the automatic assessment cycle. Persisted, so
    #: a restart resumes rather than rescanning the whole network.
    assessment_state: AssessmentState = AssessmentState.DISCOVERED
    last_assessed_at: datetime | None = None
    assessment_attempts: int = 0
    last_scan_id: int | None = None
    is_trusted: bool = False
    trust_note: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    # Derived counters, populated by inventory queries rather than stored.
    open_port_count: int = 0
    alert_count: int = 0
    finding_count: int = 0
    packet_count: int = 0
    protocols_observed: tuple[str, ...] = ()

    #: Why the host is in its assessment state - the refusal reason for a
    #: SKIPPED host, the error for a failed one. Stored, so it is shown rather
    #: than re-guessed.
    assessment_detail: str = ""
    #: When automation last started an assessment attempt; the retry back-off
    #: is measured from here.
    last_attempt_at: datetime | None = None

    # Transient facts about the most recent scan, populated by
    # :meth:`HostRepository.assessment_overview` so the security result can be
    # derived. Empty when the host has never been scanned.
    last_scan_status: str = ""
    last_scan_hosts_up: int | None = None
    last_scan_finished_at: datetime | None = None
    #: Rating of the highest open finding (CVSS band where scored).
    highest_finding: RiskLevel | None = None
    #: Highest real CVSS base score among open findings; ``None`` if none has one.
    highest_cvss: float | None = None
    #: How many open findings carry a real CVSS score.
    scored_finding_count: int = 0
    #: Open findings that are evidence of a *vulnerability* rather than of
    #: exposure - a CVE from an NSE script, a CVSS score, or a knowledge-base
    #: match. This is the only count that can make a host Vulnerable; an open
    #: port contributes to ``finding_count`` and not to this.
    confirmed_finding_count: int = 0
    #: Whether the host lies in the automatic assessment scope. ``None`` until
    #: a caller that knows the scope sets it.
    in_scope: bool | None = None

    @property
    def display_name(self) -> str:
        """Hostname when known, otherwise the IP address."""
        return self.hostname.strip() or self.ip_address

    @property
    def host_status_text(self) -> str:
        """The host's reachability, in the words the automation screen shows.

        Distinct from the assessment status and the security result: this is
        only whether the host is currently reachable/observed. ``DOWN`` is
        shown as OFFLINE because that is what it means for an inventory host -
        not seen recently, or a scan found it unreachable.
        """
        return {
            HostStatus.UP: "UP",
            HostStatus.DOWN: "OFFLINE",
            HostStatus.UNKNOWN: "UNKNOWN",
        }.get(self.status, "UNKNOWN")

    @property
    def assessment_status_text(self) -> str:
        """The assessment lifecycle state, in display words.

        Kept separate from the security result on purpose (§15): a host can be
        UP, its assessment FAILED, and its security result UNKNOWN all at once.
        """
        if self.in_scope is False and self.assessment_state in (
            AssessmentState.DISCOVERED, AssessmentState.SKIPPED,
        ):
            return "OUT OF SCOPE"
        # COMPLETED and COOLDOWN both claim the host was examined, so both are
        # checked against the evidence: a scan the host never answered
        # examined nothing, and inheriting "COMPLETED" from it is how an
        # unexamined host came to be reported as assessed beside "0 open
        # ports, 0 findings".
        #
        # Applied here as well as in the queue on purpose. The queue settles
        # new scans correctly, but this also covers rows written before that
        # rule existed and any other path that stores COMPLETED.
        if (
            self.assessment_state
            in (AssessmentState.COMPLETED, AssessmentState.COOLDOWN)
            and self.last_scan_status
            and not self.host_answered
        ):
            return "NO RESPONSE"
        return {
            AssessmentState.DISCOVERED: "DISCOVERED",
            AssessmentState.QUEUED: "QUEUED",
            AssessmentState.SCANNING: "SCANNING",
            AssessmentState.COMPLETED: "COMPLETED",
            AssessmentState.COOLDOWN: "COMPLETED",
            AssessmentState.NO_RESPONSE: "NO RESPONSE",
            AssessmentState.FAILED: "SCAN FAILED",
            AssessmentState.TIMEOUT: "TIMEOUT",
            AssessmentState.SKIPPED: "SKIPPED",
        }.get(self.assessment_state, "DISCOVERED")

    @property
    def assessment_reason_text(self) -> str:
        """Why the host is in its assessment state, or that it was not recorded.

        A blank reason beside SKIPPED is the worst of the three possibilities:
        the operator cannot tell an out-of-scope address from a deliberately
        excluded device from a bug. Saying the reason was not recorded is
        useless information, but it is *true* information, and it stops an
        empty cell reading as "no reason needed".
        """
        recorded = (self.assessment_detail or "").strip()
        if recorded:
            return recorded
        if self.assessment_state is AssessmentState.SKIPPED:
            return "no reason was recorded for this row"
        return ""

    @property
    def host_answered(self) -> bool:
        """Whether the last completed assessment got an answer from the host.

        The distinction the assessment column rests on: Nmap finishing and the
        host replying are separate facts, and a scan that completed against a
        silent host examined nothing. ``True`` only when the last scan both
        completed and reported the host up.
        """
        if (self.last_scan_status or "").upper() != "COMPLETED":
            return False
        return (self.last_scan_hosts_up or 0) > 0

    @property
    def security_result(self) -> SecurityResult:
        """What the assessment concluded, derived from real evidence (§9).

        A host outside the automatic scope that automation never assessed is
        reported as such; one that was assessed (manually, say) keeps the
        result its evidence supports.
        """
        result = derive_security_result(
            self.assessment_state,
            finding_count=self.finding_count,
            last_scan_status=self.last_scan_status,
            last_scan_hosts_up=self.last_scan_hosts_up,
            last_assessed_at=self.last_assessed_at,
            highest_finding=self.highest_finding,
            confirmed_finding_count=self.confirmed_finding_count,
        )
        if self.in_scope is False and result in (NOT_ASSESSED, NOT_AUTHORISED):
            return OUT_OF_SCOPE
        return result

    @property
    def classification_basis(self) -> str:
        """What the §3.9.9 classification rests on, for tooltips and reports."""
        if not self.finding_count:
            return ""
        if self.scored_finding_count and self.highest_cvss is not None:
            unscored = self.finding_count - self.scored_finding_count
            text = f"highest CVSS v3.1 base score {self.highest_cvss:.1f}"
            if unscored > 0:
                text += (
                    f"; {unscored} finding(s) have no CVSS score and use their "
                    "recorded rating"
                )
            return text
        return (
            "no finding carries a CVSS score, so each finding's recorded "
            "rating is used on the CVSS v3.1 qualitative scale"
        )

    @property
    def security_conclusion(self) -> SecurityResult:
        """The three-valued answer the Security result column shows.

        Vulnerable, Safe, or nothing. Every other state the assessment can be
        in - queued, scanning, no response, timed out, failed - is a statement
        about the *assessment*, not about the host's security, and belongs in
        the assessment column beside this one. Collapsing them here keeps the
        security column to the question it actually answers.

        :attr:`security_result` keeps the detailed state, because the summary
        tiles and the reports need to count those cases apart.
        """
        result = self.security_result
        if result.code == VULNERABLE.code:
            return VULNERABLE
        if result.code == SAFE.code:
            return SAFE
        return NOT_DETERMINED

    @property
    def security_result_text(self) -> str:
        """The security result as a label, with the finding count when rated."""
        result = self.security_result
        if result in FINDING_RESULTS and self.finding_count:
            return f"{result.label} ({self.finding_count})"
        return result.label

    @property
    def hostname_text(self) -> str:
        """The hostname, or why there isn't one.

        A blank cell tells an operator nothing, and a dash tells them nothing
        twice: it looks identical whether the address has no DNS record or
        whether nobody has ever asked. These two answers are different, and
        only one of them is worth acting on.

        Neither answer says anything about the host. A device with no DNS
        record is an ordinary device - most things on a home or laboratory
        network have no reverse record at all - so these strings describe the
        *lookup*, never the host.

        Both cases read "Unknown" in the table. The earlier wording leaked the
        lookup's own state into a column about identity: "Not checked" sitting
        beside a completed assessment read as "this host was skipped", which
        was untrue and was the single most common cell on the screen. Whether
        a lookup has been attempted is still recorded - see
        :attr:`hostname_lookup_text`, which the host detail shows - but it is
        not what an operator scanning a column of names needs to be told.
        """
        return self.hostname.strip() or "Unknown"

    @property
    def hostname_lookup_text(self) -> str:
        """What happened when the name was last looked up, for the detail view.

        Kept apart from :attr:`hostname_text` so the table can say "Unknown"
        while the detail can still distinguish a lookup that came back empty
        from one that was never made - which is the difference between "this
        address has no DNS record" and "nobody has asked yet".
        """
        if self.hostname.strip():
            return self.hostname_source or "Resolved"
        if self.hostname_checked_at is not None:
            return "Looked up; the address has no reverse DNS record"
        return "Not looked up yet"

    @property
    def os_text(self) -> str:
        """OS description with accuracy, or why it is not known.

        Capture cannot fingerprint an operating system - only an assessment
        can - so an unscanned host says so rather than showing a dash.
        """
        if not self.os_name:
            return "not scanned"
        text = self.os_name
        if self.os_version and self.os_version not in text:
            text = f"{text} {self.os_version}"
        if self.os_accuracy:
            text = f"{text} ({self.os_accuracy}%)"
        return text


@dataclass
class AssessmentSummary:
    """Assessment counts, each derived per host by :meth:`Host.security_result`.

    One definition for the Vulnerability Assessment tiles and the Dashboard,
    computed over the whole inventory (never a display-capped subset), so the
    two screens and the table cannot disagree.
    """

    #: Whether an automatic assessment scope was resolved. When it was not,
    #: in-scope counts cannot be computed and every host is counted.
    scope_available: bool = False
    scope_text: str = ""
    inventory_total: int = 0
    outside_scope: int = 0
    #: Hosts inside the monitored authorised network (all hosts when the scope
    #: is unavailable).
    discovered: int = 0
    active: int = 0
    host_offline: int = 0
    not_assessed: int = 0
    queued: int = 0
    scanning: int = 0
    vulnerable: int = 0
    at_risk: int = 0
    low_findings: int = 0
    no_findings: int = 0
    #: Completed, the host answered, nothing confirmed. The tile counterpart
    #: of the Safe label; ``no_findings`` is retained for the older reports
    #: that count exposures rather than conclusions.
    safe: int = 0
    #: Assessed but reaching no conclusion - the "-" rows.
    not_determined: int = 0
    offline: int = 0
    timeout: int = 0
    failed: int = 0
    skipped: int = 0
    unknown: int = 0
    #: Hosts with at least one open finding carrying a real CVSS score.
    cvss_scored_hosts: int = 0

    @property
    def awaiting(self) -> int:
        """Hosts waiting for an assessment: not yet assessed, or queued."""
        return self.not_assessed + self.queued


def summarize_assessment(hosts: "list[Host]", scope: object | None) -> AssessmentSummary:
    """Count assessment results over every host, inside the given scope.

    Args:
        hosts: the whole inventory, e.g. from
            :meth:`HostRepository.assessment_summary_hosts`.
        scope: an :class:`~aethra_sec.analytics.assessment_scope.AssessmentScope`
            or ``None``. Each host's ``in_scope`` is set from it.
    """
    available = bool(getattr(scope, "available", False))
    summary = AssessmentSummary(
        scope_available=available,
        scope_text=scope.describe() if scope is not None else "",
        inventory_total=len(hosts),
    )
    for host in hosts:
        if available:
            host.in_scope = bool(scope.contains(host.ip_address))  # type: ignore[union-attr]
            if not host.in_scope:
                summary.outside_scope += 1
                continue
        summary.discovered += 1
        if host.status is HostStatus.DOWN:
            summary.host_offline += 1
        else:
            summary.active += 1
        if host.scored_finding_count:
            summary.cvss_scored_hosts += 1
        code = host.security_result.code
        if code == VULNERABLE.code:
            summary.vulnerable += 1
        elif code == AT_RISK.code:
            summary.at_risk += 1
        elif code == LOW_FINDINGS.code:
            summary.low_findings += 1
        elif code == SAFE.code:
            summary.safe += 1
            # Retained so reports and the dashboard that ask "how many came
            # back clean" keep answering, now against the same rows.
            summary.no_findings += 1
        elif code == NOT_DETERMINED.code:
            summary.not_determined += 1
        elif code == NO_FINDINGS.code:
            summary.no_findings += 1
        elif code == SCANNING.code:
            summary.scanning += 1
        elif code == QUEUED.code:
            summary.queued += 1
        elif code == OFFLINE.code:
            summary.offline += 1
        elif code == TIMEOUT.code:
            summary.timeout += 1
        elif code in (SCAN_FAILED.code, SCAN_CANCELLED.code):
            summary.failed += 1
        elif code == NOT_ASSESSED.code:
            summary.not_assessed += 1
        elif code == NOT_AUTHORISED.code:
            summary.skipped += 1
        else:
            summary.unknown += 1
    return summary


@dataclass
class HostObservation:
    """A rolled-up record of traffic seen for one host in one interval.

    This is what keeps the host inventory current without inserting a row per
    packet: the capture worker aggregates observations in memory and flushes
    them on the configured interval.
    """

    id: int | None
    host_id: int
    interface: str = ""
    protocol: str = ""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: EvidenceSource = EvidenceSource.PYSHARK


@dataclass
class TrustedHost:
    """An asset the administrator has marked as authorised (§93).

    Trust is *context*, not an exemption: traffic from a trusted host is still
    analysed and still raises anomalies, but the incident view labels the
    source as a known asset so the analyst can weigh it.
    """

    id: int | None
    ip_address: str
    label: str = ""
    reason: str = ""
    added_by: int | None = None
    created_at: datetime | None = None
    is_active: bool = True


@dataclass
class HostDetail:
    """Everything the host detail screen shows, assembled from real records."""

    host: Host
    observations: tuple[HostObservation, ...] = ()
    open_ports: tuple[object, ...] = ()
    scans: tuple[object, ...] = ()
    alerts: tuple[object, ...] = ()
    incidents: tuple[object, ...] = ()
    findings: tuple[object, ...] = ()
    timeline: tuple[dict[str, object], ...] = field(default_factory=tuple)
