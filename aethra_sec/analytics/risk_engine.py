"""Transparent, explainable risk scoring (§20, §28).

There is no random or opaque scoring anywhere in AETHRA-SEC. Every severity is
the sum of named, documented factors, and the factors travel with the result so
the investigation view and the reports can show exactly why a level was
assigned.

Scoring is deterministic: the same evidence always produces the same severity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aethra_sec.models.enums import EvidenceSource, RiskLevel, Severity, ThreatCategory
from aethra_sec.models.incident import RiskAssessment

# --------------------------------------------------------------------------
# Score thresholds. Documented here so the mapping is auditable.
# --------------------------------------------------------------------------
SCORE_CRITICAL = 80
SCORE_HIGH = 55
SCORE_MEDIUM = 30
SCORE_LOW = 12

#: Base points per threat category, reflecting inherent seriousness.
CATEGORY_BASE_SCORE: dict[ThreatCategory, int] = {
    ThreatCategory.MALWARE_INDICATOR: 55,
    ThreatCategory.SUSPICIOUS_PAYLOAD: 45,
    ThreatCategory.BRUTE_FORCE: 40,
    ThreatCategory.DENIAL_OF_SERVICE: 40,
    ThreatCategory.TCP_SYN_FLOOD: 35,
    ThreatCategory.UDP_FLOOD: 30,
    ThreatCategory.HTTP_FLOOD: 30,
    ThreatCategory.ICMP_FLOOD: 25,
    ThreatCategory.PORT_SCAN: 25,
    ThreatCategory.HOST_SWEEP: 22,
    ThreatCategory.RECONNAISSANCE: 20,
    ThreatCategory.SERVICE_EXPOSURE: 15,
    ThreatCategory.POLICY_VIOLATION: 12,
    ThreatCategory.UNCLASSIFIED: 10,
}

#: Points contributed by a Snort priority value (1 is the most severe).
SNORT_PRIORITY_SCORE: dict[int, int] = {1: 30, 2: 20, 3: 10, 4: 5}

#: Services whose exposure carries more weight because compromise grants
#: administrative access, database contents, or lateral movement.
SENSITIVE_SERVICES: dict[str, int] = {
    "ssh": 12, "telnet": 18, "ftp": 14, "rdp": 16, "ms-wbt-server": 16,
    "microsoft-ds": 14, "netbios-ssn": 12, "smb": 14, "vnc": 16,
    "mysql": 14, "ms-sql-s": 14, "postgresql": 14, "oracle": 14,
    "mongodb": 14, "redis": 16, "elasticsearch": 12, "snmp": 12,
    "rpcbind": 10, "ldap": 8, "smtp": 6, "http": 4, "https": 2,
}

#: Services that transmit credentials or data without encryption.
CLEARTEXT_SERVICES: frozenset[str] = frozenset(
    {"telnet", "ftp", "http", "pop3", "imap", "smtp", "snmp", "tftp", "rlogin", "rsh"}
)


@dataclass(frozen=True)
class ThreatEvidence:
    """The measurable inputs the risk engine scores.

    Attributes:
        category: threat category.
        snort_priority: lowest (most severe) Snort priority among the alerts.
        snort_alert_count: number of real Snort alerts.
        anomaly_count: number of deterministic traffic anomalies.
        finding_count: number of Nmap-derived findings.
        distinct_sources: how many subsystems contributed evidence.
        event_count: total evidence events.
        affected_service: service name, when one is known.
        target_is_trusted: whether the destination is a registered asset.
        source_is_trusted: whether the source is a registered asset.
        exposure_confirmed: whether Nmap confirmed the targeted service is open.
        repeat_observations: how many times the pattern recurred.
    """

    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    snort_priority: int | None = None
    snort_alert_count: int = 0
    anomaly_count: int = 0
    finding_count: int = 0
    distinct_sources: int = 1
    event_count: int = 1
    affected_service: str = ""
    target_is_trusted: bool = False
    source_is_trusted: bool = False
    exposure_confirmed: bool = False
    repeat_observations: int = 0


class RiskEngine:
    """Turns evidence into an explainable severity and confidence."""

    def score_threat(self, evidence: ThreatEvidence) -> RiskAssessment:
        """Score a correlated threat.

        Returns:
            A :class:`RiskAssessment` carrying the total score, the resulting
            severity, a confidence percentage, and every contributing factor.
        """
        factors: list[tuple[str, int, str]] = []

        base = CATEGORY_BASE_SCORE.get(evidence.category, 10)
        factors.append(
            (
                "Threat category",
                base,
                f"{evidence.category.label} carries a base score of {base}.",
            )
        )

        if evidence.snort_priority is not None:
            points = SNORT_PRIORITY_SCORE.get(int(evidence.snort_priority), 3)
            factors.append(
                (
                    "IDS priority",
                    points,
                    f"Snort assigned priority {evidence.snort_priority} "
                    "(1 is the most severe).",
                )
            )

        if evidence.distinct_sources > 1:
            points = 10 * (evidence.distinct_sources - 1)
            factors.append(
                (
                    "Correlation strength",
                    points,
                    f"{evidence.distinct_sources} independent subsystems "
                    "reported supporting evidence.",
                )
            )

        if evidence.exposure_confirmed:
            factors.append(
                (
                    "Confirmed exposure",
                    12,
                    "A vulnerability assessment confirmed the targeted service "
                    "is actually reachable.",
                )
            )

        service = (evidence.affected_service or "").lower()
        if service in SENSITIVE_SERVICES:
            points = SENSITIVE_SERVICES[service]
            factors.append(
                (
                    "Affected service",
                    points,
                    f"The '{service}' service is security-sensitive.",
                )
            )

        frequency_points = self._frequency_points(evidence.event_count)
        if frequency_points:
            factors.append(
                (
                    "Frequency",
                    frequency_points,
                    f"{evidence.event_count} evidence event(s) were recorded "
                    "for this threat.",
                )
            )

        if evidence.repeat_observations > 2:
            points = min(10, evidence.repeat_observations)
            factors.append(
                (
                    "Persistence",
                    points,
                    f"The pattern recurred {evidence.repeat_observations} times "
                    "rather than appearing once.",
                )
            )

        if evidence.source_is_trusted:
            # Trust is context, not an exemption: it reduces the score but the
            # threat is still recorded and shown (§93).
            factors.append(
                (
                    "Trusted source",
                    -10,
                    "The source is a registered trusted asset, which makes "
                    "authorised activity more likely. The event is still "
                    "recorded for review.",
                )
            )

        if evidence.target_is_trusted:
            factors.append(
                (
                    "Trusted target",
                    5,
                    "The destination is a registered asset, so disruption "
                    "there has a wider impact.",
                )
            )

        score = max(0, sum(points for _, points, _ in factors))
        severity = self.severity_for_score(score)
        confidence = self._confidence(evidence)
        return RiskAssessment(
            score=score,
            severity=severity,
            confidence=confidence,
            factors=tuple(factors),
        )

    @staticmethod
    def _frequency_points(event_count: int) -> int:
        """Points contributed by how much evidence accumulated."""
        if event_count >= 50:
            return 15
        if event_count >= 20:
            return 10
        if event_count >= 5:
            return 5
        return 0

    @staticmethod
    def _confidence(evidence: ThreatEvidence) -> int:
        """Confidence percentage, derived from evidence breadth and volume.

        A single anomaly from one subsystem is a weak signal; the same pattern
        confirmed by Snort *and* an exposure confirmed by Nmap is a strong one.
        """
        confidence = 35
        if evidence.snort_alert_count:
            confidence += 20
        if evidence.anomaly_count:
            confidence += 10
        if evidence.finding_count or evidence.exposure_confirmed:
            confidence += 15
        confidence += min(20, 5 * max(0, evidence.distinct_sources - 1))
        if evidence.event_count >= 10:
            confidence += 10
        elif evidence.event_count >= 3:
            confidence += 5
        if evidence.source_is_trusted:
            confidence -= 10
        return max(5, min(99, confidence))

    @staticmethod
    def severity_for_score(score: int) -> Severity:
        """Map a score to a severity band."""
        if score >= SCORE_CRITICAL:
            return Severity.CRITICAL
        if score >= SCORE_HIGH:
            return Severity.HIGH
        if score >= SCORE_MEDIUM:
            return Severity.MEDIUM
        if score >= SCORE_LOW:
            return Severity.LOW
        return Severity.INFO

    # ------------------------------------------------------------------
    # Assessment findings (§19, §20)
    # ------------------------------------------------------------------
    def score_exposure(
        self,
        *,
        service: str,
        port: int,
        product: str = "",
        version: str = "",
        has_known_vulnerability: bool = False,
        host_is_trusted: bool = False,
    ) -> tuple[RiskLevel, str]:
        """Classify the risk of an observed open service.

        An open port is an *observation*; this method decides how much of a
        concern that observation is, and returns the reasoning alongside the
        level so the finding can state why (§19, §20).

        Returns:
            ``(risk_level, rationale)``.
        """
        reasons: list[str] = []
        score = 8
        reasons.append(f"Base score 8 for an exposed listening service on port {port}.")

        service_key = (service or "").lower()
        if service_key in SENSITIVE_SERVICES:
            points = SENSITIVE_SERVICES[service_key]
            score += points
            reasons.append(
                f"+{points} because '{service_key}' is a security-sensitive service."
            )

        if service_key in CLEARTEXT_SERVICES:
            score += 10
            reasons.append(
                "+10 because this protocol transmits data (and often "
                "credentials) without encryption by default."
            )

        if has_known_vulnerability:
            score += 30
            reasons.append(
                "+30 because a configured vulnerability source matched this "
                "product and version."
            )
        elif product or version:
            score += 3
            reasons.append(
                "+3 because the service disclosed product/version information, "
                "which assists an attacker in selecting an exploit."
            )

        if host_is_trusted:
            score += 4
            reasons.append(
                "+4 because the host is a registered asset, so exposure there "
                "carries wider impact."
            )

        level = self._risk_level_for(score)
        rationale = (
            f"Risk {level} (score {score}). " + " ".join(reasons)
        )
        return level, rationale

    @staticmethod
    def _risk_level_for(score: int) -> RiskLevel:
        """Map an exposure score to a risk level."""
        if score >= 55:
            return RiskLevel.CRITICAL
        if score >= 35:
            return RiskLevel.HIGH
        if score >= 20:
            return RiskLevel.MEDIUM
        if score >= 10:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL

    def host_risk_level(self, finding_levels: list[RiskLevel]) -> RiskLevel:
        """A host's risk level is the highest level among its open findings."""
        if not finding_levels:
            return RiskLevel.INFORMATIONAL
        return max(finding_levels, key=lambda level: level.severity.rank)

    @staticmethod
    def severity_for_snort_priority(priority: int | None) -> Severity:
        """Map Snort's own priority to an AETHRA-SEC severity.

        Snort priorities are 1 (highest) through 4+ (lowest). When a sensor
        supplies no priority the alert is recorded as MEDIUM and the missing
        value is visible in the alert detail, rather than being guessed.
        """
        if priority is None:
            return Severity.MEDIUM
        if priority <= 1:
            return Severity.CRITICAL
        if priority == 2:
            return Severity.HIGH
        if priority == 3:
            return Severity.MEDIUM
        return Severity.LOW


def explain_severity(assessment: RiskAssessment) -> str:
    """Render a risk assessment as readable text for the UI and reports."""
    lines = [
        f"Severity: {assessment.severity} (score {assessment.score}, "
        f"confidence {assessment.confidence}%)",
        "Contributing factors:",
    ]
    lines.extend(f"  {line}" for line in assessment.explanation_lines())
    return "\n".join(lines)


#: Matches one stored rationale line, e.g. ``+18  Threat category - Port scan...``
_FACTOR_LINE = re.compile(r"^\+(?P<points>\d+)\s+(?P<name>[^-]+?)\s+-\s+(?P<reason>.+)$")


def parse_explanation_lines(rationale: str) -> tuple[tuple[str, int, str], ...]:
    """Recover ``(factor, points, reason)`` triples from a stored rationale.

    The investigation view draws the severity breakdown as bars, and the stored
    ``risk_rationale`` is the record of how the score was reached. Lines that do
    not match the written format are returned with zero points and their text
    intact, so nothing stored is ever silently dropped from the display.
    """
    factors: list[tuple[str, int, str]] = []
    for raw in (rationale or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _FACTOR_LINE.match(line)
        if match:
            factors.append(
                (
                    match.group("name").strip(),
                    int(match.group("points")),
                    match.group("reason").strip(),
                )
            )
        else:
            factors.append((line, 0, ""))
    return tuple(factors)
