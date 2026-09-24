"""Mitigation knowledge-base models (§29-§31).

Recommendations are advisory. AETHRA-SEC never executes a mitigation: no
firewall change, no service shutdown, no account lockout, no traffic blocking
(§90). The operator reads the guidance and decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory


@dataclass
class MitigationRecommendation:
    """One entry in the administrator-maintained mitigation knowledge base."""

    id: int | None = None
    code: str = ""
    threat_name: str = ""
    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    severity: Severity = Severity.MEDIUM
    applies_to_service: str = ""
    detection_source: EvidenceSource | None = None
    explanation: str = ""
    why_it_matters: str = ""
    immediate_action: str = ""
    long_term_action: str = ""
    verification_steps: str = ""
    references: str = ""
    is_active: bool = True
    is_builtin: bool = False
    created_by: int | None = None
    updated_by: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def status_text(self) -> str:
        """``ACTIVE`` / ``INACTIVE``."""
        return "ACTIVE" if self.is_active else "INACTIVE"

    def matches(
        self,
        category: ThreatCategory,
        severity: Severity | None = None,
        service: str = "",
        source: EvidenceSource | None = None,
    ) -> int:
        """Score how well this entry fits a detected threat.

        Higher is better; ``0`` means it does not apply at all. The scoring is
        deterministic so the same threat always resolves to the same guidance.
        """
        if not self.is_active or self.category is not category:
            return 0
        score = 10
        if service and self.applies_to_service:
            if service.lower() == self.applies_to_service.lower():
                score += 6
            else:
                return 0
        elif self.applies_to_service:
            return 0
        if severity is not None and self.severity is severity:
            score += 3
        if source is not None and self.detection_source is source:
            score += 2
        return score


@dataclass
class MitigationAdvice:
    """A recommendation bound to one concrete detection (§30).

    This is what the Mitigation screen and the incident investigation view
    render: the static knowledge-base text plus the real evidence that
    triggered it.
    """

    recommendation: MitigationRecommendation
    threat_title: str = ""
    severity: Severity = Severity.MEDIUM
    evidence_lines: tuple[str, ...] = ()
    affected_asset: str = ""
    affected_service: str = ""
    related_alert_id: int | None = None
    related_finding_id: int | None = None
    related_incident_id: int | None = None
    status: str = "OPEN"
    generated_at: datetime | None = None

    @property
    def has_evidence(self) -> bool:
        """False when no supporting evidence was recorded."""
        return bool(self.evidence_lines)

    def as_text(self) -> str:
        """Full advisory rendered as plain text for exports and reports."""
        rec = self.recommendation
        evidence = "\n".join(f"  - {line}" for line in self.evidence_lines) or "  - None recorded"
        return (
            f"THREAT: {self.threat_title or rec.threat_name}\n"
            f"SEVERITY: {self.severity}\n\n"
            f"WHAT WAS OBSERVED:\n{rec.explanation}\n\n"
            f"EVIDENCE:\n{evidence}\n\n"
            f"WHY IT MATTERS:\n{rec.why_it_matters}\n\n"
            f"IMMEDIATE RECOMMENDED ACTION:\n{rec.immediate_action}\n\n"
            f"LONG-TERM RECOMMENDED ACTION:\n{rec.long_term_action}\n\n"
            f"VERIFICATION STEPS:\n{rec.verification_steps}\n\n"
            f"AFFECTED ASSET: {self.affected_asset or '-'}\n"
            f"AFFECTED SERVICE: {self.affected_service or '-'}\n"
            f"STATUS: {self.status}\n\n"
            "NOTE: AETHRA-SEC does not apply mitigations automatically. Review "
            "the guidance and take action through your normal change process."
        )


@dataclass
class ThreatMitigationMapping:
    """Explicit mapping row linking a threat category to a recommendation."""

    id: int | None = None
    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    recommendation_id: int | None = None
    priority: int = 100
    condition_service: str = ""
    condition_min_severity: Severity | None = None
    is_active: bool = True


#: How a detection reached the entry it did, strongest first. Shown to the
#: operator so the mapping can be read rather than taken on trust.
MATCH_SERVICE = "service"
MATCH_SEVERITY = "severity"
MATCH_CATEGORY = "category"
MATCH_MAPPING = "mapping"

_MATCH_TEXT = {
    MATCH_SERVICE: (
        "the entry's service condition matched the service observed on this "
        "detection"
    ),
    MATCH_SEVERITY: "the entry's category and severity both matched",
    MATCH_CATEGORY: "the entry's category matched",
    MATCH_MAPPING: (
        "the threat-to-mitigation mapping names this entry for the category, "
        "and no more specific entry applied"
    ),
}

#: Shown when the knowledge base itself could not be read. Distinct from
#: "nothing is configured", which is a fact about the data rather than a
#: failure to look.
LOOKUP_FAILED_TEXT = (
    "Mitigation recommendation unavailable: the mitigation knowledge base "
    "could not be read. This is a lookup failure, not a statement that no "
    "guidance exists for this detection - the recorded error is in the "
    "application log."
)


@dataclass(frozen=True)
class MitigationMatch:
    """One real detection resolved against the mitigation knowledge base.

    Carries *how* the entry was reached as well as the entry itself. An
    analyst acting on guidance needs to see which category the detection was
    filed under and which mapping produced the advice, because a plausible
    recommendation attached to the wrong category is worse than none.

    The three outcomes are kept apart deliberately:

    * a recommendation was found (``resolved``);
    * the knowledge base was read and holds nothing for this category
      (``recommendation is None`` and not ``lookup_failed``);
    * the knowledge base could not be read at all (``lookup_failed``).

    The middle one is a fact about the configuration. The last is a fault, and
    reporting it as "no recommendation is configured" would tell the operator
    something untrue about their own system.
    """

    recommendation: MitigationRecommendation | None = None
    category: ThreatCategory = ThreatCategory.UNCLASSIFIED
    #: Where the category came from - the detection's own stored category, or
    #: the keyword rules read over a Snort signature's text.
    category_source: str = ""
    #: One of the ``MATCH_*`` constants; empty when nothing was found.
    matched_on: str = ""
    #: The service the detection was seen against, when one could be named
    #: from the observed port. Never guessed from the category.
    observed_service: str = ""
    lookup_failed: bool = False
    failure_detail: str = ""

    @property
    def resolved(self) -> bool:
        """True when real guidance was found for this detection."""
        return self.recommendation is not None and not self.lookup_failed

    @property
    def status_text(self) -> str:
        """The knowledge-base entry's own state, or why there is none."""
        if self.lookup_failed:
            return "Lookup failed"
        if self.recommendation is None:
            return "No mapping configured"
        return self.recommendation.status_text

    def mapping_lines(self) -> tuple[str, ...]:
        """The resolution chain, end to end, in the operator's terms."""
        if self.lookup_failed:
            return (
                "Could not be resolved: the knowledge base could not be read.",
            )
        chain = (
            f"{self.category_source or 'detection'} "
            f"-> category {self.category} "
            "-> threat_mitigation_mapping"
        )
        if self.recommendation is None:
            return (
                f"{chain} -> no active entry",
                (
                    "No entry in the mitigation knowledge base is mapped to "
                    f"category {self.category}."
                ),
            )
        lines = [f"{chain} -> {self.recommendation.code}"]
        reason = _MATCH_TEXT.get(self.matched_on, "")
        if reason:
            lines.append(f"Selected because {reason}.")
        if self.observed_service:
            lines.append(f"Service observed on this detection: {self.observed_service}.")
        elif self.recommendation.applies_to_service:
            # The entry is service-specific but the detection named no
            # service, so say so rather than implying the two were compared.
            lines.append(
                "No service could be named from the observed port, so the "
                f"entry's service condition ({self.recommendation.applies_to_service}) "
                "was not verified against this detection."
            )
        return tuple(lines)
