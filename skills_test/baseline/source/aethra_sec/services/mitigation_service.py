"""Mitigation recommendation engine (§29-§31, §90).

Given a detected threat, this service selects the best-matching entry from the
administrator-maintained knowledge base and binds it to the **real evidence**
that triggered it.

It recommends only. There is no code path here - or anywhere in AETHRA-SEC -
that blocks an address, changes a firewall, stops a service or locks an
account. The operator reads the guidance and decides (§90).
"""

from __future__ import annotations

import threading
from typing import Any, Iterable

from aethra_sec.core.errors import ValidationFailedError
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.mitigation import MitigationRepository
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.incident import Incident
from aethra_sec.models.mitigation import (
    MATCH_CATEGORY,
    MATCH_MAPPING,
    MATCH_SERVICE,
    MATCH_SEVERITY,
    MitigationAdvice,
    MitigationMatch,
    MitigationRecommendation,
)
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.net import service_name_for_port
from aethra_sec.utils.timeutil import utcnow

LOGGER = get_logger("services.mitigation")

#: Text used when the knowledge base has no entry for a detected threat. It
#: says so plainly instead of inventing advice.
NO_RECOMMENDATION_TEXT = (
    "No mitigation recommendation is configured for this threat category. An "
    "administrator can add one on the Mitigation screen so future detections "
    "of this type carry guidance."
)


class MitigationService:
    """Selects and manages mitigation guidance."""

    def __init__(
        self,
        repository: MitigationRepository,
        audit: AuditService,
        access: AccessControl,
        incidents: Any = None,
    ) -> None:
        """Wire the service and prime the recommendation cache.

        ``incidents`` is optional so existing callers and tests keep working;
        without it the screen simply reports that no evidence is available,
        which is the honest outcome rather than a fabricated one.
        """
        self._repository = repository
        self._audit = audit
        self._access = access
        self._incidents = incidents
        self._lock = threading.RLock()
        self._cache: dict[str, list[MitigationRecommendation]] = {}

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------
    def recommendation_for(
        self,
        category: ThreatCategory,
        *,
        severity: Severity | None = None,
        service: str = "",
        source: EvidenceSource | None = None,
    ) -> MitigationRecommendation | None:
        """Find the best-fitting active recommendation.

        Selection is deterministic: candidates come from the mapping table in
        priority order, and the first one whose conditions match wins, with a
        service-specific entry outranking a generic one.

        Returns:
            The recommendation, or ``None`` when the knowledge base has no
            entry - in which case the caller displays
            :data:`NO_RECOMMENDATION_TEXT`.
        """
        return self._select(self._candidates(category), category, severity, service, source)[0]

    @staticmethod
    def _select(
        candidates: list[MitigationRecommendation],
        category: ThreatCategory,
        severity: Severity | None,
        service: str,
        source: EvidenceSource | None,
    ) -> tuple[MitigationRecommendation | None, str]:
        """Pick the best candidate, and say which rule picked it.

        Returns the entry and one of the ``MATCH_*`` constants, so a caller
        that shows the guidance to an analyst can also show how it was
        reached.
        """
        if not candidates:
            return None, ""

        best: MitigationRecommendation | None = None
        best_score = 0
        for candidate in candidates:
            score = candidate.matches(category, severity, service, source)
            if score > best_score:
                best, best_score = candidate, score

        if best is not None:
            # The scores come from MitigationRecommendation.matches: a service
            # condition is worth 6 and a severity match 3, on a base of 10.
            if service and best.applies_to_service:
                return best, MATCH_SERVICE
            if severity is not None and best.severity is severity:
                return best, MATCH_SEVERITY
            return best, MATCH_CATEGORY

        # Nothing scored. That happens when every entry the administrator
        # mapped to this category carries a service condition and the observed
        # service matched none of them - which is the case for HTTP_FLOOD,
        # whose only mapped entry applies to "http" while most real detections
        # of it are observed on an ephemeral port.
        #
        # The mapping table is the administrator's explicit statement of which
        # entry covers which category, so its first choice is used rather than
        # reporting that a category they did configure has no guidance. The
        # caller is told this matched on the mapping alone, so nothing implies
        # the service was confirmed.
        for candidate in candidates:
            if candidate.is_active:
                return candidate, MATCH_MAPPING
        return None, ""

    def _load_candidates(
        self, category: ThreatCategory
    ) -> list[MitigationRecommendation]:
        """Cached candidate list for a category. Raises on a database failure."""
        key = str(category)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        candidates = self._repository.candidates_for_category(category)
        with self._lock:
            self._cache[key] = candidates
        return candidates

    def _candidates(self, category: ThreatCategory) -> list[MitigationRecommendation]:
        """Candidates, treating a database failure as "none found".

        The forgiving form, for the correlation engine and the report builder:
        neither may stop because the knowledge base was briefly unreadable.
        Callers that show guidance to an analyst use :meth:`match_for_alert`
        instead, which keeps the two apart.
        """
        try:
            return self._load_candidates(category)
        except Exception:  # noqa: BLE001 - correlation must survive a DB blip
            LOGGER.exception("Could not load mitigation candidates for %s", category)
            return []

    # ------------------------------------------------------------------
    # Resolution for one real detection
    # ------------------------------------------------------------------
    def match_for_alert(self, alert: Any) -> MitigationMatch:
        """Resolve one stored Snort alert against the knowledge base.

        The category comes from the sensor's own signature text through the
        shared keyword rules - the same function the correlation engine uses,
        so the guidance shown beside an alert and the category recorded for it
        can never disagree.
        """
        # Imported here: the correlation engine imports this service, so a
        # module-level import would close the cycle.
        from aethra_sec.services.correlation_service import categorise_alert

        return self._match(
            categorise_alert(alert),
            category_source="Snort signature text",
            severity=getattr(alert, "severity", None),
            service=self.observed_service(
                getattr(alert, "dst_port", None), getattr(alert, "protocol", "")
            ),
        )

    def match_for_anomaly(self, anomaly: Any) -> MitigationMatch:
        """Resolve one of AETHRA-SEC's own detections against the knowledge base.

        No keyword guessing is involved here: the rule that fired recorded the
        category itself, so the mapping starts from a stored fact.
        """
        category = getattr(anomaly, "category", None)
        if not isinstance(category, ThreatCategory):
            category = ThreatCategory.parse(category, ThreatCategory.UNCLASSIFIED)
        rule = str(getattr(anomaly, "rule_id", "") or "detection rule")
        return self._match(
            category,
            category_source=f"category recorded by {rule}",
            severity=getattr(anomaly, "severity", None),
            service=self.observed_service(
                getattr(anomaly, "dst_port", None), getattr(anomaly, "protocol", "")
            ),
        )

    def match_for_finding(self, finding: Any) -> MitigationMatch:
        """Resolve one stored assessment finding against the knowledge base.

        The category is SERVICE_EXPOSURE, which is what an Nmap finding
        actually evidences: a port was open and a service answered on it. The
        service name comes from the finding's own ``service`` field - the
        scanner's reading, not a guess from the port number - so a
        service-specific entry can be reached.

        This says nothing about whether the finding is a *vulnerability*. That
        is decided separately by
        :func:`~aethra_sec.models.host.is_confirmed_vulnerability`, and the
        caller shows exposures and vulnerabilities apart.
        """
        risk = getattr(finding, "risk_level", None)
        severity = getattr(risk, "severity", None) if risk is not None else None
        return self._match(
            ThreatCategory.SERVICE_EXPOSURE,
            category_source="Nmap service detection",
            severity=severity,
            service=str(getattr(finding, "service", "") or ""),
        )

    @staticmethod
    def observed_service(port: Any, protocol: str = "") -> str:
        """Name the service from the port actually observed, or nothing.

        Only the well-known port table is consulted. A service is never
        inferred from the threat category: calling an HTTP_FLOOD detection
        "http" because of its category would make the mapping look as though
        it had been confirmed by the traffic when it had not.
        """
        try:
            number = int(port)
        except (TypeError, ValueError):
            return ""
        if number <= 0:
            return ""
        return service_name_for_port(number, protocol or "tcp")

    def _match(
        self,
        category: ThreatCategory,
        *,
        category_source: str,
        severity: Severity | None,
        service: str,
    ) -> MitigationMatch:
        """Shared resolution, keeping a lookup failure distinct from an empty KB."""
        try:
            candidates = self._load_candidates(category)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            LOGGER.exception(
                "Mitigation lookup failed for category %s", category
            )
            return MitigationMatch(
                category=category,
                category_source=category_source,
                observed_service=service,
                lookup_failed=True,
                failure_detail=str(exc),
            )
        recommendation, matched_on = self._select(
            candidates, category, severity, service, None
        )
        return MitigationMatch(
            recommendation=recommendation,
            category=category,
            category_source=category_source,
            matched_on=matched_on,
            observed_service=service,
        )

    def invalidate_cache(self) -> None:
        """Drop the cache after the knowledge base changes."""
        with self._lock:
            self._cache.clear()

    def advice_for_incident(
        self, incident: Incident, evidence_lines: Iterable[str] = ()
    ) -> MitigationAdvice | None:
        """Bind a recommendation to one incident and its real evidence (§30)."""
        recommendation = self.recommendation_for(
            incident.category,
            severity=incident.severity,
            service=incident.affected_service,
            source=incident.evidence_sources[0] if incident.evidence_sources else None,
        )
        if recommendation is None:
            return None
        return MitigationAdvice(
            recommendation=recommendation,
            threat_title=incident.title,
            severity=incident.severity,
            evidence_lines=tuple(evidence_lines),
            affected_asset=incident.affected_host_ip or incident.dst_ip or incident.src_ip,
            affected_service=incident.affected_service,
            related_incident_id=incident.id,
            status=str(incident.status),
            generated_at=utcnow(),
        )

    # ------------------------------------------------------------------
    # Knowledge-base reads
    # ------------------------------------------------------------------
    def list_all(self, session: Session, **filters: Any) -> list[MitigationRecommendation]:
        """List or search the knowledge base."""
        self._access.require(session, Permission.MITIGATION_VIEW)
        if filters:
            return self._repository.search(**filters)
        return self._repository.list_all()

    def get(self, session: Session, recommendation_id: int) -> MitigationRecommendation | None:
        """Fetch one recommendation."""
        self._access.require(session, Permission.MITIGATION_VIEW)
        return self._repository.get(recommendation_id)

    def categories(self, session: Session) -> list[str]:
        """Categories present in the knowledge base."""
        self._access.require(session, Permission.MITIGATION_VIEW)
        return self._repository.distinct_categories()

    def evidence_for(
        self, session: Session, recommendation_id: int, limit: int = 50
    ) -> list[Any]:
        """Real incidents this recommendation was bound to.

        Returns stored incidents only. When the list is empty the screen says
        so rather than composing an example: a generic knowledge-base entry
        that has never matched anything has no evidence, and inventing some
        would make the mitigation screen the one place in AETHRA-SEC that
        shows a security fact nothing observed.
        """
        self._access.require(session, Permission.MITIGATION_VIEW)
        if not recommendation_id or self._incidents is None:
            return []
        return self._incidents.for_mitigation(recommendation_id, limit=limit)

    def count_active(self) -> int:
        """Number of active recommendations (used by the health screen)."""
        try:
            return self._repository.count_active()
        except Exception:  # noqa: BLE001
            return 0

    # ------------------------------------------------------------------
    # Knowledge-base management (administrator only)
    # ------------------------------------------------------------------
    def create(
        self, session: Session, recommendation: MitigationRecommendation
    ) -> int:
        """Create a recommendation (§31).

        Raises:
            PermissionDeniedError: without ``mitigation.manage``.
            ValidationFailedError: on missing required text or a duplicate code.
        """
        live = self._access.require(
            session, Permission.MITIGATION_MANAGE, target=recommendation.code
        )
        self._validate(recommendation)
        if self._repository.get_by_code(recommendation.code):
            raise ValidationFailedError(
                f"Code '{recommendation.code}' already exists.",
                user_message=(
                    f"A recommendation with code '{recommendation.code}' "
                    "already exists. Choose a different code."
                ),
            )
        new_id = self._repository.create(recommendation, live.user_id)
        self.invalidate_cache()
        self._audit.record(
            AuditAction.MITIGATION_CREATED,
            session=live,
            category=AuditCategory.MITIGATION,
            target_type="mitigation",
            target_id=new_id,
            detail=(
                f"Created recommendation '{recommendation.code}' for "
                f"{recommendation.category}."
            ),
        )
        return new_id

    def update(
        self, session: Session, recommendation: MitigationRecommendation
    ) -> None:
        """Update an existing recommendation."""
        live = self._access.require(
            session, Permission.MITIGATION_MANAGE, target=recommendation.code
        )
        if recommendation.id is None:
            raise ValidationFailedError(
                "Recommendation id is required for an update.",
                user_message="Select a recommendation before saving changes.",
            )
        self._validate(recommendation)
        self._repository.update(recommendation, live.user_id)
        self.invalidate_cache()
        self._audit.record(
            AuditAction.MITIGATION_UPDATED,
            session=live,
            category=AuditCategory.MITIGATION,
            target_type="mitigation",
            target_id=recommendation.id,
            detail=f"Updated recommendation '{recommendation.code}'.",
        )

    def set_active(
        self, session: Session, recommendation_id: int, active: bool
    ) -> None:
        """Activate or deactivate a recommendation.

        Deactivation is preferred over deletion so incidents that already cite
        the entry keep their guidance (§110).
        """
        live = self._access.require(
            session, Permission.MITIGATION_MANAGE, target=str(recommendation_id)
        )
        self._repository.set_active(recommendation_id, active, live.user_id)
        self.invalidate_cache()
        self._audit.record(
            AuditAction.MITIGATION_DEACTIVATED if not active else AuditAction.MITIGATION_UPDATED,
            session=live,
            category=AuditCategory.MITIGATION,
            target_type="mitigation",
            target_id=recommendation_id,
            detail=f"Recommendation {'activated' if active else 'deactivated'}.",
        )

    @staticmethod
    def _validate(recommendation: MitigationRecommendation) -> None:
        """Check that a recommendation carries the text operators depend on.

        Raises:
            ValidationFailedError: when a required field is empty.
        """
        required = (
            ("code", recommendation.code),
            ("threat name", recommendation.threat_name),
            ("explanation", recommendation.explanation),
            ("immediate action", recommendation.immediate_action),
        )
        for label, value in required:
            if not str(value or "").strip():
                raise ValidationFailedError(
                    f"Mitigation {label} is required.",
                    user_message=f"Enter the {label} before saving.",
                )
        if len(recommendation.code) > 64:
            raise ValidationFailedError(
                "Code is too long.",
                user_message="The code must be 64 characters or fewer.",
            )
