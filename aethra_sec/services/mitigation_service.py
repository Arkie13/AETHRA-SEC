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
from aethra_sec.models.mitigation import MitigationAdvice, MitigationRecommendation
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
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
    ) -> None:
        """Wire the service and prime the recommendation cache."""
        self._repository = repository
        self._audit = audit
        self._access = access
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
        candidates = self._candidates(category)
        if not candidates:
            return None

        best: MitigationRecommendation | None = None
        best_score = 0
        for candidate in candidates:
            score = candidate.matches(category, severity, service, source)
            if score > best_score:
                best, best_score = candidate, score

        if best is not None:
            return best
        # Fall back to a generic entry for the category (one with no service
        # condition) rather than returning nothing when only service-specific
        # entries exist.
        for candidate in candidates:
            if not candidate.applies_to_service and candidate.is_active:
                return candidate
        return None

    def _candidates(self, category: ThreatCategory) -> list[MitigationRecommendation]:
        """Cached candidate list for a category."""
        key = str(category)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        try:
            candidates = self._repository.candidates_for_category(category)
        except Exception:  # noqa: BLE001 - correlation must survive a DB blip
            LOGGER.exception("Could not load mitigation candidates for %s", category)
            return []
        with self._lock:
            self._cache[key] = candidates
        return candidates

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
