"""Mitigation knowledge-base persistence (§29-§31)."""

from __future__ import annotations

from typing import Any

from aethra_sec.database.repositories.base import (
    QueryFilter,
    Repository,
    as_bool,
    as_dt,
    as_int,
    as_text,
    limit_clause,
)
from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.mitigation import (
    MitigationRecommendation,
    ThreatMitigationMapping,
)
from aethra_sec.utils.timeutil import to_db, utcnow

_FILTERABLE = {
    "code", "threat_name", "category", "severity", "applies_to_service",
    "detection_source", "is_active", "is_builtin",
}
_SELECT = (
    "SELECT id, code, threat_name, category, severity, applies_to_service, "
    "detection_source, explanation, why_it_matters, immediate_action, "
    "long_term_action, verification_steps, reference_notes, "
    "enforcement_point, procedure_steps, rollback_steps, "
    "operational_warnings, is_active, "
    "is_builtin, created_by, updated_by, created_at, updated_at "
    "FROM mitigation_recommendations"
)


class MitigationRepository(Repository):
    """Reads and maintains the administrator-editable mitigation knowledge."""

    @staticmethod
    def _map(row: dict[str, Any]) -> MitigationRecommendation:
        """Map a row to :class:`MitigationRecommendation`."""
        source_text = as_text(row.get("detection_source"))
        return MitigationRecommendation(
            id=as_int(row.get("id")),
            code=as_text(row.get("code")),
            threat_name=as_text(row.get("threat_name")),
            category=ThreatCategory.parse(
                row.get("category"), ThreatCategory.UNCLASSIFIED
            ),
            severity=Severity.parse(row.get("severity"), Severity.MEDIUM),
            applies_to_service=as_text(row.get("applies_to_service")),
            detection_source=(
                EvidenceSource.parse(source_text, EvidenceSource.SYSTEM)
                if source_text
                else None
            ),
            explanation=as_text(row.get("explanation")),
            why_it_matters=as_text(row.get("why_it_matters")),
            immediate_action=as_text(row.get("immediate_action")),
            long_term_action=as_text(row.get("long_term_action")),
            verification_steps=as_text(row.get("verification_steps")),
            references=as_text(row.get("reference_notes")),
            enforcement_point=as_text(row.get("enforcement_point")),
            procedure_steps=as_text(row.get("procedure_steps")),
            rollback_steps=as_text(row.get("rollback_steps")),
            operational_warnings=as_text(row.get("operational_warnings")),
            is_active=as_bool(row.get("is_active")),
            is_builtin=as_bool(row.get("is_builtin")),
            created_by=as_int(row.get("created_by")),
            updated_by=as_int(row.get("updated_by")),
            created_at=as_dt(row.get("created_at")),
            updated_at=as_dt(row.get("updated_at")),
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def get(self, recommendation_id: int) -> MitigationRecommendation | None:
        """Fetch one recommendation."""
        row = self.db.query_one(f"{_SELECT} WHERE id = %s", (recommendation_id,))
        return self._map(row) if row else None

    def get_by_code(self, code: str) -> MitigationRecommendation | None:
        """Fetch one recommendation by its stable code."""
        row = self.db.query_one(f"{_SELECT} WHERE code = %s", (code,))
        return self._map(row) if row else None

    def list_all(
        self, *, active_only: bool = False, limit: int = 500
    ) -> list[MitigationRecommendation]:
        """List recommendations for the mitigation management screen."""
        where = "WHERE is_active = 1" if active_only else ""
        limit_sql, limit_params = limit_clause(limit)
        rows = self.db.query(
            f"{_SELECT} {where} ORDER BY category, severity DESC, code {limit_sql}",
            limit_params,
        )
        return self._map_all(rows, self._map)

    def search(
        self,
        *,
        text: str = "",
        category: str = "",
        severity: str = "",
        service: str = "",
        active_only: bool = False,
        limit: int = 500,
    ) -> list[MitigationRecommendation]:
        """Search the knowledge base."""
        query = QueryFilter(_FILTERABLE)
        query.equals("category", category)
        query.equals("severity", severity)
        query.equals("applies_to_service", service)
        if active_only:
            query.equals("is_active", 1)
        query.any_of(
            ("code", "threat_name", "explanation", "immediate_action"), text
        )
        limit_sql, limit_params = limit_clause(limit)
        rows = self.db.query(
            f"{_SELECT} {query.where_clause()} ORDER BY category, code {limit_sql}",
            (*query.bound_params(), *limit_params),
        )
        return self._map_all(rows, self._map)

    def candidates_for_category(
        self, category: ThreatCategory
    ) -> list[MitigationRecommendation]:
        """Active recommendations mapped to a threat category, best first.

        The mapping table drives priority so an administrator can promote a
        service-specific entry above the generic one.
        """
        rows = self.db.query(
            "SELECT m.id, m.code, m.threat_name, m.category, m.severity, "
            "m.applies_to_service, m.detection_source, m.explanation, "
            "m.why_it_matters, m.immediate_action, m.long_term_action, "
            "m.verification_steps, m.reference_notes, m.enforcement_point, "
            "m.procedure_steps, m.rollback_steps, m.operational_warnings, m.is_active, "
            "m.is_builtin, m.created_by, m.updated_by, m.created_at, "
            "m.updated_at FROM mitigation_recommendations m "
            "JOIN threat_mitigation_mapping tm ON tm.recommendation_id = m.id "
            "WHERE tm.category = %s AND tm.is_active = 1 AND m.is_active = 1 "
            "ORDER BY tm.priority ASC, m.id ASC",
            (str(category),),
        )
        return self._map_all(rows, self._map)

    def mappings_for_category(
        self, category: ThreatCategory
    ) -> list[ThreatMitigationMapping]:
        """Raw mapping rows for a category."""
        rows = self.db.query(
            "SELECT id, category, recommendation_id, priority, "
            "condition_service, condition_min_severity, is_active "
            "FROM threat_mitigation_mapping WHERE category = %s "
            "ORDER BY priority ASC",
            (str(category),),
        )
        return [
            ThreatMitigationMapping(
                id=as_int(r["id"]),
                category=ThreatCategory.parse(
                    r["category"], ThreatCategory.UNCLASSIFIED
                ),
                recommendation_id=as_int(r["recommendation_id"]),
                priority=as_int(r["priority"]) or 100,
                condition_service=as_text(r["condition_service"]),
                condition_min_severity=(
                    Severity.parse(r["condition_min_severity"])
                    if as_text(r["condition_min_severity"])
                    else None
                ),
                is_active=as_bool(r["is_active"]),
            )
            for r in rows
        ]

    def count_active(self) -> int:
        """Number of active recommendations."""
        return self.count(
            "SELECT COUNT(*) FROM mitigation_recommendations WHERE is_active = 1"
        )

    def distinct_categories(self) -> list[str]:
        """Categories present in the knowledge base."""
        rows = self.db.query(
            "SELECT DISTINCT category FROM mitigation_recommendations ORDER BY category"
        )
        return [as_text(r["category"]) for r in rows]

    # ------------------------------------------------------------------
    # Writes (administrator only - enforced in the service layer)
    # ------------------------------------------------------------------
    def create(
        self, recommendation: MitigationRecommendation, user_id: int | None
    ) -> int:
        """Insert a new recommendation."""
        now = to_db(utcnow())
        new_id = self.db.insert(
            "INSERT INTO mitigation_recommendations (code, threat_name, "
            "category, severity, applies_to_service, detection_source, "
            "explanation, why_it_matters, immediate_action, long_term_action, "
            "verification_steps, reference_notes, is_active, is_builtin, "
            "created_by, updated_by, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, "
            "%s, %s, %s, %s)",
            (
                recommendation.code[:64], recommendation.threat_name[:190],
                str(recommendation.category), str(recommendation.severity),
                recommendation.applies_to_service[:64],
                str(recommendation.detection_source)
                if recommendation.detection_source
                else "",
                recommendation.explanation, recommendation.why_it_matters,
                recommendation.immediate_action, recommendation.long_term_action,
                recommendation.verification_steps, recommendation.references,
                1 if recommendation.is_active else 0, user_id, user_id, now, now,
            ),
        )
        self.db.execute(
            "INSERT INTO threat_mitigation_mapping (category, "
            "recommendation_id, priority, condition_service, "
            "condition_min_severity, is_active) VALUES (%s, %s, %s, %s, '', 1) "
            "ON DUPLICATE KEY UPDATE priority = VALUES(priority), is_active = 1",
            (
                str(recommendation.category),
                new_id,
                10 if recommendation.applies_to_service else 100,
                recommendation.applies_to_service[:64],
            ),
        )
        return new_id

    def update(
        self, recommendation: MitigationRecommendation, user_id: int | None
    ) -> None:
        """Update an existing recommendation."""
        self.db.execute(
            "UPDATE mitigation_recommendations SET threat_name = %s, "
            "category = %s, severity = %s, applies_to_service = %s, "
            "detection_source = %s, explanation = %s, why_it_matters = %s, "
            "immediate_action = %s, long_term_action = %s, "
            "verification_steps = %s, reference_notes = %s, is_active = %s, "
            "updated_by = %s, updated_at = %s WHERE id = %s",
            (
                recommendation.threat_name[:190], str(recommendation.category),
                str(recommendation.severity),
                recommendation.applies_to_service[:64],
                str(recommendation.detection_source)
                if recommendation.detection_source
                else "",
                recommendation.explanation, recommendation.why_it_matters,
                recommendation.immediate_action, recommendation.long_term_action,
                recommendation.verification_steps, recommendation.references,
                1 if recommendation.is_active else 0, user_id,
                to_db(utcnow()), recommendation.id,
            ),
        )
        self.db.execute(
            "UPDATE threat_mitigation_mapping SET category = %s, "
            "condition_service = %s, is_active = %s WHERE recommendation_id = %s",
            (
                str(recommendation.category),
                recommendation.applies_to_service[:64],
                1 if recommendation.is_active else 0,
                recommendation.id,
            ),
        )

    def set_active(self, recommendation_id: int, active: bool, user_id: int | None) -> None:
        """Activate or deactivate a recommendation.

        Deactivation is preferred over deletion so incidents that already
        reference the entry keep their guidance (§110).
        """
        self.db.execute(
            "UPDATE mitigation_recommendations SET is_active = %s, "
            "updated_by = %s, updated_at = %s WHERE id = %s",
            (1 if active else 0, user_id, to_db(utcnow()), recommendation_id),
        )
        self.db.execute(
            "UPDATE threat_mitigation_mapping SET is_active = %s "
            "WHERE recommendation_id = %s",
            (1 if active else 0, recommendation_id),
        )
