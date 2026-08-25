"""Repository foundations.

Two rules hold for every repository in this package:

1. **Values are always bound**, never interpolated. The only strings that are
   ever concatenated into SQL are column and table identifiers, and those come
   exclusively from module-level whitelists defined next to the query.
2. **Repositories return models, not rows.** Row-to-model mapping lives here so
   services and the UI never see driver types.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence, TypeVar

from aethra_sec.database.connection import DatabaseManager
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import from_db

LOGGER = get_logger("database.repository")

T = TypeVar("T")

#: Sort directions the query builder accepts.
SORT_DIRECTIONS = ("ASC", "DESC")

#: Hard ceiling on any single result set, so a mis-set filter cannot pull an
#: unbounded number of rows into the UI thread.
MAX_ROW_LIMIT = 20_000


class SqlIdentifierError(ValueError):
    """Raised when a caller supplies a column name outside the whitelist."""


@dataclass
class QueryFilter:
    """A parameterised WHERE clause assembled from whitelisted columns.

    Example:
        >>> f = QueryFilter({"severity", "src_ip"})
        >>> f.equals("severity", "HIGH").like("src_ip", "192.168.")
        >>> f.where_clause()
        'WHERE severity = %s AND src_ip LIKE %s'
    """

    allowed_columns: set[str]
    clauses: list[str] = field(default_factory=list)
    params: list[Any] = field(default_factory=list)
    prefix: str = ""

    def _check(self, column: str) -> str:
        """Validate a column against the whitelist and apply the table alias.

        The alias is a literal supplied by repository code (never by a caller),
        which is what makes qualifying joined queries safe.
        """
        if column not in self.allowed_columns:
            raise SqlIdentifierError(
                f"Column '{column}' is not filterable on this query."
            )
        return f"{self.prefix}.{column}" if self.prefix else column

    def equals(self, column: str, value: Any) -> "QueryFilter":
        """Add ``column = %s`` when ``value`` is not ``None``/empty string."""
        if value is None or value == "":
            return self
        self.clauses.append(f"{self._check(column)} = %s")
        self.params.append(value)
        return self

    def not_equals(self, column: str, value: Any) -> "QueryFilter":
        """Add ``column <> %s``."""
        if value is None or value == "":
            return self
        self.clauses.append(f"{self._check(column)} <> %s")
        self.params.append(value)
        return self

    def like(self, column: str, value: str) -> "QueryFilter":
        """Add a contains-match. ``%`` and ``_`` in the value are escaped."""
        if not value:
            return self
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        self.clauses.append(f"{self._check(column)} LIKE %s")
        self.params.append(f"%{escaped}%")
        return self

    def in_values(self, column: str, values: Sequence[Any]) -> "QueryFilter":
        """Add ``column IN (...)`` with one placeholder per value."""
        cleaned = [v for v in values if v is not None and v != ""]
        if not cleaned:
            return self
        placeholders = ", ".join(["%s"] * len(cleaned))
        self.clauses.append(f"{self._check(column)} IN ({placeholders})")
        self.params.extend(cleaned)
        return self

    def gte(self, column: str, value: Any) -> "QueryFilter":
        """Add ``column >= %s``."""
        if value is None:
            return self
        self.clauses.append(f"{self._check(column)} >= %s")
        self.params.append(value)
        return self

    def lte(self, column: str, value: Any) -> "QueryFilter":
        """Add ``column <= %s``."""
        if value is None:
            return self
        self.clauses.append(f"{self._check(column)} <= %s")
        self.params.append(value)
        return self

    def is_null(self, column: str, null: bool = True) -> "QueryFilter":
        """Add ``column IS NULL`` / ``IS NOT NULL``."""
        suffix = "IS NULL" if null else "IS NOT NULL"
        self.clauses.append(f"{self._check(column)} {suffix}")
        return self

    def raw(self, clause: str, *params: Any) -> "QueryFilter":
        """Add a pre-written clause. Only literal SQL from repository code may
        be passed here - never operator input."""
        self.clauses.append(clause)
        self.params.extend(params)
        return self

    def any_of(self, columns: Sequence[str], value: str) -> "QueryFilter":
        """Add an OR-group of contains-matches (used by free-text search)."""
        if not value:
            return self
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        parts = [f"{self._check(col)} LIKE %s" for col in columns]
        self.clauses.append("(" + " OR ".join(parts) + ")")
        self.params.extend([f"%{escaped}%"] * len(parts))
        return self

    def where_clause(self) -> str:
        """Render the WHERE clause (empty string when no filters were added)."""
        return f"WHERE {' AND '.join(self.clauses)}" if self.clauses else ""

    def bound_params(self) -> tuple[Any, ...]:
        """Bound parameters in clause order."""
        return tuple(self.params)


def order_clause(
    column: str,
    direction: str,
    allowed_columns: set[str],
    default: str,
    prefix: str = "",
) -> str:
    """Build a validated ORDER BY clause.

    Args:
        column: requested sort column.
        direction: ``ASC`` or ``DESC`` (case-insensitive).
        allowed_columns: whitelist for this query.
        default: column used when the request is not permitted.
        prefix: table alias to qualify the column with, for joined queries.
    """
    safe_column = column if column in allowed_columns else default
    safe_direction = direction.upper() if direction.upper() in SORT_DIRECTIONS else "DESC"
    qualified = f"{prefix}.{safe_column}" if prefix else safe_column
    return f"ORDER BY {qualified} {safe_direction}"


def limit_clause(limit: int | None, offset: int = 0) -> tuple[str, tuple[Any, ...]]:
    """Build a bounded LIMIT/OFFSET clause."""
    if limit is None:
        return "", ()
    safe_limit = max(1, min(int(limit), MAX_ROW_LIMIT))
    safe_offset = max(0, int(offset))
    if safe_offset:
        return "LIMIT %s OFFSET %s", (safe_limit, safe_offset)
    return "LIMIT %s", (safe_limit,)


def encode_json(value: Any) -> str:
    """Serialise a structure for a TEXT column.

    Values that cannot be serialised are stringified rather than raising, so a
    surprising evidence payload cannot block an insert.
    """
    if value is None:
        return ""
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps({"value": str(value)})


def decode_json(raw: Any, default: Any = None) -> Any:
    """Parse a TEXT column back into a structure, tolerating malformed data."""
    if raw in (None, ""):
        return {} if default is None else default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {} if default is None else default


def as_int(value: Any) -> int | None:
    """Coerce a driver value to ``int``, or ``None`` when absent/invalid."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    """Coerce a driver value to ``float``, or ``None`` when absent/invalid."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_bool(value: Any) -> bool:
    """Coerce MySQL's ``TINYINT(1)`` to ``bool``."""
    return bool(value)


def as_text(value: Any) -> str:
    """Coerce a nullable column to ``str`` (never ``None``)."""
    return "" if value is None else str(value)


def as_dt(value: Any) -> datetime | None:
    """Interpret a stored ``DATETIME`` as timezone-aware UTC."""
    return from_db(value) if isinstance(value, datetime) else None


class Repository:
    """Base class holding the shared database handle."""

    def __init__(self, db: DatabaseManager) -> None:
        """Bind the repository to a database manager."""
        self.db = db

    def _map_all(
        self, rows: Iterable[dict[str, Any]], mapper: Callable[[dict[str, Any]], T]
    ) -> list[T]:
        """Map rows to models, skipping (and logging) any row that fails."""
        results: list[T] = []
        for row in rows:
            try:
                results.append(mapper(row))
            except Exception:  # noqa: BLE001 - one bad row must not break a page
                LOGGER.exception("Failed to map row in %s", type(self).__name__)
        return results

    def count(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run a COUNT query and return an int."""
        return int(self.db.query_value(sql, params, default=0) or 0)
