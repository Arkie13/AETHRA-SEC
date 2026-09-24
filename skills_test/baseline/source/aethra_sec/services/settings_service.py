"""Runtime access to administrator-tunable settings (§40, §91).

Values live in the ``system_settings`` table so an administrator can change
detection thresholds, retention and refresh rates without editing code. This
service caches them in memory (they are read on every packet in the hot path)
and refreshes the cache when a value changes or on a periodic tick.

Every write is permission-checked and audited.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from aethra_sec.config.defaults import SETTING_SPEC_BY_KEY, SettingSpec
from aethra_sec.core.errors import ValidationFailedError
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.settings import SettingsRepository
from aethra_sec.models.system import SystemSetting
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("services.settings")


class SettingsService:
    """Cached, validated access to the tunable settings table."""

    def __init__(
        self,
        repository: SettingsRepository,
        access: AccessControl | None = None,
        audit: AuditService | None = None,
    ) -> None:
        """Create the service and load the cache."""
        self._repository = repository
        self._access = access
        self._audit = audit
        self._lock = threading.RLock()
        self._cache: dict[str, Any] = {}
        self._listeners: list[Callable[[str, Any], None]] = []
        self.reload()

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def reload(self) -> int:
        """Refresh the in-memory cache from the database.

        Returns:
            The number of settings loaded. On a database failure the previous
            cache is kept so the detection pipeline keeps working with the last
            known-good thresholds.
        """
        try:
            stored = self._repository.load_all()
        except Exception:  # noqa: BLE001 - never let a settings read stop capture
            LOGGER.warning("Could not reload settings; keeping the cached values.")
            return len(self._cache)
        with self._lock:
            self._cache = {key: setting.typed_value() for key, setting in stored.items()}
            return len(self._cache)

    def get(self, key: str, default: Any = None) -> Any:
        """Read a setting, falling back to its declared default."""
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        spec = SETTING_SPEC_BY_KEY.get(key)
        if spec is not None:
            return spec.default
        return default

    def get_int(self, key: str, default: int = 0) -> int:
        """Read an integer setting."""
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        """Read a float setting."""
        try:
            return float(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Read a boolean setting."""
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def get_str(self, key: str, default: str = "") -> str:
        """Read a string setting."""
        value = self.get(key, default)
        return "" if value is None else str(value)

    def list_for_ui(self, category: str = "") -> list[SystemSetting]:
        """Settings for the Settings screen, with descriptions."""
        return self._repository.list_by_category(category)

    def categories(self) -> list[str]:
        """Distinct setting categories."""
        return self._repository.categories()

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def set(self, session: Session, key: str, value: Any) -> Any:
        """Validate and persist a setting change.

        Args:
            session: the acting administrator's session.
            key: setting key; must be a declared setting.
            value: new value, coerced and range-checked against the spec.

        Returns:
            The stored, typed value.

        Raises:
            PermissionDeniedError: when the session lacks SETTINGS_MANAGE.
            ValidationFailedError: on an unknown key or an out-of-range value.
        """
        if self._access:
            self._access.require(session, Permission.SETTINGS_MANAGE, target=key)

        spec = SETTING_SPEC_BY_KEY.get(key)
        if spec is None:
            raise ValidationFailedError(
                f"Unknown setting '{key}'.",
                user_message=f"'{key}' is not a recognised setting.",
            )

        typed = self._coerce(spec, value)
        previous = self.get(key)
        stored_text = (
            "true" if (spec.value_type == "bool" and typed) else
            "false" if spec.value_type == "bool" else
            str(typed)
        )
        self._repository.set_value(key, stored_text, session.user_id if session else None)
        with self._lock:
            self._cache[key] = typed

        if self._audit:
            self._audit.record(
                AuditAction.SETTING_CHANGED,
                session=session,
                category=AuditCategory.ADMINISTRATION,
                target_type="setting",
                target_id=key,
                detail=f"Changed '{key}' from {previous!r} to {typed!r}.",
            )
        LOGGER.info("Setting '%s' changed to %r.", key, typed)

        for listener in list(self._listeners):
            try:
                listener(key, typed)
            except Exception:  # noqa: BLE001 - a listener must not break a save
                LOGGER.exception("Settings listener failed for '%s'", key)
        return typed

    @staticmethod
    def _coerce(spec: SettingSpec, value: Any) -> Any:
        """Coerce and range-check a value against its declaration.

        Raises:
            ValidationFailedError: when the value cannot be used.
        """
        try:
            if spec.value_type == "int":
                typed: Any = int(str(value).strip())
            elif spec.value_type == "float":
                typed = float(str(value).strip())
            elif spec.value_type == "bool":
                typed = str(value).strip().lower() in {"1", "true", "yes", "on"}
            else:
                typed = str(value).strip()
        except (TypeError, ValueError) as exc:
            raise ValidationFailedError(
                f"Setting '{spec.key}' expects a {spec.value_type} value.",
                user_message=(
                    f"'{spec.key}' must be a {spec.value_type} value."
                ),
            ) from exc

        if spec.value_type in ("int", "float"):
            if spec.minimum is not None and typed < spec.minimum:
                raise ValidationFailedError(
                    f"'{spec.key}' must be at least {spec.minimum}.",
                    user_message=f"'{spec.key}' must be at least {spec.minimum}.",
                )
            if spec.maximum is not None and typed > spec.maximum:
                raise ValidationFailedError(
                    f"'{spec.key}' must be at most {spec.maximum}.",
                    user_message=f"'{spec.key}' must be at most {spec.maximum}.",
                )
        if spec.value_type == "str" and len(str(typed)) > 512:
            raise ValidationFailedError(
                f"'{spec.key}' is too long.",
                user_message=f"'{spec.key}' must be 512 characters or fewer.",
            )
        return typed

    def add_listener(self, listener: Callable[[str, Any], None]) -> None:
        """Register a callback invoked after a setting changes.

        Services use this to apply a new threshold immediately instead of
        waiting for a restart.
        """
        self._listeners.append(listener)

    def spec_for(self, key: str) -> SettingSpec | None:
        """Declared specification for a setting (used by the Settings screen)."""
        return SETTING_SPEC_BY_KEY.get(key)
