"""Local interface preferences (§61).

Window geometry, the collapsed sidebar, the last screen opened and each table's
sort choice are remembered between runs. These are display preferences only:
nothing here influences detection, storage or reporting, and the file holds no
security data and no credentials.

The file lives beside the logs so it follows the same per-installation path the
rest of the application already uses, and a corrupt or unreadable file is
ignored rather than fatal - the console simply starts with its defaults.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("ui.state")

#: File name inside the configured log directory.
STATE_FILENAME = "ui_state.json"

#: Keys the console reads and writes.
KEY_GEOMETRY = "window.geometry"
KEY_SIDEBAR_COLLAPSED = "sidebar.collapsed"
KEY_LAST_SCREEN = "navigation.last_screen"
KEY_TABLE_SORT = "tables.sort"


class UiState:
    """A small JSON-backed preference store."""

    def __init__(self, directory: Path) -> None:
        """Load preferences from ``directory`` if a file is present."""
        self._path = Path(directory) / STATE_FILENAME
        self._values: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Read the file, tolerating absence and corruption."""
        try:
            if self._path.exists():
                loaded = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._values = loaded
        except (OSError, ValueError) as exc:
            LOGGER.debug("Interface preferences could not be read: %s", exc)
            self._values = {}

    def save(self) -> None:
        """Write the file, tolerating a read-only or missing directory."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._values, indent=2, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            LOGGER.debug("Interface preferences could not be written: %s", exc)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        """Read one preference."""
        return self._values.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Write one preference in memory; call :meth:`save` to persist."""
        self._values[key] = value

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Read a boolean preference."""
        value = self._values.get(key, default)
        return bool(value)

    def get_str(self, key: str, default: str = "") -> str:
        """Read a string preference."""
        value = self._values.get(key, default)
        return str(value) if isinstance(value, (str, int, float)) else default

    def table_sort(self, table_key: str) -> tuple[str, bool]:
        """``(column, descending)`` remembered for a table, or ``("", False)``."""
        sorts = self._values.get(KEY_TABLE_SORT)
        if not isinstance(sorts, dict):
            return "", False
        entry = sorts.get(table_key)
        if isinstance(entry, list) and len(entry) == 2:
            return str(entry[0]), bool(entry[1])
        return "", False

    def set_table_sort(self, table_key: str, column: str, descending: bool) -> None:
        """Remember a table's sort choice."""
        sorts = self._values.get(KEY_TABLE_SORT)
        if not isinstance(sorts, dict):
            sorts = {}
            self._values[KEY_TABLE_SORT] = sorts
        sorts[table_key] = [column, bool(descending)]
