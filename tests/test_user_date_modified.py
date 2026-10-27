"""Date Modified means an administrator edited the account, and nothing else.

``updated_at`` already existed and looked like the answer. It is not: six code
paths write it, and three of them are sign-in bookkeeping. Read against this
installation before the change, the ``admin`` account's ``updated_at`` was that
morning's login rather than any edit, so showing it as "Date Modified" would
have moved the column every time somebody signed in - exactly what the column
must not do.

So ``date_modified`` is separate, nullable, and written by three paths only:
a profile edit, an activation change, and a password change. These tests hold
that boundary from both sides, because a column that quietly tracks logins is
worse than no column: it looks like evidence.

They also hold the two honesty rules. A new account has no modification date
rather than its creation date, and an existing account whose history was never
recorded keeps a dash rather than being back-filled with a date that would
assert an edit nobody made.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.database.repositories import users as users_repo
from aethra_sec.models.user import User


def _source(method) -> str:  # noqa: ANN001
    """A method's code with its docstring removed.

    The docstrings here discuss ``date_modified`` at length, so a plain
    substring check would pass on the prose alone.
    """
    body = inspect.getsource(method)
    doc = inspect.getdoc(method)
    if doc:
        for line in doc.splitlines():
            body = body.replace(line, "")
    return body


# ---------------------------------------------------------------------------
# Which writers stamp it
# ---------------------------------------------------------------------------
class TestOnlyRealEditsStampIt:
    @pytest.mark.parametrize(
        "method",
        ["update_profile", "set_active", "set_password"],
        ids=["profile edit", "activation change", "password change"],
    )
    def test_an_administrator_edit_sets_it(self, method: str) -> None:
        body = _source(getattr(users_repo.UserRepository, method))
        assert "date_modified = %s" in body, (
            f"{method} is an administrator changing the account, so it must "
            "record when"
        )

    @pytest.mark.parametrize(
        "method",
        ["register_successful_login", "register_failed_login", "set_locked"],
        ids=["sign-in", "failed login", "automatic lockout"],
    )
    def test_login_bookkeeping_does_not_set_it(self, method: str) -> None:
        body = _source(getattr(users_repo.UserRepository, method))
        assert "date_modified" not in body, (
            f"{method} is not an administrator editing the account; stamping "
            "it here is how updated_at became useless for this purpose"
        )

    def test_updated_at_is_still_maintained(self) -> None:
        """The new column is an addition, not a replacement."""
        body = _source(users_repo.UserRepository.update_profile)
        assert "updated_at = %s" in body

    def test_creation_does_not_set_it(self) -> None:
        """§4: a new account has not been modified."""
        body = _source(users_repo.UserRepository.create_user)
        assert "date_modified" not in body


# ---------------------------------------------------------------------------
# It comes from the database
# ---------------------------------------------------------------------------
class TestItIsReadFromTheDatabase:
    def test_the_column_is_selected(self) -> None:
        assert "u.date_modified" in users_repo._USER_COLUMNS

    def test_the_mapper_reads_it(self) -> None:
        body = inspect.getsource(users_repo.UserRepository._map_user)
        assert 'date_modified=as_dt(row.get("date_modified"))' in body

    def test_the_model_carries_it_and_defaults_to_none(self) -> None:
        assert "date_modified" in User.__dataclass_fields__
        assert User(id=1, username="x").date_modified is None

    def test_the_screen_does_not_compute_it(self) -> None:
        """§7: never datetime.now(), never derived from another column."""
        from aethra_sec.ui.screens import users as screen

        body = inspect.getsource(screen)
        row = body.split('"date_modified":')[1][:160]
        assert "user.date_modified" in row
        for forbidden in ("now()", "utcnow", "created_at", "last_login"):
            assert forbidden not in row, (
                f"Date Modified must be the stored value, not {forbidden}"
            )


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------
class TestTheUsersTable:
    @staticmethod
    def _keys() -> list[str]:
        from aethra_sec.ui.screens.users import USER_COLUMNS

        return [column.key for column in USER_COLUMNS]

    def test_the_layout_is_the_one_asked_for(self) -> None:
        assert self._keys() == [
            "id", "username", "full_name", "email", "role", "status",
            "failures", "last_login", "last_host", "created", "date_modified",
        ]

    def test_the_id_is_first(self) -> None:
        assert self._keys()[0] == "id"

    def test_there_is_exactly_one_id_column(self) -> None:
        """No "Database ID" or "Account ID" alongside it."""
        keys = self._keys()
        assert keys.count("id") == 1
        assert not [k for k in keys if k != "id" and k.endswith("_id")]

    def test_the_id_shown_is_the_primary_key(self) -> None:
        from aethra_sec.ui.screens import users as screen

        body = inspect.getsource(screen)
        assert '"id": user.id,' in body, (
            "the column must show the real users.id, not a row number"
        )

    def test_date_modified_is_last(self) -> None:
        assert self._keys()[-1] == "date_modified"

    def test_a_missing_value_renders_as_a_dash(self) -> None:
        """§4/§9: never a creation date standing in for an edit."""
        from aethra_sec.utils.timeutil import format_local

        assert format_local(None) == "-"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
class TestTheSchema:
    def test_the_migration_is_registered(self) -> None:
        from aethra_sec.database.migrations import MIGRATIONS

        names = {m.name for m in MIGRATIONS}
        assert "user_date_modified" in names

    def test_the_migration_is_additive(self) -> None:
        """§2: the users table is never dropped or recreated."""
        from aethra_sec.database import migrations

        body = inspect.getsource(migrations._apply_user_date_modified)
        assert "ALTER TABLE users ADD COLUMN" in body
        for forbidden in ("DROP TABLE", "TRUNCATE", "DELETE FROM", "CREATE TABLE"):
            assert forbidden not in body

    def test_the_migration_back_fills_nothing(self) -> None:
        """§9: historical accounts keep a dash, not a manufactured date."""
        from aethra_sec.database import migrations

        body = inspect.getsource(migrations._apply_user_date_modified)
        assert "UPDATE users" not in body

    def test_it_is_nullable_in_the_base_schema(self) -> None:
        """A fresh install must behave like a migrated one."""
        from pathlib import Path

        schema = Path(users_repo.__file__).resolve().parents[1] / "schema.py"
        text = schema.read_text(encoding="utf-8")
        line = next(
            l for l in text.splitlines() if "date_modified" in l and "DATETIME" in l
        )
        assert "NULL" in line and "NOT NULL" not in line

    def test_it_is_guarded_against_re_running(self) -> None:
        from aethra_sec.database import migrations

        body = inspect.getsource(migrations._apply_user_date_modified)
        assert "_column_exists" in body
