"""An error dialog must not teach the reader about the installation.

Every error AETHRA-SEC raises on purpose already carries text written for the
operator. The gap was the other branch - the ``except Exception`` that catches
what nobody anticipated. Three of those rendered ``str(exc)`` straight into a
dialog, and the text a Python exception carries is written for whoever is
debugging it:

* ``FileNotFoundError`` prints the absolute path it tried to open.
* ``KeyError`` on configuration prints the name of the missing variable.
* A driver error prints the statement that failed.

None of it helps the person looking at the dialog, and a signed-in USER - who
cannot read the audit trail or the logs - could read it off the screen. The
detail still reaches the application log with a full traceback; only what the
*screen* says changes.

The sole place a real path still appears is the packet export dialog, and that
is the path the operator just chose in a save dialog. "Permission denied" on
their own filename is the actionable answer, not a disclosure.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aethra_sec.core.errors import (
    AethraError,
    AuthenticationError,
    DatabaseError,
    ValidationFailedError,
    user_facing,
)

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "aethra_sec" / "ui"


def _statements(path: Path) -> str:
    """Source with docstrings removed, so prose is not mistaken for code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


class TestDeliberateErrorsSpeakForThemselves:
    """An error written for the operator is passed through untouched."""

    def test_an_aethra_error_keeps_its_own_words(self) -> None:
        exc = ValidationFailedError(
            "port must be 1-65535", user_message="Enter a port between 1 and 65535."
        )
        assert user_facing(exc) == "Enter a port between 1 and 65535."

    def test_the_database_error_does_not_surface_sql(self) -> None:
        """The connector's text names the statement; the operator's does not."""
        exc = DatabaseError(
            "Database operation failed: 1064 (42000): You have an error in your "
            "SQL syntax near 'SELECT * FROM users'",
            user_message=(
                "The database operation could not be completed. See the "
                "System Health screen for details."
            ),
        )
        shown = user_facing(exc)
        assert "SELECT" not in shown
        assert "1064" not in shown
        assert "System Health" in shown

    def test_authentication_stays_uninformative_on_purpose(self) -> None:
        """§62: the same answer for an unknown user and a wrong password."""
        assert user_facing(AuthenticationError()) == AuthenticationError().user_message


class TestUnexpectedErrorsDiscloseNothing:
    """The branch that catches what nobody planned for."""

    @pytest.mark.parametrize(
        "exc",
        [
            FileNotFoundError(
                2, "No such file or directory",
                r"C:\xampp\htdocs\AETHRA-SECNEW\aethra_sec\config\secrets.ini",
            ),
            KeyError("AETHRA_DB_PASSWORD"),
            PermissionError(13, "Permission denied", r"C:\Snort-wsl\log\alert"),
            RuntimeError("dumpcap -i \\Device\\NPF_{2C1A-...} -w C:\\temp\\cap.pcap"),
            ValueError("invalid literal for int() with base 10: 'admin'"),
        ],
    )
    def test_nothing_from_the_exception_reaches_the_screen(
        self, exc: Exception
    ) -> None:
        shown = user_facing(exc)
        for leak in ("C:\\", "/usr/", "NPF_", "AETHRA_DB_PASSWORD", "dumpcap"):
            assert leak not in shown, f"{leak!r} disclosed in {shown!r}"

    def test_the_message_is_the_same_whatever_failed(self) -> None:
        """A varying message is itself a disclosure channel."""
        messages = {
            user_facing(FileNotFoundError(2, "nope", "/etc/shadow")),
            user_facing(KeyError("SECRET")),
            user_facing(ZeroDivisionError("division by zero")),
        }
        assert len(messages) == 1

    def test_it_still_tells_the_operator_where_to_look(self) -> None:
        """Uninformative about internals is not the same as useless."""
        shown = user_facing(RuntimeError("boom"))
        assert "log" in shown.lower()
        assert shown.strip()

    def test_a_subclass_of_aethra_error_is_still_trusted(self) -> None:
        class Custom(AethraError):
            default_message = "The capture interface is no longer present."

        assert user_facing(Custom()) == "The capture interface is no longer present."


class TestTheUiUsesIt:
    """The helper has to be wired, not merely available."""

    @pytest.mark.parametrize("name", ["base.py", "login.py", "recovery.py"])
    def test_the_unexpected_branch_is_scrubbed(self, name: str) -> None:
        source = _statements(UI / name)
        assert "user_facing(exc)" in source

    @pytest.mark.parametrize("name", ["base.py", "login.py", "recovery.py"])
    def test_no_raw_exception_text_is_rendered(self, name: str) -> None:
        """Neither ``str(exc)`` nor an f-string interpolation of it."""
        source = _statements(UI / name)
        for line in source.splitlines():
            if "LOGGER" in line or "logger" in line:
                continue
            assert "str(exc)" not in line, line
            assert "{exc}" not in line, line

    def test_the_real_error_is_still_logged(self) -> None:
        """Scrubbing the dialog must not also lose the diagnosis."""
        source = _statements(UI / "base.py")
        assert "LOGGER.exception" in source

    def test_the_export_dialog_may_show_the_operators_own_path(self) -> None:
        """Scoped to OSError on a filename the operator just chose.

        Deliberately left alone: "Permission denied on <your file>" is the
        answer they need, and the path is one they typed.
        """
        source = _statements(UI / "widgets" / "packet_inspector.py")
        assert "except OSError as exc" in source


class TestNoBroadeningOfWhatIsTrusted:
    """``user_facing`` must not become a way to smuggle detail through."""

    def test_it_reads_only_user_message(self) -> None:
        body = inspect.getsource(user_facing)
        tree = ast.parse(body.replace(body[: body.index("def ")], "", 1))
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert attributes <= {"user_message"}, attributes

    def test_it_never_formats_the_exception(self) -> None:
        source = _statements(Path(inspect.getfile(user_facing)))
        marker = source.index("def user_facing")
        body = source[marker : source.index("class ConfigurationError")]
        assert "str(exc)" not in body
        assert "{exc}" not in body
