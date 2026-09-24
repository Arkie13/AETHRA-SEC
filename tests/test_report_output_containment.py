"""Report output must stay inside the configured folder (PT-02).

``set_output_dir`` took no session and validated nothing, while creating any
directory it was given with ``mkdir(parents=True)``. During the authorized
assessment the call ``set_output_dir("../../../../tmp/evil")`` created
``C:\\tmp\\evil``, which is an arbitrary-filesystem-write primitive running with
the console's privileges.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aethra_sec.core.errors import PermissionDeniedError, ValidationFailedError



from aethra_sec.core.permissions import Permission
from aethra_sec.services.report_service import ReportService


class _Access:
    """Access control that grants only what the session's role holds."""

    def __init__(self, granted: set[str]) -> None:
        self._granted = granted

    def require(self, session, permission, target: str = ""):
        code = str(getattr(permission, "value", permission))
        if code not in self._granted:
            raise PermissionDeniedError(
                f"{code} required",
                user_message="You do not have permission for this.",
            )
        return session


@pytest.fixture()
def reports_root(tmp_path: Path) -> Path:
    root = tmp_path / "reports_output"
    root.mkdir()
    return root


def _service(root: Path, granted: set[str]) -> ReportService:
    return ReportService(
        builder=None, repository=None, event_bus=None, audit=None,
        access=_Access(granted), output_dir=root,
    )


@pytest.fixture()
def admin_session():
    return object()


@pytest.fixture()
def user_session():
    return object()


@pytest.fixture()
def report_service(reports_root: Path) -> ReportService:
    """An administrator's view: settings.manage granted."""
    return _service(reports_root, {str(Permission.SETTINGS_MANAGE)})


@pytest.fixture()
def analyst_service(reports_root: Path) -> ReportService:
    """An analyst: report.generate but not settings.manage."""
    return _service(reports_root, {str(Permission.REPORT_GENERATE)})


ESCAPES = [
    "../../../../tmp/evil",
    r"..\..\..\Windows\System32",
    "/etc",
    r"C:\Windows\System32",
    "../",
]


class TestOutputStaysInsideTheReportsFolder:
    """Containment is checked on the resolved path, so ".." cannot escape."""

    @pytest.mark.parametrize("escape", ESCAPES)
    def test_a_path_outside_the_root_is_refused(
        self, report_service, admin_session, escape: str
    ) -> None:
        with pytest.raises(ValidationFailedError):
            report_service.set_output_dir(admin_session, escape)

    @pytest.mark.parametrize("escape", ESCAPES)
    def test_a_refused_path_is_never_created(
        self, report_service, admin_session, escape: str, tmp_path: Path
    ) -> None:
        """The write primitive was the mkdir, so nothing may be created."""
        before = {p for p in Path(tmp_path).rglob("*")}
        with pytest.raises(ValidationFailedError):
            report_service.set_output_dir(admin_session, escape)
        assert {p for p in Path(tmp_path).rglob("*")} == before

    def test_a_folder_inside_the_root_is_allowed(
        self, report_service, admin_session
    ) -> None:
        """The feature still works for what it is for."""
        report_service.set_output_dir(admin_session, "quarterly")
        assert report_service.output_dir.name == "quarterly"

    def test_the_root_itself_is_allowed(self, report_service, admin_session) -> None:
        root = report_service.output_dir
        report_service.set_output_dir(admin_session, root)
        assert report_service.output_dir == Path(root).resolve()


class TestOnlyAnAdministratorMayRedirectOutput:
    """Choosing where files land is configuration, not report generation."""

    def test_an_analyst_account_cannot_redirect_output(
        self, analyst_service, user_session
    ) -> None:
        """report.generate is held by ordinary analysts, so it is not enough."""
        with pytest.raises(PermissionDeniedError):
            analyst_service.set_output_dir(user_session, "quarterly")

    def test_a_session_is_required(self, report_service) -> None:
        """The call took no session at all before this."""
        with pytest.raises(TypeError):
            report_service.set_output_dir("quarterly")  # type: ignore[call-arg]
