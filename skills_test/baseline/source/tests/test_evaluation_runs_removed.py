"""Evaluation Runs is gone; the security system it sat beside is not.

Evaluation Runs was a test-run measurement module: an operator recorded when
an attack was initiated, and it timed how long the detectors took to notice.
That is a thesis measurement, not a view of production security data, and it
ran a background job every fifteen seconds to keep it up to date.

It was removed rather than hidden, and these tests hold both halves of that:

* nothing in the interface leads to it - no sidebar entry, no screen, no
  registry entry, no command-palette result - its worker no longer runs, and
  an old link lands on Reports instead of a broken page;
* everything it sat next to still works, in particular the two things most
  easily removed by accident with it. ``evaluation.classify`` gates the
  analyst's True/False positive actions on real alerts, and
  ``EVALUATION_RECORDED`` is what audits them. Both share the word and
  neither belonged to the feature.

The two database tables are kept. They hold one row - a run an administrator
started and cancelled, noted "verification only - not a real scenario" - and
destroying a real record of a real user action to tidy up a schema is not a
trade this system makes.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "aethra_sec"


# ---------------------------------------------------------------------------
# The feature is gone
# ---------------------------------------------------------------------------
class TestTheModulesAreRemoved:
    @pytest.mark.parametrize(
        "relative",
        [
            "ui/screens/evaluation.py",
            "services/evaluation_service.py",
            "database/repositories/evaluation.py",
            "models/evaluation.py",
        ],
    )
    def test_the_module_no_longer_exists(self, relative: str) -> None:
        assert not (PACKAGE / relative).exists(), f"{relative} is still present"

    @pytest.mark.parametrize(
        "module",
        [
            "aethra_sec.ui.screens.evaluation",
            "aethra_sec.services.evaluation_service",
            "aethra_sec.database.repositories.evaluation",
            "aethra_sec.models.evaluation",
        ],
    )
    def test_the_module_cannot_be_imported(self, module: str) -> None:
        with pytest.raises(ImportError):
            __import__(module)

    def test_nothing_in_the_package_imports_them(self) -> None:
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            code = path.read_text(encoding="utf-8")
            for name in (
                "models.evaluation", "services.evaluation_service",
                "repositories.evaluation", "screens.evaluation",
            ):
                if name in code:
                    offenders.append(f"{path.name}: {name}")
        assert not offenders, offenders


class TestNoWayIntoItRemains:
    def test_the_sidebar_reporting_section_is_reports_and_logs(self) -> None:
        from aethra_sec.ui.app import NAV_GROUPS

        assert dict(NAV_GROUPS)["REPORTING"] == ("reports", "logs")

    def test_no_navigation_entry_names_it(self) -> None:
        from aethra_sec.ui.app import NAVIGATION

        keys = [key for key, _label, _perm in NAVIGATION]
        labels = [label for _key, label, _perm in NAVIGATION]
        assert "evaluation" not in keys
        assert not any("valuation" in label for label in labels)
        assert not any("Test Run" in label for label in labels)

    def test_it_is_not_in_the_screen_registry(self) -> None:
        from aethra_sec.ui.app import MainWindow

        assert "evaluation" not in MainWindow._screen_factories()

    def test_every_navigation_entry_still_has_a_screen(self) -> None:
        """Removing one entry must not orphan another."""
        from aethra_sec.ui.app import NAV_GROUPS, NAVIGATION, MainWindow

        declared = {key for key, _label, _perm in NAVIGATION}
        grouped = {key for _title, keys in NAV_GROUPS for key in keys}
        registry = set(MainWindow._screen_factories())
        assert grouped <= declared, f"orphaned group entries: {grouped - declared}"
        assert declared <= registry, f"in the sidebar with no screen: {declared - registry}"

    def test_the_final_sidebar_is_as_specified(self) -> None:
        from aethra_sec.ui.app import NAV_GROUPS

        assert NAV_GROUPS == (
            ("MONITOR", ("dashboard", "traffic")),
            ("SECURITY", ("alerts", "mitigation")),
            ("ASSETS", ("hosts", "vulnerabilities")),
            ("REPORTING", ("reports", "logs")),
            ("ADMINISTRATION", ("users", "health", "settings")),
            ("HELP", ("help", "about")),
        )


class TestAnOldLinkLandsSomewhereReal:
    def test_the_route_redirects_to_reports(self) -> None:
        from aethra_sec.ui.app import RETIRED_SCREENS

        assert RETIRED_SCREENS["evaluation"] == "reports"

    def test_the_redirect_runs_before_the_permission_check(self) -> None:
        import inspect

        from aethra_sec.ui.app import MainWindow

        source = inspect.getsource(MainWindow.navigate)
        assert source.index("RETIRED_SCREENS") < source.index(
            "not in self._nav_buttons"
        ), "an old link is refused instead of landing on Reports"

    def test_no_screen_navigates_to_it(self) -> None:
        for path in (PACKAGE / "ui").rglob("*.py"):
            if "__pycache__" in path.parts or path.name == "app.py":
                continue
            code = path.read_text(encoding="utf-8")
            assert 'navigate("evaluation"' not in code, path.name
            assert "navigate('evaluation'" not in code, path.name


class TestTheWorkerIsGone:
    """§10, §33: no orphan timer, no hidden process."""

    def test_the_scheduled_job_is_not_registered(self) -> None:
        source = (PACKAGE / "core" / "application.py").read_text(encoding="utf-8")
        assert "evaluation-runs" not in source
        assert "evaluate_open_runs" not in source

    def test_the_context_has_no_evaluation_service(self) -> None:
        from aethra_sec.core.application import ApplicationContext

        context = ApplicationContext.__new__(ApplicationContext)
        assert not hasattr(context, "evaluation")

    def test_the_other_scheduled_jobs_are_untouched(self) -> None:
        """The jobs that run the real security system stay."""
        source = (PACKAGE / "core" / "application.py").read_text(encoding="utf-8")
        for job in (
            "assessment-queue", "correlation", "retention", "database-backup",
        ):
            assert f'"{job}"' in source, f"the {job} job was removed as well"


# ---------------------------------------------------------------------------
# What shares the word and must survive
# ---------------------------------------------------------------------------
class TestAnalystClassificationSurvives:
    """§5, §17: classifying a real alert is not an evaluation run."""

    def test_the_permission_still_exists(self) -> None:
        from aethra_sec.core.permissions import Permission

        assert Permission.EVALUATION_CLASSIFY == "evaluation.classify"

    def test_it_still_gates_alert_classification(self) -> None:
        """This is what would have broken had the permission gone with it."""
        source = (PACKAGE / "services" / "snort_service.py").read_text(
            encoding="utf-8"
        )
        assert source.count("Permission.EVALUATION_CLASSIFY") >= 2, (
            "classifying an alert or a detection no longer checks a permission"
        )

    def test_the_audit_action_for_a_verdict_survives(self) -> None:
        from aethra_sec.security.audit import AuditAction

        assert AuditAction.EVALUATION_RECORDED == "EVALUATION_RECORDED"

    def test_the_run_audit_actions_are_gone(self) -> None:
        """Nothing can write them any more.

        ``AuditAction`` is a plain class of string constants rather than an
        Enum, so the check is over its attributes.
        """
        from aethra_sec.security.audit import AuditAction

        names = {n for n in vars(AuditAction) if not n.startswith("_")}
        assert "EVALUATION_RUN_STARTED" not in names
        assert "EVALUATION_RUN_COMPLETED" not in names
        assert "EVALUATION_RECORDED" in names, "the verdict action went too"

    def test_historical_audit_rows_stay_readable(self) -> None:
        """The repository reads the action as stored text, not via the enum."""
        source = (PACKAGE / "database" / "repositories" / "audit.py").read_text(
            encoding="utf-8"
        )
        assert 'action=as_text(row.get("action"))' in source, (
            "audit actions are parsed back through the enum, so a row naming "
            "a removed action would no longer read"
        )

    def test_the_alerts_screen_still_offers_a_verdict(self) -> None:
        source = (PACKAGE / "ui" / "screens" / "alerts.py").read_text(
            encoding="utf-8"
        )
        assert '"True positive"' in source
        assert '"False positive"' in source
        assert "_classify" in source


class TestTheSecuritySystemIsUntouched:
    """§4: every subsystem the feature sat beside still exists."""

    @pytest.mark.parametrize(
        "relative",
        [
            "services/snort_service.py",
            "services/packet_capture.py",
            "services/nmap_service.py",
            "services/assessment_queue.py",
            "services/mitigation_service.py",
            "services/notification_service.py",
            "services/health_service.py",
            "services/log_service.py",
            "reports/builder.py",
        ],
    )
    def test_the_module_is_still_present(self, relative: str) -> None:
        assert (PACKAGE / relative).exists()

    @pytest.mark.parametrize(
        "screen",
        ["alerts", "traffic", "vulnerabilities", "hosts", "mitigation",
         "reports", "logs", "dashboard", "health", "settings", "users"],
    )
    def test_the_screen_is_still_registered(self, screen: str) -> None:
        from aethra_sec.ui.app import MainWindow

        assert screen in MainWindow._screen_factories()

    def test_reports_never_depended_on_evaluation_runs(self) -> None:
        """It reads the analyst's label on an alert, which is a different thing."""
        source = (PACKAGE / "reports" / "builder.py").read_text(encoding="utf-8")
        assert "EvaluationRun" not in source
        assert "evaluation_runs" not in source

    def test_no_dashboard_metric_came_from_it(self) -> None:
        source = (PACKAGE / "ui" / "screens" / "dashboard.py").read_text(
            encoding="utf-8"
        )
        for metric in (
            "detection_accuracy", "false_positive_rate", "false_negative_rate",
            "EvaluationRun",
        ):
            assert metric not in source


class TestNoFabricatedReplacement:
    """§13, §14, §24: nothing invented to fill the gap."""

    def test_no_accuracy_metric_was_introduced(self) -> None:
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            code = path.read_text(encoding="utf-8")
            for invented in (
                "detection_accuracy", "overall_accuracy", "false_negative_rate",
                "accuracy_percent",
            ):
                if invented in code:
                    offenders.append(f"{path.name}: {invented}")
        assert not offenders, (
            f"an evaluation metric survives with no feature to compute it: "
            f"{offenders}"
        )

    def test_no_simulator_replaced_it(self) -> None:
        """§24: it must not come back as a hidden attack generator."""
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            code = path.read_text(encoding="utf-8")
            for name in ("attack_simulator", "simulate_attack", "fake_attack"):
                if name in code:
                    offenders.append(f"{path.name}: {name}")
        assert not offenders, offenders

    def test_production_still_imports_no_randomness(self) -> None:
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(
                    a.name == "random" for a in node.names
                ):
                    offenders.append(path.name)
                elif isinstance(node, ast.ImportFrom) and node.module == "random":
                    offenders.append(path.name)
        assert not offenders, offenders


class TestTheStoredRunIsPreserved:
    """§8, §9, §18: the tables are deprecated, not destroyed."""

    def test_no_migration_drops_them(self) -> None:
        source = (PACKAGE / "database" / "migrations.py").read_text(
            encoding="utf-8"
        ).upper()
        for statement in (
            "DROP TABLE EVALUATION_RUNS",
            "DROP TABLE IF EXISTS EVALUATION_RUNS",
            "DELETE FROM EVALUATION_RUNS",
            "TRUNCATE TABLE EVALUATION_RUNS",
        ):
            assert statement not in source, f"a migration runs {statement}"

    def test_the_tables_are_still_declared(self) -> None:
        """Kept so an existing installation and a fresh one agree."""
        from aethra_sec.database.schema import REQUIRED_TABLES

        assert "evaluation_runs" in REQUIRED_TABLES
        assert "evaluation_run_detections" in REQUIRED_TABLES

    def test_nothing_writes_to_them_any_more(self) -> None:
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts or path.name in (
                "schema.py", "migrations.py",
            ):
                continue
            code = path.read_text(encoding="utf-8")
            if "evaluation_runs" in code or "evaluation_run_detections" in code:
                offenders.append(path.name)
        assert not offenders, f"a writer to the retired tables remains: {offenders}"
