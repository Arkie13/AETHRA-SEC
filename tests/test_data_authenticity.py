"""Guards for the data authenticity audit.

The audit's conclusion was that AETHRA-SEC does not fabricate observations:
there is no random generation in the production package, the seed routine
creates only reference data, and every derived record resolves to a real
source row. These tests keep that true, and cover the one defect the audit
did find - a failed dashboard query being displayed as an observed zero.

Nothing here writes to the production database.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "aethra_sec"


def _production_sources() -> list[Path]:
    """Every module that ships in the application package."""
    return sorted(PACKAGE.rglob("*.py"))


# ---------------------------------------------------------------------------
# TEST B - no demo or random data in the production path
# ---------------------------------------------------------------------------
class TestNothingFabricatesObservations:
    def test_the_production_package_never_imports_random(self) -> None:
        """A security observation must never come from a number generator.

        ``secrets`` is a different matter and is allowed: it generates
        passwords and recovery codes, which are credentials rather than
        observations.
        """
        offenders = []
        pattern = re.compile(r"^\s*(?:import random\b|from random import)", re.M)
        for path in _production_sources():
            if pattern.search(path.read_text(encoding="utf-8")):
                offenders.append(str(path.relative_to(PACKAGE)))
        assert not offenders, f"random number generation in {offenders}"

    def test_no_module_fabricates_a_faker_style_dataset(self) -> None:
        offenders = []
        for path in _production_sources():
            text = path.read_text(encoding="utf-8").lower()
            for token in ("faker", "mimesis", "factory_boy"):
                if token in text:
                    offenders.append(f"{path.relative_to(PACKAGE)}: {token}")
        assert not offenders, offenders

    #: Tables the seed routine is allowed to write: authored reference and
    #: configuration data, none of it an observation of the network.
    SEEDABLE = {
        "roles", "permissions", "role_permissions", "system_settings",
        "mitigation_recommendations", "threat_mitigation_mapping",
        "vuln_knowledge",
    }

    def test_seeding_writes_only_to_reference_tables(self) -> None:
        """Hosts, alerts, scans, findings and packets are observations.

        Checked by the SQL the module actually contains rather than by the
        words in it: the seed module's own docstring lists the tables it
        never seeds, and the mitigation guidance text mentions hosts and
        ports in ordinary prose.
        """
        from aethra_sec.database import seed

        source = inspect.getsource(seed)
        # INSERT/REPLACE create rows; a bare UPDATE must name a table
        # followed by SET, so that "ON DUPLICATE KEY UPDATE <column>"
        # does not read as a write to a table called <column>.
        creates = re.findall(
            r"(?:INSERT|REPLACE)\s+INTO\s+`?([a-z_]+)`?", source, re.I)
        updates = re.findall(
            r"(?<!KEY )UPDATE\s+`?([a-z_]+)`?\s+SET", source, re.I)
        written = set(creates) | set(updates)
        assert written, "no SQL writes found; the check would prove nothing"
        stray = written - self.SEEDABLE
        assert not stray, (
            f"the seed routine writes to {sorted(stray)}, which hold "
            "observations rather than reference data"
        )

    def test_seed_all_reports_only_reference_counts(self) -> None:
        from aethra_sec.database.seed import seed_all

        source = inspect.getsource(seed_all)
        assert "No security records are created" in source

    def test_the_only_production_packet_source_is_the_capture_reader(self) -> None:
        """One call site feeds the traffic analyser, and it is the real one."""
        callers = []
        for path in _production_sources():
            if "analyzer.observe(" in path.read_text(encoding="utf-8"):
                callers.append(path.relative_to(PACKAGE).as_posix())
        # The file, not the line: pinning a line number would break on any
        # edit above it and would be testing the formatting, not the design.
        assert callers == ["services/packet_capture.py"], (
            f"the analyser is fed from {callers}; it must only receive "
            "packets from the capture reader"
        )


# ---------------------------------------------------------------------------
# TEST F - a failed figure is never displayed as an observation
# ---------------------------------------------------------------------------
class TestAFailedQueryIsNotAnObservedZero:
    """The defect the audit found.

    Every counter on DashboardSnapshot defaults to 0, and the service applied
    ``or 0`` to each guarded query. A database fault therefore rendered as a
    calm network - zero packets, zero detections, zero hosts - which is the
    one mistake a security console must not make.
    """

    @staticmethod
    def _snapshot(**fields):
        from aethra_sec.models.system import DashboardSnapshot
        from aethra_sec.utils.timeutil import utcnow

        return DashboardSnapshot(generated_at=utcnow(), **fields)

    def test_a_clean_snapshot_is_complete(self) -> None:
        snapshot = self._snapshot()
        assert snapshot.unreadable == ()
        assert snapshot.is_complete is True

    def test_a_genuine_empty_install_still_reports_no_data(self) -> None:
        """The first-run empty state must keep working."""
        assert self._snapshot().has_any_data is False

    def test_an_unreadable_figure_is_not_reported_as_no_data(self) -> None:
        """Zero because the query failed is not zero because nothing happened."""
        snapshot = self._snapshot(unreadable=("hosts_total",))
        assert snapshot.is_complete is False
        assert snapshot.has_any_data is True, (
            "a failed build claimed the installation was empty"
        )

    def test_the_service_records_the_name_of_every_failure(self) -> None:
        from aethra_sec.services.dashboard_service import DashboardService

        source = inspect.getsource(DashboardService.snapshot)
        assert "unreadable.append(name)" in source
        assert "snapshot.unreadable = tuple(unreadable)" in source

    def test_the_failure_is_logged_loudly_not_at_debug(self) -> None:
        """A dashboard query that cannot run is an operational fault."""
        from aethra_sec.services.dashboard_service import DashboardService

        source = inspect.getsource(DashboardService.snapshot)
        start = source.index("def attempt")
        block = source[start:start + 900]
        assert "LOGGER.warning" in block
        assert "LOGGER.debug" not in block

    def test_the_screen_declares_the_figures_it_could_not_read(self) -> None:
        from aethra_sec.ui.screens import dashboard as screen

        source = inspect.getsource(screen)
        assert "could not be read and are shown as" in source
        assert "These are not measurements" in source


# ---------------------------------------------------------------------------
# TEST G - notifications follow real events
# ---------------------------------------------------------------------------
class TestNotificationsFollowRealEvents:
    def test_no_notification_is_raised_without_a_source_event(self) -> None:
        """Each raiser is driven by a stored record or a subsystem fault."""
        from aethra_sec.services import notification_service

        source = inspect.getsource(notification_service)
        # Every path stores a reference or is an explicit subsystem failure.
        assert "reference_type" in source
        for invented in ("import random", "for _ in range(", "sample("):
            assert invented not in source, (
                f"the notification service contains {invented!r}"
            )


# ---------------------------------------------------------------------------
# TEST I - reference data is not mistaken for observation
# ---------------------------------------------------------------------------
class TestReferenceDataIsDistinctFromObservation:
    def test_mitigation_guidance_is_authored_not_observed(self) -> None:
        """Predefined guidance is legitimate reference content.

        It is authored text mapped to threat categories, and the audit must
        not treat it as a fabricated observation. What it must never do is
        claim an action was taken.
        """
        from aethra_sec.database.mitigation_guides import GUIDES

        for code, guide in GUIDES.items():
            blob = " ".join(guide.values()).lower()
            for claim in ("has been applied", "was applied", "rule applied",
                          "attack was blocked", "successfully blocked",
                          "mitigation succeeded"):
                assert claim not in blob, f"{code} claims {claim!r}"

    def test_no_schema_column_records_an_applied_mitigation(self) -> None:
        """Checked against the committed schema export.

        A column recording that a firewall rule was applied would invite a
        claim the system cannot verify, so none exists.
        """
        schema = (Path(__file__).resolve().parents[1]
                  / "sql" / "aethra_sec_schema.sql").read_text(encoding="utf-8")
        for column in ("mitigation_applied", "firewall_applied",
                       "rule_applied", "attack_blocked", "remediated_at"):
            assert column not in schema, f"the schema defines {column}"
