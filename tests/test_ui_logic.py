"""Interface logic that can be tested without a display.

The widgets themselves need a real Tk display and are exercised by the GUI
smoke run, but the pure logic behind them - command matching, preference
storage, the severity vocabulary and the parsing of a stored risk rationale -
is ordinary code and is tested here.
"""

from __future__ import annotations

import inspect
import json

import pytest

from aethra_sec.analytics.risk_engine import (
    RiskEngine,
    ThreatEvidence,
    parse_explanation_lines,
)
from aethra_sec.models.enums import Severity, ThreatCategory
from aethra_sec.ui.state import (
    KEY_GEOMETRY,
    KEY_SIDEBAR_COLLAPSED,
    STATE_FILENAME,
    UiState,
)
from aethra_sec.models.user import ResetStatus
from aethra_sec.ui import app as app_module
from aethra_sec.ui import login as login_module
from aethra_sec.ui import recovery as recovery_module
from aethra_sec.ui.screens.users import UsersScreen as users_screen
from aethra_sec.ui.theme import (
    ICONS,
    STATUS_COLOURS,
    chip_colours,
    severity_glyph,
)
from aethra_sec.ui.widgets.palette import Command, fuzzy_match, rank


class TestCommandPaletteMatching:
    """The palette filters by subsequence, ranked most obvious first."""

    @pytest.mark.parametrize(
        ("query", "candidate"),
        [
            ("", "anything"),
            ("dash", "go to dashboard"),
            ("nm", "network monitoring"),
            ("vasc", "vulnerability assessment scan"),
        ],
    )
    def test_matches(self, query: str, candidate: str) -> None:
        """A subsequence of the candidate matches."""
        assert fuzzy_match(query, candidate)

    @pytest.mark.parametrize(
        ("query", "candidate"),
        [("zzz", "dashboard"), ("dashx", "dashboard"), ("bda", "dashboard")],
    )
    def test_refuses(self, query: str, candidate: str) -> None:
        """Characters out of order, or absent, do not match."""
        assert not fuzzy_match(query, candidate)

    def test_prefix_ranks_first(self) -> None:
        """An entry whose title starts with the query sorts above the rest."""
        commands = [
            Command("a", "Network Monitoring", "Go to"),
            Command("b", "Hosts", "Go to", detail="network inventory"),
        ]
        ordered = sorted(commands, key=lambda command: rank("net", command))
        assert ordered[0].title == "Network Monitoring"

    def test_haystack_includes_category_and_detail(self) -> None:
        """A command is findable by its category as well as its title."""
        command = Command("a", "Refresh", "Action", detail="reload the screen")
        assert fuzzy_match("action", command.haystack)
        assert fuzzy_match("reload", command.haystack)


class TestUiState:
    """Interface preferences survive a restart and tolerate a bad file."""

    def test_round_trip(self, tmp_path) -> None:
        """Values written are read back by the next instance."""
        state = UiState(tmp_path)
        state.set(KEY_GEOMETRY, "1600x980+0+0")
        state.set(KEY_SIDEBAR_COLLAPSED, True)
        state.set_table_sort("incidents", "severity", True)
        state.save()

        reloaded = UiState(tmp_path)
        assert reloaded.get_str(KEY_GEOMETRY) == "1600x980+0+0"
        assert reloaded.get_bool(KEY_SIDEBAR_COLLAPSED) is True
        assert reloaded.table_sort("incidents") == ("severity", True)
        assert reloaded.table_sort("alerts") == ("", False)

    def test_corrupt_file_is_ignored(self, tmp_path) -> None:
        """A damaged preferences file starts the console with its defaults."""
        (tmp_path / STATE_FILENAME).write_text("{not json", encoding="utf-8")
        state = UiState(tmp_path)
        assert state.get_str(KEY_GEOMETRY) == ""
        assert state.get_bool(KEY_SIDEBAR_COLLAPSED) is False

    def test_holds_no_security_data(self, tmp_path) -> None:
        """Only display preferences are written to disk."""
        state = UiState(tmp_path)
        state.set(KEY_GEOMETRY, "1200x800+10+10")
        state.set_table_sort("alerts", "received_at", True)
        state.save()

        stored = json.loads((tmp_path / STATE_FILENAME).read_text(encoding="utf-8"))
        assert set(stored) <= {KEY_GEOMETRY, KEY_SIDEBAR_COLLAPSED, "tables.sort",
                               "navigation.last_screen"}


class TestSeverityVocabulary:
    """Severity is never conveyed by colour alone."""

    @pytest.mark.parametrize(
        "value", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    def test_every_severity_has_a_shape(self, value: str) -> None:
        """Each severity carries a distinct glyph."""
        assert severity_glyph(value)

    def test_glyphs_are_distinct(self) -> None:
        """Two severities never share a shape."""
        glyphs = [severity_glyph(v) for v in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        assert len(set(glyphs)) == len(glyphs)

    def test_unknown_value_has_no_glyph(self) -> None:
        """A value that is not a severity is not decorated."""
        assert severity_glyph("SOMETHING ELSE") == ""

    def test_chip_background_is_derived_from_the_surface(self) -> None:
        """A chip tint sits between the accent and the surface it is drawn on."""
        foreground, background = chip_colours("#FF0000", surface="#000000")
        assert foreground == "#FF0000"
        assert background != "#FF0000" and background != "#000000"

    def test_every_screen_has_an_icon(self) -> None:
        """The sidebar can label every navigation entry when collapsed."""
        from aethra_sec.ui.app import NAVIGATION

        for key, _label, _permission in NAVIGATION:
            assert ICONS.get(key), f"no icon for '{key}'"


class TestNavigationGrouping:
    """The grouped sidebar covers exactly the navigation entries."""

    def test_groups_cover_every_entry_once(self) -> None:
        """No screen is missing from a group, and none appears twice."""
        from aethra_sec.ui.app import NAVIGATION, NAV_GROUPS

        grouped = [key for _heading, keys in NAV_GROUPS for key in keys]
        assert sorted(grouped) == sorted(key for key, _l, _p in NAVIGATION)
        assert len(grouped) == len(set(grouped))


class TestRiskRationaleParsing:
    """The investigation view redraws exactly what was scored."""

    def test_round_trip_from_a_real_assessment(self) -> None:
        """Factors survive being written to text and parsed back."""
        assessment = RiskEngine().score_threat(
            ThreatEvidence(
                category=ThreatCategory.PORT_SCAN,
                distinct_sources=2,
                anomaly_count=2,
                finding_count=1,
                event_count=3,
                exposure_confirmed=True,
            )
        )
        rationale = "\n".join(assessment.explanation_lines())
        factors = parse_explanation_lines(rationale)

        assert len(factors) == len(assessment.factors)
        assert [name for name, _points, _reason in factors] == [
            name for name, _points, _reason in assessment.factors
        ]
        assert sum(points for _n, points, _r in factors) == assessment.score

    def test_unparsable_lines_are_kept(self) -> None:
        """A line that does not fit the format is still displayed."""
        factors = parse_explanation_lines("+10  Known factor - because\nfree text line")
        assert factors[0] == ("Known factor", 10, "because")
        assert factors[1] == ("free text line", 0, "")

    def test_empty_rationale_yields_nothing(self) -> None:
        """An incident with no stored rationale shows no breakdown."""
        assert parse_explanation_lines("") == ()
        assert parse_explanation_lines("   \n  ") == ()


class TestSeverityOfScoring:
    """Scoring stays deterministic, which the breakdown depends on."""

    def test_same_evidence_scores_identically(self) -> None:
        """Two identical evidence sets produce the same factors."""
        evidence = ThreatEvidence(
            category=ThreatCategory.BRUTE_FORCE,
            distinct_sources=1,
            snort_alert_count=5,
            event_count=5,
            snort_priority=1,
        )
        first = RiskEngine().score_threat(evidence)
        second = RiskEngine().score_threat(evidence)
        assert first.score == second.score
        assert first.factors == second.factors
        assert first.severity is second.severity

    def test_more_sources_never_lowers_the_score(self) -> None:
        """Corroboration adds points; it never subtracts them."""
        single = RiskEngine().score_threat(
            ThreatEvidence(
                category=ThreatCategory.PORT_SCAN,
                distinct_sources=1,
                snort_alert_count=2,
                event_count=2,
            )
        )
        corroborated = RiskEngine().score_threat(
            ThreatEvidence(
                category=ThreatCategory.PORT_SCAN,
                distinct_sources=2,
                snort_alert_count=2,
                finding_count=1,
                event_count=2,
            )
        )
        assert corroborated.score >= single.score
        assert corroborated.confidence >= single.confidence
        assert Severity.parse(str(corroborated.severity)) is corroborated.severity


class TestRecoveryInterfaceWiring:
    """The password recovery workflow is reachable, and reachable safely.

    The widgets need a display, so what is checked here is the wiring that
    makes the behaviour possible - the same approach the sign-out flow tests
    take.
    """

    def test_sign_in_offers_both_halves_of_recovery(self) -> None:
        """Raising a request and redeeming a code are both one click away."""
        source = inspect.getsource(login_module.LoginWindow)
        # The affordances, not their wording: the redesign reworded the second
        # one, and the fact worth protecting is that both tabs are reachable.
        assert "Forgot password?" in source
        assert "recovery code" in source
        assert "self._open_recovery()" in source
        assert "start_tab=1" in source

    def test_sign_in_no_longer_claims_recovery_is_impossible(self) -> None:
        """The old copy said there was no reset path. There is one now."""
        source = inspect.getsource(login_module.LoginWindow)
        assert "no self-service reset" not in source
        assert "administrator review" in source or "administrator approves" in source

    def test_the_dialog_borrows_the_modal_grab_and_gives_it_back(self) -> None:
        """Closing recovery must leave the sign-in form usable."""
        source = inspect.getsource(login_module.LoginWindow._open_recovery)
        assert "dialog.grab_set()" in source
        assert "self.wait_window(dialog)" in source
        assert "self.grab_set()" in source

    def test_recovery_calls_never_touch_tk_from_a_worker(self) -> None:
        """Argon2 is slow: the call runs on a thread and returns via dispatch."""
        source = inspect.getsource(recovery_module.PasswordRecoveryDialog._run_async)
        assert "threading.Thread" in source
        assert "dispatch.post" in source
        assert ".after(" not in source

    def test_the_dialog_clears_secrets_on_close(self) -> None:
        """No password or code is left sitting in a Tk variable."""
        source = inspect.getsource(recovery_module.PasswordRecoveryDialog.close)
        assert "_redeem_password" in source
        assert "_redeem_code" in source
        assert 'set("")' in source

    def test_the_admin_queue_is_permission_guarded(self) -> None:
        """The tab is hidden without the grant, and the service re-checks it."""
        source = inspect.getsource(users_screen._build_resets)
        assert "Permission.USER_RESET_APPROVE" in source
        assert "EmptyState" in source

    def test_the_users_badge_only_asks_when_it_may(self) -> None:
        """An unauthorised count per tick would be a flood of denial records."""
        source = inspect.getsource(app_module.MainWindow._refresh_nav_badges)
        assert "session.has(Permission.USER_RESET_APPROVE)" in source
        assert "users" in app_module.BADGE_SOURCES

    def test_every_request_state_has_a_colour(self) -> None:
        """The queue never shows a status in the default 'unknown' grey."""
        for status in ResetStatus.ALL:
            assert status in STATUS_COLOURS
