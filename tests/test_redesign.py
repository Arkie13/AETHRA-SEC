"""The console redesign: the type scale, the shell, and the summary strips.

The single most consequential thing fixed here is not visible in any one
screen. ``apply_theme`` used to call ``option_add("*Font", ...)``, which sets a
*widget* option, and a widget option beats the ttk *style* that would otherwise
supply the font. Every size in the scale - titles, metrics, section labels -
was therefore configured correctly, looked up correctly, and then silently
ignored, so the whole interface rendered at body size. Fixing it is what makes
hierarchy possible at all, which is why it is pinned first.

The rest is structure an operator would notice the loss of: the sign-in form's
affordances, navigation grouped by the question being asked, and one summary
component used by every queue so "how bad is it?" is answered the same way on
each of them.
"""

from __future__ import annotations

import inspect

import pytest

from aethra_sec.models.enums import IncidentStatus, RiskLevel, Severity
from aethra_sec.models.host import Host
from aethra_sec.models.incident import Incident
from aethra_sec.ui import app as app_module
from aethra_sec.ui import login as login_module
from aethra_sec.ui import theme as theme_module
from aethra_sec.ui.screens.dashboard import _balanced_columns
from aethra_sec.ui.screens.hosts import _host_counts
from aethra_sec.ui.widgets.cards import SummaryCell, SummaryStrip


# ---------------------------------------------------------------------------
# The type scale
# ---------------------------------------------------------------------------
class TestTypeScaleReachesTheWidgets:
    """A style font that a widget option overrides is not a font."""

    def test_no_blanket_font_default_is_installed(self) -> None:
        """``*Font`` matches ttk widgets too, and outranks their style."""
        source = inspect.getsource(theme_module.apply_theme)
        # The call, not the comment that explains why it is gone.
        calls = [
            line for line in source.splitlines()
            if 'option_add("*Font"' in line and not line.strip().startswith("#")
        ]
        assert not calls, calls

    def test_classic_widget_classes_still_get_a_default(self) -> None:
        """tk.Text and friends have no ttk style to fall back on."""
        source = inspect.getsource(theme_module.apply_theme)
        assert 'option_add(f"*{widget_class}.font"' in source
        for widget_class in ("Text", "Listbox", "Menu"):
            assert f'"{widget_class}"' in source

    def test_the_scale_is_actually_a_scale(self) -> None:
        """Sizes have to differ, or there is no hierarchy to render."""
        from aethra_sec.ui.theme import Fonts

        fonts = Fonts(
            body=("X", 10), body_bold=("X", 10, "bold"), small=("X", 9),
            small_bold=("X", 9, "bold"), label=("X", 8, "bold"),
            heading=("X", 12, "bold"), subheading=("X", 11, "bold"),
            title=("X", 17, "bold"), metric=("X", 26, "bold"),
            metric_small=("X", 17, "bold"), mono=("M", 9), mono_small=("M", 8),
        )
        sizes = [
            fonts.label[1], fonts.small[1], fonts.body[1], fonts.subheading[1],
            fonts.heading[1], fonts.title[1], fonts.metric[1],
        ]
        assert sizes == sorted(sizes)
        assert len(set(sizes)) == len(sizes), "two steps share a size"

    def test_the_family_is_exposed_for_one_off_sizes(self) -> None:
        """The sign-in headline needs a size the shared scale has no name for."""
        from aethra_sec.ui.theme import Fonts

        fonts = Fonts(
            body=("Segoe UI", 10), body_bold=("Segoe UI", 10, "bold"),
            small=("Segoe UI", 9), small_bold=("Segoe UI", 9, "bold"),
            label=("Segoe UI", 8, "bold"), heading=("Segoe UI", 12, "bold"),
            subheading=("Segoe UI", 11, "bold"), title=("Segoe UI", 17, "bold"),
            metric=("Segoe UI", 26, "bold"),
            metric_small=("Segoe UI", 17, "bold"),
            mono=("Consolas", 9), mono_small=("Consolas", 8),
        )
        assert fonts.family == "Segoe UI"


# ---------------------------------------------------------------------------
# Sign in
# ---------------------------------------------------------------------------
class TestSignIn:
    """The first screen, and the only one shown without a session."""

    def test_the_password_can_be_revealed(self) -> None:
        """Typing a long password blind is how people get locked out."""
        source = inspect.getsource(login_module.LoginWindow._toggle_reveal)
        assert 'configure(show="" if hidden else "*")' in source

    def test_caps_lock_is_reported(self) -> None:
        """The usual cause of a failed sign-in, and invisible without this."""
        source = inspect.getsource(login_module.LoginWindow._on_key)
        assert "Caps Lock is on." in source

    def test_only_the_username_is_ever_remembered(self) -> None:
        """A password must never reach the preference file."""
        source = inspect.getsource(login_module.LoginWindow._remember_username)
        assert "KEY_REMEMBERED_USER" in source
        assert "password" not in source.lower().replace("a password", "")

    def test_clearing_remember_me_forgets_the_stored_name(self) -> None:
        """Otherwise the box is a one-way door."""
        source = inspect.getsource(login_module.LoginWindow._remember_username)
        assert 'username if remember else ""' in source

    def test_the_button_reports_that_it_is_working(self) -> None:
        """Argon2 is deliberately slow; a dead button reads as a hang."""
        source = inspect.getsource(login_module.LoginWindow._submit_login)
        assert 'configure(text="Signing in' in source

    def test_the_message_band_hides_when_it_has_nothing_to_say(self) -> None:
        """An empty red panel above the form is noise."""
        source = inspect.getsource(login_module.LoginWindow._show_message)
        assert "pack_forget()" in source

    def test_subsystem_state_is_shown_before_any_attempt(self) -> None:
        """An operator should see the database is down, not discover it."""
        source = inspect.getsource(login_module.LoginWindow._show_startup_state)
        assert "_set_subsystem" in source
        assert 'self._submit.state(["disabled"])' in source

    def test_an_offline_database_blocks_sign_in(self) -> None:
        """Rather than failing every attempt for an unexplained reason."""
        source = inspect.getsource(login_module.LoginWindow._show_startup_state)
        assert "sign-in is not possible" in source


# ---------------------------------------------------------------------------
# The shell
# ---------------------------------------------------------------------------
class TestNavigation:
    """Grouped by the question being asked, not by the subsystem answering."""

    def test_monitoring_comes_before_findings(self) -> None:
        """"What is happening" precedes "what was found"."""
        headings = [heading for heading, _ in app_module.NAV_GROUPS]
        assert headings.index("MONITOR") < headings.index("SECURITY")
        assert headings.index("SECURITY") < headings.index("ASSETS")

    def test_help_is_last(self) -> None:
        """Nobody opens Help during an incident."""
        assert app_module.NAV_GROUPS[-1][0] == "HELP"

    def test_the_dashboard_is_the_first_entry(self) -> None:
        """It is where the console opens."""
        assert app_module.NAV_GROUPS[0][1][0] == "dashboard"

    def test_every_screen_appears_exactly_once(self) -> None:
        """A regrouping must not strand or duplicate a screen."""
        keys = [key for _h, group in app_module.NAV_GROUPS for key in group]
        assert len(keys) == len(set(keys))
        assert set(keys) == {k for k, _l, _p in app_module.NAVIGATION}

    def test_the_monitoring_screen_is_named_for_what_it_does(self) -> None:
        """"Network Monitoring" sat directly under "Dashboard" saying little."""
        labels = {key: label for key, label, _p in app_module.NAVIGATION}
        assert labels["traffic"] == "Live Monitoring"


# ---------------------------------------------------------------------------
# Summary strips
# ---------------------------------------------------------------------------
class TestSummaryCounts:
    """One component, and figures that always match the table below."""

    @staticmethod
    def _incident(severity: Severity, status: IncidentStatus) -> Incident:
        return Incident(
            id=1, reference="INC-1", title="t", description="d",
            severity=severity, status=status,
        )

    def test_hosts_report_online_from_observed_status(self) -> None:
        """Not from "exists in the inventory", which is always true."""
        hosts = [
            Host(id=1, ip_address="10.0.0.1", status="UP"),
            Host(id=2, ip_address="10.0.0.2", status="DOWN"),
            Host(id=3, ip_address="10.0.0.3", status="UNKNOWN"),
        ]
        counts = _host_counts(hosts, {"total": 3, "active_24h": 1, "trusted": 0})
        assert counts["online"] == 1
        assert counts["offline"] == 2

    def test_hosts_report_elevated_risk(self) -> None:
        """The cell an operator is actually scanning the strip for."""
        hosts = [
            Host(id=1, ip_address="10.0.0.1", risk_level=RiskLevel.CRITICAL),
            Host(id=2, ip_address="10.0.0.2", risk_level=RiskLevel.HIGH),
            Host(id=3, ip_address="10.0.0.3", risk_level=RiskLevel.LOW),
        ]
        assert _host_counts(hosts, {})["elevated"] == 2

    def test_host_totals_come_from_the_inventory_not_the_page(self) -> None:
        """The table is paged; the total is not."""
        hosts = [Host(id=1, ip_address="10.0.0.1")]
        assert _host_counts(hosts, {"total": 94})["total"] == 94


class TestSummaryStripComponent:
    """It is one component so every queue answers the question the same way."""

    def test_a_cell_may_open_a_filtered_view(self) -> None:
        """Reading a count and acting on it should not be two journeys."""
        assert "on_click" in {f for f in SummaryCell.__dataclass_fields__}

    def test_the_strip_wraps_rather_than_clipping(self) -> None:
        """Six cells do not fit a narrow window."""
        source = inspect.getsource(SummaryStrip._on_configure)
        assert "MIN_CELL_WIDTH" in source

    def test_a_missing_figure_shows_a_dash_not_a_zero(self) -> None:
        """"Unknown" and "none" are different answers."""
        source = inspect.getsource(SummaryStrip.update_counts)
        assert 'label.configure(text="-")' in source


# ---------------------------------------------------------------------------
# Dashboard layout
# ---------------------------------------------------------------------------
class TestTileGrid:
    """Six tiles across five columns leaves one stranded."""

    @pytest.mark.parametrize(
        "fits,expected", [(1, 1), (2, 2), (3, 3), (4, 3), (5, 3), (6, 6)]
    )
    def test_six_tiles_land_on_a_balanced_grid(self, fits: int, expected: int) -> None:
        """3+3 reads as a layout; 5+1 reads as a mistake."""
        assert _balanced_columns(6, fits) == expected

    def test_it_never_returns_zero_columns(self) -> None:
        """A zero would divide by zero in the caller."""
        assert _balanced_columns(6, 0) >= 1
        assert _balanced_columns(0, 0) >= 1
