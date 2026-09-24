"""The manuscript's §3.9.8 rate bands, and how the IDS queue presents them.

The bands are a study-defined measure, so the danger is not that the code
stops working but that the number shown to an operator drifts away from the
number actually applied. These tests hold the two together: the classifier and
every label read from one definition, and the severity summary states its
threshold in text rather than leaving it to a tooltip.

The counts beside those thresholds are a separate concern and are deliberately
untouched here - they come from stored rows, and nothing in this feature may
change them.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from aethra_sec.analytics.anomaly_rules import (
    FLOOD_BAND_HIGH_FLOOR,
    FLOOD_BAND_LOW_FLOOR,
    FLOOD_BAND_MEDIUM_FLOOR,
    FLOOD_BANDS,
    flood_band,
    flood_severity,
)
from aethra_sec.models.enums import Severity

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "aethra_sec" / "ui" / "screens" / "alerts.py"
CARDS = ROOT / "aethra_sec" / "ui" / "widgets" / "cards.py"


class TestTheBandsAreTheManuscripts:
    """The values themselves, exactly as §3.9.8 states them."""

    def test_the_three_bands_are_defined(self) -> None:
        assert [b.label for b in FLOOD_BANDS] == ["HIGH", "MEDIUM", "LOW"]

    def test_low_is_100_to_500(self) -> None:
        band = flood_band(Severity.LOW)
        assert band is not None
        assert (band.min_pps, band.max_pps) == (100, 500)
        assert band.range_text == "100-500 pps"
        assert band.description == (
            "Traffic above the normal baseline but of limited volume."
        )

    def test_medium_is_501_to_1000(self) -> None:
        band = flood_band(Severity.MEDIUM)
        assert band is not None
        assert (band.min_pps, band.max_pps) == (501, 1000)
        assert band.range_text == "501-1,000 pps"
        assert band.description == (
            "Sustained abnormal traffic consistent with an active flood."
        )

    def test_high_is_above_1000(self) -> None:
        band = flood_band(Severity.HIGH)
        assert band is not None
        assert band.min_pps == 1001
        assert band.max_pps is None, "HIGH is unbounded above"
        assert band.range_text == "> 1,000 pps"
        assert band.description == (
            "High-volume flooding consistent with a denial-of-service condition."
        )

    def test_the_prose_threshold_matches_the_numbers(self) -> None:
        assert flood_band(Severity.HIGH).threshold_text == "Greater than 1,000 pps"
        assert flood_band(Severity.MEDIUM).threshold_text == "501 to 1,000 pps"
        assert flood_band(Severity.LOW).threshold_text == "100 to 500 pps"

    def test_a_review_state_has_no_band(self) -> None:
        """UNREVIEWED is not a traffic rate, so it must not acquire a threshold."""
        for severity in Severity:
            band = flood_band(severity)
            if severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
                assert band is not None
            else:
                assert band is None, (
                    f"{severity} was given a rate band the manuscript does not define"
                )


class TestTheClassifierAndTheLabelsAgree:
    """One definition, so a displayed range cannot drift from the applied one."""

    def test_the_floors_are_unchanged(self) -> None:
        assert (FLOOD_BAND_LOW_FLOOR, FLOOD_BAND_MEDIUM_FLOOR,
                FLOOD_BAND_HIGH_FLOOR) == (100.0, 500.0, 1000.0)

    def test_classification_still_follows_section_3_9_8(self) -> None:
        """Unchanged by this feature - the boundaries behave as before."""
        assert flood_severity(100)[0] is Severity.LOW
        assert flood_severity(500)[0] is Severity.LOW
        assert flood_severity(500.5)[0] is Severity.MEDIUM
        assert flood_severity(1000)[0] is Severity.MEDIUM
        assert flood_severity(1000.5)[0] is Severity.HIGH

    def test_each_band_description_comes_from_the_shared_definition(self) -> None:
        for rate, band in ((1500, FLOOD_BANDS[0]), (700, FLOOD_BANDS[1]),
                           (300, FLOOD_BANDS[2])):
            assert flood_severity(rate)[1] == band.summary()

    def test_the_classifier_does_not_repeat_the_ranges(self) -> None:
        """A second copy of "501-1,000" is how the two drift apart."""
        source = inspect.getsource(flood_severity)
        for literal in ("> 1,000 pps", "501-1,000 pps", "100-500 pps"):
            assert literal not in source, (
                f"{literal!r} is written out in the classifier as well as in "
                "FLOOD_BANDS; there must be one definition"
            )

    def test_below_the_low_floor_is_still_reported_and_says_so(self) -> None:
        """The manuscript defines no band under 100 pps, so none is invented."""
        severity, band = flood_severity(40)
        assert severity is Severity.LOW
        assert "below" in band, (
            "a rate under the Low floor must say it was under it, not be "
            "presented as if it sat inside the band"
        )

    def test_no_band_claims_to_cover_0_to_99(self) -> None:
        for band in FLOOD_BANDS:
            assert band.min_pps >= 100, (
                "a band was extended below the manuscript's 100 pps Low floor"
            )


class TestTheSummaryStripStatesItsThresholds:
    """Visible text, not hover alone."""

    def test_the_cells_read_their_captions_from_the_shared_bands(self) -> None:
        source = ast.unparse(
            next(
                node for node in ast.walk(ast.parse(ALERTS.read_text(encoding="utf-8")))
                if isinstance(node, ast.FunctionDef) and node.name == "_build_summary"
            )
        )
        assert "flood_band(" in source, (
            "the summary no longer reads the manuscript bands"
        )
        for literal in ("> 1,000 pps", "501-1,000 pps", "100-500 pps"):
            assert literal not in source, (
                f"{literal!r} is hardcoded in the screen instead of being read "
                "from FLOOD_BANDS"
            )

    def test_unreviewed_is_given_no_threshold(self) -> None:
        """UNREVIEWED is a review state, so it gets no §3.9.8 rate band.

        Asserted on the cell's actual text rather than on the mere presence of
        a caption. A caption used to mean "rate threshold" and nothing else,
        so "has no caption" was a fair proxy; the unreviewed cell now captions
        the row marker that corresponds to this figure, which is not a rate
        and must not be mistaken for one. What matters is that no threshold,
        no packet rate and no band label is attached to it.
        """
        tree = ast.parse(ALERTS.read_text(encoding="utf-8"))
        cell = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "SummaryCell"
            and node.args
            and getattr(node.args[0], "value", None) == "unreviewed"
        )
        rendered = ast.unparse(cell)
        for rate in ("pps", "threshold", "Threshold", "100-500", "501-",
                     "> 1,000", "flood_band"):
            assert rate not in rendered, (
                f"UNREVIEWED carries {rate!r}; it is a review state, not a "
                "traffic rate"
            )

    def test_a_cell_can_carry_a_caption(self) -> None:
        from aethra_sec.ui.widgets.cards import SummaryCell

        assert "caption" in SummaryCell.__dataclass_fields__

    def test_the_caption_is_drawn_as_text(self) -> None:
        """Accessibility: the threshold must not depend on hovering."""
        source = CARDS.read_text(encoding="utf-8")
        assert "text=cell.caption" in source, (
            "the caption is no longer rendered, so the threshold would exist "
            "only in the tooltip"
        )

    def test_each_cell_gets_one_tooltip(self) -> None:
        """Binding per cell, not per refresh - tooltips must not accumulate."""
        source = CARDS.read_text(encoding="utf-8")
        assert source.count("attach_tooltip(holder") == 1


class TestTheTooltipSaysWhatTheManuscriptSays:
    def test_each_band_explains_itself(self) -> None:
        for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            band = flood_band(severity)
            text = band.explain()
            assert text.startswith(f"{band.label} SEVERITY")
            assert "Threshold:" in text and "Criteria:" in text
            assert band.threshold_text in text
            assert band.description in text

    def test_the_high_tooltip_is_the_manuscript_wording(self) -> None:
        text = flood_band(Severity.HIGH).explain()
        assert "Greater than 1,000 pps" in text
        assert "denial-of-service condition" in text

    def test_the_tooltip_uses_the_existing_component(self) -> None:
        """One tooltip system, not a second incompatible one."""
        source = CARDS.read_text(encoding="utf-8")
        assert "attach_tooltip" in source
        assert "Toplevel" not in source.split("class SummaryStrip")[1], (
            "the summary strip builds its own tooltip window instead of using "
            "the shared component"
        )


class TestTheCountsAreUntouched:
    """The thresholds are explanatory; they must not touch the figures."""

    def test_the_summary_counts_still_come_from_stored_rows(self) -> None:
        source = ALERTS.read_text(encoding="utf-8")
        tree = ast.parse(source)
        mapper = next(
            (ast.unparse(n) for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "_summary_cells"),
            "",
        )
        assert mapper, "_summary_cells is gone"
        # The counting path must not have learned about rate bands at all.
        for literal in ("> 1,000", "501-1,000", "100-500", "pps", "flood_band"):
            assert literal not in mapper, (
                "the threshold feature has reached the counting path"
            )
        assert "detection_totals" in source, (
            "the summary no longer reads its figures from the database"
        )

    def test_the_counts_are_whatever_the_database_returned(self) -> None:
        """No floor, no cap, no substitution - the stored figure, as it is."""
        from aethra_sec.ui.screens.alerts import _summary_cells

        cells = _summary_cells(
            {"HIGH": 6, "MEDIUM": 241, "LOW": 15, "unreviewed": 61}
        )
        assert cells == {"high": 6, "medium": 241, "low": 15, "unreviewed": 61}
        # And an empty database stays empty rather than being filled in.
        assert _summary_cells({}) == {
            "high": 0, "medium": 0, "low": 0, "unreviewed": 0
        }

    def test_no_count_is_hardcoded_in_the_summary(self) -> None:
        source = ast.unparse(
            next(
                node for node in ast.walk(ast.parse(ALERTS.read_text(encoding="utf-8")))
                if isinstance(node, ast.FunctionDef) and node.name == "_build_summary"
            )
        )
        # The cells are built with no figures at all; update_counts fills them.
        assert "update_counts" not in source
        for fake in ("=6", "=241", "=15", "=61", "'6'", "'241'"):
            assert fake not in source

    def test_severity_mapping_is_not_touched_by_the_bands(self) -> None:
        """Snort priority -> severity is a different rule and stays as it was."""
        from aethra_sec.analytics.risk_engine import RiskEngine

        assert RiskEngine.severity_for_snort_priority(1) is Severity.HIGH
        assert RiskEngine.severity_for_snort_priority(3) is Severity.MEDIUM
        assert RiskEngine.severity_for_snort_priority(4) is Severity.LOW
        assert RiskEngine.severity_for_snort_priority(None) is Severity.MEDIUM
