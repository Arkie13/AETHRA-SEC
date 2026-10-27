"""Attack Statistics: detected attacks by category, per source.

AETHRA-SEC episodes, Snort evidence and correlated attacks are counted
separately and never added together - they count different things. Every
figure comes from the database through two GROUP BY queries
(``AlertRepository.aethra_episode_statistics`` and
``snort_signature_statistics``) and is shaped by the pure function
:func:`aethra_sec.analytics.attack_categories.summarise`. A failed query is
shown as unavailable, never as zero.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.analytics.attack_categories import (
    SNORT_ATTACK_COVERAGE,
    AttackStatistics,
    summarise,
)
from aethra_sec.models.periods import period_for_range
from aethra_sec.ui.base import Screen
from aethra_sec.ui.widgets import Card, Column, DataTable, FilterBar
from aethra_sec.utils.formatting import format_count
from aethra_sec.utils.timeutil import format_local, utcnow

#: Period choices -> the shared range catalogue (models.periods), so "Today"
#: is the Dashboard's local midnight and the bounds are the same half-open
#: windows every other screen uses.
PERIODS: dict[str, str] = {
    "Today": "Today",
    "Last 24 hours": "Last 24 hours",
    "All time": "All data",
}

COLUMNS = (
    Column("category", "Category", width=110),
    Column("episodes", "AETHRA-SEC episodes", width=150, anchor="e"),
    Column("active", "Active now", width=90, anchor="e"),
    Column("correlated", "Correlated with Snort", width=160, anchor="e"),
    Column("snort_raw", "Raw Snort attack alerts", width=170, anchor="e"),
    Column("snort_records", "Snort attack records", width=150, anchor="e"),
    Column("snort_obs", "Raw Snort per-packet alerts", width=190, anchor="e"),
)

EXPLANATION = (
    "AETHRA-SEC episodes - one per attack episode detected by AETHRA-SEC's own "
    "rules (a run ends after detection.episode_gap_seconds of quiet). "
    "Correlated with Snort - those episodes the correlation engine linked to at "
    "least one Snort alert. Raw Snort attack alerts - alert lines from Snort's "
    "flood (threshold) rules, repeats included; Snort attack records - the "
    "stored rows they fold into. Raw Snort per-packet alerts - lines from rules "
    "that fire on every matching packet (a ping, a SYN); evidence, not attacks. "
    "\"no rule\" - the deployed Snort rule set has no rule for this category, "
    "so Snort cannot report it. Host sweeps are host discovery, not port "
    "scans, and are shown on their own line."
)


def table_rows(stats: AttackStatistics) -> list[dict[str, Any]]:
    """The table's rows, from the model alone."""
    rows = []
    for row in stats.rows:
        rows.append({
            "category": row.category,
            "episodes": format_count(row.aethra_episodes),
            "active": format_count(row.aethra_active),
            "correlated": format_count(row.correlated),
            "snort_raw": (format_count(row.snort_attack_raw)
                          if row.snort_attack_raw is not None else "no rule"),
            "snort_records": (format_count(row.snort_attack_records)
                              if row.snort_attack_records is not None else "no rule"),
            "snort_obs": format_count(row.snort_observation_raw),
        })
    return rows


def summary_lines(stats: AttackStatistics, period: str) -> list[tuple[str, str]]:
    """The totals beneath the table, each with what it counts."""
    latest = (format_local(stats.latest_detection, "%d %b %Y %H:%M:%S")
              if stats.latest_detection else "None in this period")
    lines = [
        ("Period", period),
        ("Unique AETHRA-SEC attack episodes (5 categories)", format_count(stats.aethra_total)),
        ("  Active now / ended", f"{format_count(stats.aethra_active)} / "
                                 f"{format_count(stats.aethra_ended)}"),
        ("Correlated attack episodes (AETHRA-SEC + Snort)", format_count(stats.correlated_total)),
        ("Raw Snort attack-rule alerts", format_count(stats.snort_attack_raw_total)),
        ("Raw Snort per-packet alerts", format_count(stats.snort_observation_raw_total)),
        ("Stored Snort records (all signatures)", format_count(stats.snort_records_total)),
        ("Unique Snort episodes", "Not shown - stored Snort history cannot be split "
                                  "into episodes reliably (repeats before 15 Oct 2026 "
                                  "were folded on a 120 s chain)"),
        ("Host sweeps (host discovery, not counted above)",
         f"{format_count(stats.host_sweep_episodes)} "
         f"({format_count(stats.host_sweep_active)} active)"),
        ("Most recent AETHRA-SEC detection", latest),
    ]
    if stats.legacy_aethra_episodes:
        lines.append((
            "Recorded before the 15 Oct 2026 revision",
            f"{format_count(stats.legacy_aethra_episodes)} of these episodes - such "
            "rows may hold several runs merged by the old 120 s window, or a ping "
            "flood's target recorded as a second source",
        ))
    if stats.unmapped_snort:
        names = ", ".join(f"{g}:{s} rev {r}" for g, s, r in stats.unmapped_snort)
        lines.append(("Snort signatures not in the deployed rule set (OTHER)",
                      f"{names} - {format_count(stats.other_snort_raw)} raw alert(s)"))
    return lines


class AttackStatisticsScreen(Screen):
    """Detected attacks by category, AETHRA-SEC and Snort side by side."""

    title = "Attack Statistics"
    subtitle = "Detected attacks by category - AETHRA-SEC episodes and Snort evidence, counted separately"

    def build(self) -> None:
        controls = Card(self, "Period", fonts=self.fonts, padding=12)
        controls.pack(fill="x")
        bar = FilterBar(controls)
        bar.pack(fill="x")
        ttk.Label(bar, text="Period", style="CardMuted.TLabel").pack(side="left")
        self._period_var = tk.StringVar(value="Last 24 hours")
        box = ttk.Combobox(bar, textvariable=self._period_var, values=list(PERIODS),
                           state="readonly", width=16)
        box.pack(side="left", padx=(8, 14))
        box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        ttk.Button(bar, text="Refresh", style="Accent.TButton",
                   command=self.refresh).pack(side="left")
        self._refreshed_var = tk.StringVar(value="Not loaded yet")
        ttk.Label(bar, textvariable=self._refreshed_var,
                  style="CardMuted.TLabel").pack(side="right")

        table_card = Card(self, "Attacks by category", fonts=self.fonts, padding=12)
        table_card.pack(fill="x", pady=(10, 0))
        self._table = DataTable(table_card, COLUMNS, height=6, show_toolbar=False,
                                empty_text="Loading...")
        self._table.pack(fill="x")

        totals = Card(self, "Totals", fonts=self.fonts, padding=12)
        totals.pack(fill="both", expand=True, pady=(10, 0))
        self._totals = tk.Text(totals, height=14, wrap="word", relief="flat")
        from aethra_sec.ui.theme import configure_text_widget

        configure_text_widget(self._totals, self.fonts)
        self._totals.pack(fill="both", expand=True)
        self._show_text("Loading...")

    def _show_text(self, text: str) -> None:
        self._totals.configure(state="normal")
        self._totals.delete("1.0", "end")
        self._totals.insert("1.0", text)
        self._totals.configure(state="disabled")

    def refresh(self) -> None:
        """Query the period on a worker; render on the Tk thread."""
        snort = self.context.snort
        session = self.session
        if snort is None or session is None:
            self._show_text("Unavailable - the detection service is not running.")
            return
        label = self._period_var.get()
        period = period_for_range(PERIODS.get(label, "Last 24 hours"))
        start = getattr(period, "start", None)
        end = getattr(period, "end", None)
        gap = 15
        settings = getattr(self.context, "settings_service", None)
        if settings is not None:
            try:
                gap = settings.get_int("detection.episode_gap_seconds", 15)
            except Exception:  # noqa: BLE001
                gap = 15

        def work() -> AttackStatistics:
            raw = snort.attack_statistics(session, start, end, gap)
            return summarise(raw["aethra"], raw["snort"])

        self.status("Loading attack statistics...")
        self.run_async(work, lambda stats: self._apply(stats, label),
                       self._failed, name="attack-statistics")

    def _apply(self, stats: AttackStatistics, label: str) -> None:
        self._table.set_rows(table_rows(stats))
        self._show_text(
            "\n".join(f"{name}: {value}" for name, value in summary_lines(stats, label))
            + "\n\n" + EXPLANATION
            + "\n\nSnort attack rules deployed for: "
            + ", ".join(sorted(SNORT_ATTACK_COVERAGE)) + "."
        )
        self._refreshed_var.set(f"Refreshed {format_local(utcnow(), '%H:%M:%S')}")
        self.status(f"Attack statistics for {label.lower()} loaded.")

    def _failed(self, message: str) -> None:
        # Never a zero: a failed query says it failed.
        self._table.set_rows([])
        self._show_text(f"Statistics unavailable - the query failed: {message}")
        self._refreshed_var.set("Last refresh failed")
        self.status("Attack statistics could not be loaded.")
