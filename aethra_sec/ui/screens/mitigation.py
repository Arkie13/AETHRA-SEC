"""Mitigation knowledge screen (§31, §68).

Analysts read the guidance; administrators maintain it. AETHRA-SEC never
applies a mitigation - the page states that plainly so no operator assumes an
action was taken on their behalf (§90).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.models.enums import EvidenceSource, Severity, ThreatCategory
from aethra_sec.models.mitigation import MitigationRecommendation
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    Card,
    Column,
    DataTable,
    FormDialog,
    FormField,
    ScrollableFrame,
    Toolbar,
    confirm,
    show_message,
)
from aethra_sec.utils.timeutil import format_local

COLUMNS = (
    Column("code", "Code", width=170),
    Column("threat", "Threat", width=250, stretch=True),
    Column("category", "Category", width=170),
    Column("severity", "Severity", width=105, colour_by="severity", glyph=True),
    Column("service", "Service", width=100),
    Column("source", "Detection source", width=130),
    Column("status", "Status", width=90, colour_by="status"),
    Column("updated", "Updated", width=140),
)


class MitigationScreen(Screen):
    """Browse and (for administrators) maintain mitigation guidance."""

    title = "Mitigation Guidance"
    subtitle = "Recommendation-only knowledge base - AETHRA-SEC never applies a mitigation"
    required_permission = "mitigation.view"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._entries: dict[int, MitigationRecommendation] = {}

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the mitigation screen.

        Wrapped in a :class:`ScrollableFrame`, matching the Alerts screen:
        the knowledge-base table and the recommendation detail are stacked,
        each given real room, and the page scrolls to reach whichever one
        does not fit - rather than a resizable split, whose divider a
        `ttk.Panedwindow` (it has no `minsize` option at all, unlike the
        classic `tk` one) cannot be stopped from landing, or being dragged,
        somewhere too cramped to show a row.
        """
        scroller = ScrollableFrame(self)
        scroller.pack(fill="both", expand=True)
        root = scroller.interior

        notice = Card(root, "How mitigation works here", fonts=self.fonts, padding=18)
        notice.pack(fill="x")
        ttk.Label(
            notice,
            text=(
                "When a threat is detected, AETHRA-SEC selects the best-matching "
                "entry below and binds it to the real evidence that triggered the "
                "detection. It does not block addresses, change firewall rules, "
                "stop services or lock accounts - the authorised operator reads "
                "the guidance and decides."
            ),
            style="CardMuted.TLabel", wraplength=1000, justify="left",
        ).pack(anchor="w")

        controls = Card(root, "Search", fonts=self.fonts, padding=18)
        controls.pack(fill="x", pady=(16, 0))
        row = ttk.Frame(controls, style="Card.TFrame")
        row.pack(fill="x")

        self._search_var = tk.StringVar()
        ttk.Label(row, text="Search", style="CardMuted.TLabel").pack(side="left")
        entry = ttk.Entry(row, textvariable=self._search_var, width=28)
        entry.pack(side="left", padx=(8, 14))
        entry.bind("<Return>", lambda _e: self.refresh())

        self._category_var = tk.StringVar(value="All")
        ttk.Label(row, text="Category", style="CardMuted.TLabel").pack(side="left")
        ttk.Combobox(
            row, textvariable=self._category_var, state="readonly", width=22,
            values=["All", *[str(c) for c in ThreatCategory]],
        ).pack(side="left", padx=(8, 14))

        self._active_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row, text="Active only", variable=self._active_only, command=self.refresh
        ).pack(side="left", padx=(0, 14))
        ttk.Button(row, text="Apply", style="Accent.TButton", command=self.refresh).pack(
            side="left"
        )

        card = Card(root, "Knowledge base", fonts=self.fonts, padding=18)
        card.pack(fill="both", expand=True, pady=(16, 0))

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        can_manage = self.can("mitigation.manage")
        toolbar.add_button("New recommendation", self._create, enabled=can_manage)
        toolbar.add_button("Edit", self._edit, enabled=can_manage)
        toolbar.add_button("Activate", lambda: self._set_active(True), enabled=can_manage)
        toolbar.add_button(
            "Deactivate", lambda: self._set_active(False), enabled=can_manage
        )
        if not can_manage:
            toolbar.add_label("Administrator access is required to edit entries.")
        self._count_label = toolbar.add_label("", side="right")

        self._table = DataTable(card, COLUMNS, height=9, on_select=self._show_entry)
        self._table.pack(fill="both", expand=True)

        detail_card = Card(root, "Recommendation", fonts=self.fonts, padding=18)
        detail_card.pack(fill="both", expand=True, pady=(16, 0))
        self._detail = tk.Text(detail_card, wrap="word")
        configure_text_widget(self._detail, self.fonts)
        scrollbar = ttk.Scrollbar(detail_card, orient="vertical", command=self._detail.yview)
        self._detail.configure(yscrollcommand=scrollbar.set)
        self._detail.insert("1.0", "Select a recommendation to read the full guidance.")
        self._detail.configure(state="disabled")
        self._detail.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload the knowledge base."""
        mitigation = self.context.mitigation
        session = self.session
        if mitigation is None or session is None:
            return
        filters: dict[str, Any] = {}
        if self._search_var.get().strip():
            filters["text"] = self._search_var.get().strip()
        if self._category_var.get() != "All":
            filters["category"] = self._category_var.get()
        if self._active_only.get():
            filters["active_only"] = True

        self.run_async(
            lambda: mitigation.list_all(session, **filters),
            self._apply,
            name="mitigation-load",
        )

    def _apply(self, entries: list[MitigationRecommendation]) -> None:
        """Render the knowledge base table."""
        self._entries = {e.id: e for e in entries if e.id is not None}
        self._table.set_rows(
            [
                {
                    "_id": entry.id,
                    "code": entry.code,
                    "threat": entry.threat_name,
                    "category": entry.category.label,
                    "severity": str(entry.severity),
                    "service": entry.applies_to_service or "any",
                    "source": (
                        entry.detection_source.label if entry.detection_source else "any"
                    ),
                    "status": entry.status_text,
                    "updated": format_local(entry.updated_at, "%d %b %Y %H:%M"),
                }
                for entry in entries
            ]
        )
        self._count_label.configure(text=f"{len(entries)} recommendation(s)")
        self.status(f"{len(entries)} mitigation recommendation(s) loaded.")
        if entries:
            self._table.select_first()

    def _selected(self) -> MitigationRecommendation | None:
        """The currently selected recommendation."""
        row = self._table.selected_row()
        if row is None:
            return None
        return self._entries.get(int(row.get("_id") or 0))

    def _show_entry(self, _row: dict[str, Any]) -> None:
        """Render the selected recommendation in full (§30)."""
        entry = self._selected()
        self._detail.configure(state="normal")
        self._detail.delete("1.0", "end")
        if entry is None:
            self._detail.insert("1.0", "Select a recommendation.")
        else:
            self._detail.insert(
                "1.0",
                "\n".join(
                    [
                        f"THREAT: {entry.threat_name}",
                        f"CODE: {entry.code}    CATEGORY: {entry.category.label}    "
                        f"SEVERITY: {entry.severity}",
                        f"APPLIES TO SERVICE: {entry.applies_to_service or 'any service'}",
                        f"DETECTION SOURCE: "
                        f"{entry.detection_source.label if entry.detection_source else 'any source'}",
                        f"STATUS: {entry.status_text}"
                        + ("   (built-in entry)" if entry.is_builtin else ""),
                        "",
                        "EXPLANATION",
                        entry.explanation or "-",
                        "",
                        "WHY IT MATTERS",
                        entry.why_it_matters or "-",
                        "",
                        "IMMEDIATE RECOMMENDED ACTION",
                        entry.immediate_action or "-",
                        "",
                        "LONG-TERM RECOMMENDED ACTION",
                        entry.long_term_action or "-",
                        "",
                        "VERIFICATION STEPS",
                        entry.verification_steps or "-",
                        "",
                        "REFERENCES",
                        entry.references or "-",
                        "",
                        "NOTE: AETHRA-SEC recommends only. Apply changes through "
                        "your normal change-control process.",
                    ]
                ),
            )
        self._detail.configure(state="disabled")

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------
    def _fields(
        self, entry: MitigationRecommendation | None = None
    ) -> list[FormField]:
        """Build the edit form fields."""
        return [
            FormField(
                "code", "Code", value=entry.code if entry else "", required=True,
                help_text="Stable identifier, for example MIT-SSH-EXPOSURE.",
            ),
            FormField(
                "threat_name", "Threat name",
                value=entry.threat_name if entry else "", required=True,
            ),
            FormField(
                "category", "Threat category", kind="choice",
                value=str(entry.category) if entry else str(ThreatCategory.UNCLASSIFIED),
                options=[str(c) for c in ThreatCategory], required=True,
            ),
            FormField(
                "severity", "Severity", kind="choice",
                value=str(entry.severity) if entry else str(Severity.MEDIUM),
                options=[str(s) for s in Severity], required=True,
            ),
            FormField(
                "applies_to_service", "Applies to service",
                value=entry.applies_to_service if entry else "",
                help_text="Leave blank to apply to any service (a generic entry).",
            ),
            FormField(
                "detection_source", "Detection source", kind="choice",
                value=str(entry.detection_source) if entry and entry.detection_source else "",
                options=["", *[str(s) for s in EvidenceSource]],
            ),
            FormField(
                "explanation", "Explanation", kind="multiline",
                value=entry.explanation if entry else "", required=True,
            ),
            FormField(
                "why_it_matters", "Why it matters", kind="multiline",
                value=entry.why_it_matters if entry else "",
            ),
            FormField(
                "immediate_action", "Immediate action", kind="multiline",
                value=entry.immediate_action if entry else "", required=True,
            ),
            FormField(
                "long_term_action", "Long-term action", kind="multiline",
                value=entry.long_term_action if entry else "",
            ),
            FormField(
                "verification_steps", "Verification steps", kind="multiline",
                value=entry.verification_steps if entry else "",
            ),
            FormField(
                "references", "References", kind="multiline",
                value=entry.references if entry else "",
            ),
            FormField(
                "is_active", "Active", kind="bool",
                value=entry.is_active if entry else True,
            ),
        ]

    @staticmethod
    def _to_model(
        values: dict[str, Any], entry: MitigationRecommendation | None = None
    ) -> MitigationRecommendation:
        """Convert form values into a model."""
        source = values.get("detection_source") or ""
        return MitigationRecommendation(
            id=entry.id if entry else None,
            code=values["code"],
            threat_name=values["threat_name"],
            category=ThreatCategory.parse(values["category"], ThreatCategory.UNCLASSIFIED),
            severity=Severity.parse(values["severity"], Severity.MEDIUM),
            applies_to_service=values.get("applies_to_service", ""),
            detection_source=EvidenceSource.parse(source) if source else None,
            explanation=values.get("explanation", ""),
            why_it_matters=values.get("why_it_matters", ""),
            immediate_action=values.get("immediate_action", ""),
            long_term_action=values.get("long_term_action", ""),
            verification_steps=values.get("verification_steps", ""),
            references=values.get("references", ""),
            is_active=bool(values.get("is_active", True)),
        )

    def _create(self) -> None:
        """Create a new recommendation."""
        mitigation = self.context.mitigation
        session = self.session
        if mitigation is None or session is None:
            return
        values = FormDialog(
            self, "New mitigation recommendation", self._fields(),
            fonts=self.fonts, submit_label="Create",
            intro=(
                "New entries take effect immediately: the correlation engine "
                "will attach them to matching detections."
            ),
        ).show()
        if not values:
            return
        self.run_async(
            lambda: mitigation.create(session, self._to_model(values)),
            lambda _r: (self.status("Recommendation created."), self.refresh()),
            name="mitigation-create",
        )

    def _edit(self) -> None:
        """Edit the selected recommendation."""
        entry = self._selected()
        mitigation = self.context.mitigation
        session = self.session
        if entry is None or mitigation is None or session is None:
            self.status("Select a recommendation first.")
            return
        values = FormDialog(
            self, f"Edit {entry.code}", self._fields(entry),
            fonts=self.fonts, submit_label="Save",
        ).show()
        if not values:
            return
        self.run_async(
            lambda: mitigation.update(session, self._to_model(values, entry)),
            lambda _r: (self.status("Recommendation updated."), self.refresh()),
            name="mitigation-update",
        )

    def _set_active(self, active: bool) -> None:
        """Activate or deactivate the selected recommendation (§110)."""
        entry = self._selected()
        mitigation = self.context.mitigation
        session = self.session
        if entry is None or entry.id is None or mitigation is None or session is None:
            self.status("Select a recommendation first.")
            return
        if not active and not confirm(
            self, "Deactivate recommendation",
            f"Deactivate '{entry.code}'?",
            detail=(
                "Deactivation is preferred over deletion: incidents that "
                "already reference this entry keep their guidance, and new "
                "detections stop using it."
            ),
            confirm_label="Deactivate", danger=True,
        ):
            return
        entry_id = entry.id
        self.run_async(
            lambda: mitigation.set_active(session, entry_id, active),
            lambda _r: (
                self.status(
                    f"Recommendation {'activated' if active else 'deactivated'}."
                ),
                self.refresh(),
            ),
            name="mitigation-active",
        )
