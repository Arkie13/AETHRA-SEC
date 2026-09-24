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
from aethra_sec.models.scope import scope_of
from aethra_sec.models.mitigation import MitigationRecommendation
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import METRICS, PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    MitigationPanel,
    FilterBar,
    Workspace,
    Card,
    Column,
    DataTable,
    FormDialog,
    FormField,
    Toolbar,
    confirm,
    show_message,
)
from aethra_sec.utils.timeutil import format_local

COLUMNS = (
    Column("code", "Code", width=170),
    Column("threat", "Threat", width=250),
    Column("category", "Category", width=170),
    # Which of these correspond to the study's tested attack scenarios, and
    # which are guidance for other events the sensors genuinely observe. Both
    # are real; conflating them would overstate the study's scope.
    Column("scope", "Scope", width=150),
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
        #: Set by :meth:`set_focus_code` when another screen links here.
        self._focus_code = ""

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """A knowledge-base workspace: the entries beside the guidance.

        This was two prose panels stacked above a *vertical* split whose lower
        half - the guidance text - carried more weight than the list above it.
        Fifteen real recommendations therefore rendered as roughly two visible
        rows. The list now sits beside the guidance and takes the full height
        of the workspace, so the whole knowledge base is on screen at once.
        """
        workspace = Workspace(self, share=0.46)
        workspace.pack(fill="both", expand=True)

        # Filters live on one line rather than inside a titled panel: they are
        # controls, not a section of the page.
        row = FilterBar(workspace.toolbar)
        row.pack(fill="x")

        # No search box here. The knowledge-base table carries its own, which
        # filters live as you type; a second one that only applied on Enter or
        # on an Apply button meant two controls doing the same job, and the
        # slower one looked like the primary. These two narrow the query the
        # table cannot: they change what is fetched, so each applies at once
        # and there is nothing left for an Apply button to do.
        self._category_var = tk.StringVar(value="All")
        ttk.Label(row, text="Category", style="CardMuted.TLabel").pack(side="left")
        categories = ttk.Combobox(
            row, textvariable=self._category_var, state="readonly", width=20,
            values=["All", *[str(c) for c in ThreatCategory]],
        )
        categories.pack(side="left", padx=(METRICS.space_sm, METRICS.space_md))
        categories.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        self._active_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row, text="Active only", variable=self._active_only,
            command=self.refresh, style="Toolbar.TCheckbutton",
        ).pack(side="left")

        # The standing caveat is one muted line under the controls, not a
        # titled panel: it never changes, so it should never take a panel's
        # worth of the workspace.
        disclaimer = ttk.Label(
            workspace.context,
            text=(
                "Recommendation-only: AETHRA-SEC binds the best-matching entry "
                "to the real evidence that triggered a detection. It never "
                "blocks an address, changes a firewall rule, stops a service "
                "or locks an account - the authorised operator decides."
            ),
            style="CardDim.TLabel", justify="left",
        )
        disclaimer.pack(anchor="w", fill="x")
        # A fixed wraplength clips on any window narrower than the guess, so
        # follow the real width of the row the label sits in.
        workspace.context.bind(
            "<Configure>",
            lambda event: disclaimer.configure(wraplength=max(320, event.width - 8)),
            add="+",
        )

        # --- master: the whole knowledge base ---------------------------
        listing = Card(
            workspace.master_pane, "Knowledge base", fonts=self.fonts
        )
        listing.pack(fill="both", expand=True)

        toolbar = Toolbar(listing)
        toolbar.pack(fill="x", pady=(0, METRICS.space_sm))
        can_manage = self.can("mitigation.manage")
        toolbar.add_button("New", self._create, enabled=can_manage)
        toolbar.add_button("Edit", self._edit, enabled=can_manage)
        toolbar.add_button("Activate", lambda: self._set_active(True), enabled=can_manage)
        toolbar.add_button(
            "Deactivate", lambda: self._set_active(False), enabled=can_manage
        )
        if not can_manage:
            toolbar.add_label("Administrator access is required to edit entries.")
        self._count_label = toolbar.add_label("", side="right")

        # `height` is a floor, not a cap: the table fills the pane, so the row
        # count follows the window rather than this number.
        self._table = DataTable(
            workspace.master_pane, COLUMNS, height=14, on_select=self._show_entry,
            on_activate=lambda _row: self._edit() if can_manage else None,
            empty_text="No recommendations match these filters",
        )
        self._table.pack(fill="both", expand=True)

        # --- detail: the selected recommendation ------------------------
        self._detail_card = Card(
            workspace.detail_pane, "Selected mitigation",
            subtitle="select an entry", fonts=self.fonts,
        )
        self._detail_card.pack(fill="x")
        # One scroll region for the whole recommendation, rather than a Text
        # widget scrolling inside the pane that is already scrolling.
        self._panel = MitigationPanel(
            workspace.detail_pane, fonts=self.fonts,
            on_copy=self._copy_to_clipboard,
        )
        self._panel.pack(fill="both", expand=True)

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
                    "scope": scope_of(entry.category).label,
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
        if entries and not self._select_focused():
            self._table.select_first()

    def set_focus_code(self, code: str) -> None:
        """Open this screen on one existing entry, named by its stable code.

        Used by "View in Mitigation" in the full alert view. It selects a
        record that is already there; nothing is created by arriving here, and
        the code is matched against the loaded rows rather than trusted, so an
        entry that has since been removed leaves the screen on its normal
        first row instead of on a blank panel.

        The filters are cleared first: an entry hidden by the category or
        active-only control would otherwise not be in the result set to select.
        """
        self._focus_code = str(code or "").strip()
        if not self._focus_code:
            return
        self._category_var.set("All")
        self._active_only.set(False)
        if self._entries:
            # Already loaded, so show it at once rather than after the reload.
            # The code stays pending: navigate() calls this setter *before*
            # on_show(), which always refreshes, and the reload would
            # otherwise land on the first row and undo this selection.
            self._select_focused(consume=False)

    def _select_focused(self, *, consume: bool = True) -> bool:
        """Select the row set by :meth:`set_focus_code`. True when it was found.

        Args:
            consume: clear the pending code, so a later refresh selects
                normally. Left ``False`` for the eager selection made while a
                reload is still on its way.
        """
        code = self._focus_code
        if not code:
            return False
        if consume:
            self._focus_code = ""
        if self._table.select_where(lambda row: str(row.get("code", "")) == code):
            self.status(f"Showing mitigation recommendation {code}.")
            return True
        return False

    def _selected(self) -> MitigationRecommendation | None:
        """The currently selected recommendation."""
        row = self._table.selected_row()
        if row is None:
            return None
        return self._entries.get(int(row.get("_id") or 0))

    def _show_entry(self, _row: dict[str, Any]) -> None:
        """Render the selected recommendation and its real evidence (§30).

        The knowledge-base entry is already in memory, so the panel renders
        immediately; the detections bound to it are fetched on a worker so a
        selection never blocks the interface. Selecting a different entry
        before the query returns simply discards the late result.
        """
        entry = self._selected()
        if entry is None:
            self._panel.show(None, [])
            self._detail_card.set_subtitle("select an entry")
            return

        self._detail_card.set_subtitle(entry.code)
        # Render the guidance now, with no evidence, then fill the evidence in
        # when it arrives. The operator sees the actions immediately.
        self._panel.show(entry, [])

        mitigation = self.context.mitigation
        session = self.session
        if mitigation is None or session is None or entry.id is None:
            return
        wanted = entry.id

        def work() -> list[Any]:
            return mitigation.evidence_for(session, wanted)

        def done(incidents: list[Any]) -> None:
            current = self._selected()
            # A slower query for an entry the operator has already moved on
            # from must not overwrite what is now on screen.
            if current is not None and current.id == wanted:
                self._panel.show(current, incidents)

        self.run_async(work, done, name="mitigation-evidence")

    def _copy_to_clipboard(self, label: str, text: str) -> None:
        """Put generated firewall text on the clipboard for review."""
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status(f"{label} copied. AETHRA-SEC has not applied anything.")
        except tk.TclError:  # pragma: no cover - no clipboard on this display
            pass

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
                "Deactivation is preferred over deletion: detections that "
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
