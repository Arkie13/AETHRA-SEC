"""Master/detail workspace layout (§12, §41).

Three screens - incidents, alerts and the mitigation knowledge base - are the
same workflow: pick a record from a list, read everything about it. Each had
built that as two sections stacked vertically, and each had chosen its own
weights. On the mitigation screen the detail pane was given more weight than
the list, so fifteen real records rendered as about two visible rows with the
rest reachable only by dragging a sash most operators never notice.

A :class:`SplitView` puts the list beside the detail instead of above it. The
list then gets the full height of the workspace - twenty-odd rows rather than
two - and the detail gets a column tall enough to read. The divider is a real
sash, so an operator can still favour one side, and the initial position is
set once from the actual width rather than inherited from whatever the panes
happened to request.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from aethra_sec.ui.theme import METRICS


class SplitView(ttk.PanedWindow):
    """A resizable list-beside-detail workspace.

    Attributes:
        master_pane: parent for the record list.
        detail_pane: parent for whatever describes the selected record.
    """

    #: Share of the width the list takes on first layout.
    DEFAULT_SHARE = 0.42
    #: Narrowest either side may be dragged to, so neither can be lost.
    MIN_PANE = 260

    def __init__(
        self,
        parent: tk.Misc,
        *,
        share: float = DEFAULT_SHARE,
        orient: str = "horizontal",
    ) -> None:
        """Create the split and its two panes."""
        super().__init__(parent, orient=orient)
        self._share = share
        self._placed = False

        self.master_pane = ttk.Frame(self, style="TFrame")
        self.detail_pane = ttk.Frame(self, style="TFrame")
        # Weights only share out space added on a later resize; the sash
        # itself starts wherever the panes' requested sizes put it, which is
        # why the first real layout places it explicitly below.
        self.add(self.master_pane, weight=2)
        self.add(self.detail_pane, weight=3)

        self.bind("<Configure>", self._place_sash)

    def _place_sash(self, event: tk.Event) -> None:
        """Put the divider where both sides are usable, once.

        Runs on the first layout that has a real width and then stops, so a
        sash the operator has dragged is never moved back underneath them.
        """
        if self._placed:
            return
        extent = int(event.width if str(self.cget("orient")) == "horizontal"
                     else event.height)
        if extent < self.MIN_PANE * 2:
            return
        self._placed = True
        try:
            self.sashpos(0, int(extent * self._share))
        except tk.TclError:  # pragma: no cover - pane not realised yet
            self._placed = False


class Workspace(ttk.Frame):
    """A screen body: a compact toolbar strip above a split workspace.

    The five redesigned screens all open the same way - a line of controls,
    then the work - so the arrangement is defined here once instead of being
    re-derived (and re-spaced) on every screen.
    """

    def __init__(self, parent: tk.Misc, *, share: float = SplitView.DEFAULT_SHARE) -> None:
        """Create the toolbar strip and the split beneath it."""
        super().__init__(parent, style="TFrame")

        #: Controls that act on the whole screen - filters, search, actions.
        self.toolbar = ttk.Frame(self, style="TFrame")
        self.toolbar.pack(fill="x", pady=(0, METRICS.space_sm))

        #: An optional one-line status/context strip under the toolbar.
        self.context = ttk.Frame(self, style="TFrame")
        self.context.pack(fill="x")

        self.split = SplitView(self, share=share)
        self.split.pack(fill="both", expand=True, pady=(METRICS.space_sm, 0))

    @property
    def master_pane(self) -> ttk.Frame:
        """Parent for the record list."""
        return self.split.master_pane

    @property
    def detail_pane(self) -> ttk.Frame:
        """Parent for the selected record's detail."""
        return self.split.detail_pane
