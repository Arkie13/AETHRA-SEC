"""Reusable presentation widgets."""

from __future__ import annotations

from aethra_sec.ui.widgets.cards import (
    Card,
    ControlBar,
    EmptyState,
    FilterBar,
    KeyValueList,
    RiskFactorList,
    ScrollableFrame,
    SeverityBadge,
    StatCard,
    SummaryCell,
    SummaryStrip,
    StatusIndicator,
    Toolbar,
)
from aethra_sec.ui.widgets.charts import (
    BarChart,
    DonutChart,
    Sparkline,
    SparkBar,
    TimelineChart,
    TimeSeriesChart,
    bytes_formatter,
)
from aethra_sec.ui.widgets.chips import (
    Chip,
    CountBadge,
    SeverityChip,
    StatusChip,
    rounded_rectangle,
)
from aethra_sec.ui.widgets.drawer import DetailDrawer, DrawerSection
from aethra_sec.ui.widgets.dialogs import (
    ConfirmDialog,
    DetailDialog,
    FormDialog,
    FormField,
    MessageDialog,
    confirm,
    show_error,
    show_message,
)
from aethra_sec.ui.widgets.palette import Command, CommandPalette
from aethra_sec.ui.widgets.surface import (
    HoverSurface,
    MetricTile,
    Pill,
    Surface,
    blend,
)
from aethra_sec.ui.widgets.tables import Column, DataTable, RowAction
from aethra_sec.ui.widgets.toast import ToastManager
from aethra_sec.ui.widgets.tooltip import Tooltip, attach_tooltip

__all__ = [
    "BarChart", "Card", "Chip", "Column", "Command", "CommandPalette",
    "ConfirmDialog", "ControlBar", "CountBadge", "DataTable", "DetailDialog",
    "DetailDrawer", "DonutChart", "DrawerSection",
    "EmptyState", "FilterBar", "HoverSurface", "MetricTile", "Pill",
    "Surface", "blend", "FormDialog", "FormField", "KeyValueList",
    "MessageDialog",
    "RiskFactorList", "RowAction", "ScrollableFrame", "SeverityBadge",
    "SeverityChip", "SparkBar", "Sparkline", "StatCard", "StatusChip",
    "StatusIndicator", "SummaryCell", "SummaryStrip", "TimeSeriesChart",
    "TimelineChart", "ToastManager", "Toolbar", "Tooltip", "attach_tooltip",
    "bytes_formatter", "confirm", "rounded_rectangle", "show_error",
    "show_message",
]
