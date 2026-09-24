"""Reusable presentation widgets."""

from __future__ import annotations

from aethra_sec.ui.widgets.cards import (
    Card,
    ControlBar,
    EmptyState,
    FilterBar,
    KeyValueList,
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
from aethra_sec.ui.widgets.kpi import Kpi, KpiStrip
from aethra_sec.ui.widgets.factgrid import (
    Fact,
    FactGrid,
)
from aethra_sec.ui.widgets.interface_picker import InterfacePicker
from aethra_sec.ui.widgets.mitigation_panel import MitigationPanel
from aethra_sec.ui.widgets.splitview import SplitView, Workspace
from aethra_sec.ui.widgets.packet_inspector import PacketInspector
from aethra_sec.ui.widgets.dialogs import (
    ConfirmDialog,
    DetailDialog,
    DetailSection,
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
    "ConfirmDialog", "ControlBar", "CountBadge", "DataTable", "DetailDialog", "DetailSection",
    "DetailDrawer", "DonutChart", "DrawerSection",
    "EmptyState", "FilterBar", "HoverSurface", "MetricTile", "Pill",
    "Surface", "blend", "FormDialog", "FormField", "KeyValueList",
    "MessageDialog",
    "Fact", "FactGrid", "InterfacePicker", "Kpi", "KpiStrip", "MitigationPanel", "PacketInspector", "SplitView", "Workspace", "RowAction", "ScrollableFrame", "SeverityBadge",
    "SeverityChip", "SparkBar", "Sparkline", "StatCard", "StatusChip",
    "StatusIndicator", "SummaryCell", "SummaryStrip", "TimeSeriesChart",
    "TimelineChart", "ToastManager", "Toolbar", "Tooltip", "attach_tooltip",
    "bytes_formatter", "confirm", "rounded_rectangle", "show_error",
    "show_message",
]
