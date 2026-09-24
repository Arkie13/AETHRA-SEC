"""Navigable screens (§61)."""

from __future__ import annotations

from aethra_sec.ui.screens.about import AboutScreen, HelpScreen
from aethra_sec.ui.screens.alerts import AlertsScreen
from aethra_sec.ui.screens.dashboard import DashboardScreen
from aethra_sec.ui.screens.health import HealthScreen
from aethra_sec.ui.screens.hosts import HostsScreen
from aethra_sec.ui.screens.logs import LogsScreen
from aethra_sec.ui.screens.mitigation import MitigationScreen
from aethra_sec.ui.screens.reports import ReportsScreen
from aethra_sec.ui.screens.settings import SettingsScreen
from aethra_sec.ui.screens.traffic import TrafficScreen
from aethra_sec.ui.screens.users import UsersScreen
from aethra_sec.ui.screens.vulnerabilities import VulnerabilitiesScreen

__all__ = [
    "AboutScreen", "AlertsScreen", "DashboardScreen", "HealthScreen",
    "HelpScreen", "HostsScreen", "LogsScreen",
    "MitigationScreen", "ReportsScreen", "SettingsScreen", "TrafficScreen",
    "UsersScreen", "VulnerabilitiesScreen",
]
