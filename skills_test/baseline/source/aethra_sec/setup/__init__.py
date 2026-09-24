"""First-run setup: one implementation, three front ends.

The graphical wizard (:mod:`aethra_sec.setup.wizard`), the console setup
(:mod:`aethra_sec.setup.console`, which ``setup.bat`` runs) and the installer
all drive the same modules underneath:

* :mod:`aethra_sec.setup.detection` - dependency checks that run the tools
  rather than merely locating them;
* :mod:`aethra_sec.setup.interfaces` - adapter discovery and a routing-based
  recommendation;
* :mod:`aethra_sec.setup.configfile` - reading and writing the configuration;
* :mod:`aethra_sec.setup.provisioning` - database preparation and the first
  administrator;
* :mod:`aethra_sec.setup.healthcheck` - the health report all three display.

Keeping one implementation is the point. Two setup paths that each knew how to
create an administrator would eventually create two different administrators.
"""

from __future__ import annotations

from aethra_sec.setup.detection import ProbeResult
from aethra_sec.setup.healthcheck import HealthLine, HealthReport, run_health_check
from aethra_sec.setup.interfaces import (
    DetectedInterface,
    InterfaceReport,
    detect_interfaces,
    monitoring_position_note,
)
from aethra_sec.setup.provisioning import (
    AdminResult,
    ProvisionResult,
    create_administrator,
    prepare_database,
    validate_admin_input,
)

__all__ = [
    "AdminResult",
    "DetectedInterface",
    "HealthLine",
    "HealthReport",
    "InterfaceReport",
    "ProbeResult",
    "ProvisionResult",
    "create_administrator",
    "detect_interfaces",
    "monitoring_position_note",
    "prepare_database",
    "run_health_check",
    "validate_admin_input",
]
