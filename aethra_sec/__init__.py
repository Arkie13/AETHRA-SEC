"""AETHRA-SEC — unified defensive security operations console.

The package is organised in strictly downward-depending layers:

``utils`` / ``models``  -> no project dependencies
``config``              -> utils
``database`` / ``security`` / ``analytics`` / ``integrations``
``services``            -> everything above
``core``                -> wiring, session, events
``ui``                  -> presentation only

No module in this package fabricates security data. Every value surfaced to the
operator originates from Nmap, PyShark, Snort, or a deterministic rule applied
to records produced by those tools.
"""

from __future__ import annotations

from aethra_sec.version import APP_FULL_NAME, APP_NAME, APP_VERSION

__all__ = ["APP_NAME", "APP_FULL_NAME", "APP_VERSION"]
