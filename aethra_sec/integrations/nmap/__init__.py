"""Nmap integration: profiles, execution and result parsing."""

from __future__ import annotations

from aethra_sec.integrations.nmap.parser import (
    FindingBuilder,
    VulnKnowledgeEntry,
    extract_script_references,
    parse_scan_result,
)
from aethra_sec.integrations.nmap.profiles import (
    DEFAULT_PROFILE,
    DEFAULT_TIMING,
    PROFILE_BY_KEY,
    PROFILES,
    TIMING_TEMPLATES,
    ScanProfile,
    ScanRequest,
    available_profiles,
    build_scan_request,
    has_raw_socket_privilege,
)
from aethra_sec.integrations.nmap.runner import (
    NmapAvailability,
    NmapRunner,
    NmapRunResult,
    find_nmap,
    probe_nmap,
)

__all__ = [
    "DEFAULT_PROFILE",
    "DEFAULT_TIMING",
    "FindingBuilder",
    "NmapAvailability",
    "NmapRunResult",
    "NmapRunner",
    "PROFILES",
    "PROFILE_BY_KEY",
    "ScanProfile",
    "ScanRequest",
    "TIMING_TEMPLATES",
    "VulnKnowledgeEntry",
    "available_profiles",
    "build_scan_request",
    "extract_script_references",
    "find_nmap",
    "has_raw_socket_privilege",
    "parse_scan_result",
    "probe_nmap",
]
