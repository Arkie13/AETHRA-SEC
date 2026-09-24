"""Adapters to the external security tools AETHRA-SEC depends on.

Each integration is a thin, independently testable layer over one real tool:
``nmap`` (assessment), TShark via PyShark (capture) and Snort (intrusion
detection). No integration ever synthesises data; when its tool is unavailable
it reports that fact and the interface says so.
"""
