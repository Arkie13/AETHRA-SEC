"""Version and identity constants for AETHRA-SEC."""

from __future__ import annotations

APP_NAME = "AETHRA-SEC"
APP_FULL_NAME = (
    "AETHRA-SEC: A Unified System for Automated Penetration Testing with "
    "Real-Time Network Traffic Analysis and Immediate Threat Mitigation "
    "Recommender"
)
APP_VERSION = "1.1.0"
SCHEMA_VERSION = 1

APP_PURPOSE = (
    "A defensive security operations console that unifies Nmap vulnerability "
    "assessment, live PyShark/Wireshark traffic analysis and Snort intrusion "
    "detection into a single authorised monitoring workflow, and recommends "
    "(but never performs) mitigation actions."
)

AUTHORIZED_USE_NOTICE = (
    "AETHRA-SEC must only be operated against networks, hosts and interfaces "
    "that the operator is explicitly authorised to monitor or assess. It "
    "performs no exploitation, no credential attacks and no automated "
    "mitigation. All mitigation output is advisory and requires a human "
    "decision."
)

EDUCATIONAL_USE_NOTICE = (
    "Intended for academic Network Security laboratories and authorised "
    "internal LAN environments."
)

TECHNOLOGY_STACK = (
    "Python 3.10+",
    "Tkinter / ttk desktop UI",
    "MySQL (mysql-connector-python, pooled)",
    "Nmap via python-nmap",
    "Wireshark / TShark via PyShark",
    "Snort via Alert Socket IPC (and file / TCP / syslog transports)",
    "Argon2id password hashing",
    "ReportLab (PDF) · openpyxl (Excel) · csv (CSV)",
)
