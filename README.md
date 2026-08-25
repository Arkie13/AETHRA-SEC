# AETHRA-SEC

**A Unified System for Automated Penetration Testing with Real-Time Network
Traffic Analysis and Immediate Threat Mitigation Recommender**

A defensive security operations console for an authorised laboratory or
internal LAN. It brings three real tools into one workflow — **Nmap**
vulnerability assessment, **Wireshark/TShark** live traffic analysis via
PyShark, and **Snort** intrusion detection — correlates their output into
incidents, and *recommends* mitigation for a human to decide on.

---

## What it does, and what it will never do

| It does | It never does |
| --- | --- |
| Runs authorised Nmap assessments from a fixed profile catalogue | Exploit anything, run Metasploit, or attack a target |
| Captures and analyses live traffic on an interface you select | Attempt credential guessing or brute force |
| Receives real Snort alerts over four transports | Reconfigure a firewall, block an IP or disable a service |
| Correlates evidence into incidents with a transparent risk breakdown | Invent packets, alerts, hosts, findings or statistics |
| Recommends mitigation steps and explains why | Apply a mitigation on its own |
| Records every action in a hash-chained audit trail | Store a plaintext password, or log a credential |
| Recovers a forgotten password only after an administrator approves it | Reset a password on its own, or email one out |

Targets outside the configured authorised networks are **refused** before any
command is built. See [`docs/SECURITY.md`](docs/SECURITY.md).

### Real data only

Every number, row and chart in the interface comes from a real observation
stored in MySQL or a live in-memory counter. On a fresh installation the
dashboard reads zero, the tables read *"No data available"*, and the capture
indicator is grey — that is the correct first-run appearance, not a fault.
There is no demo mode, no sample data and no seeded alerts. Synthetic fixtures
exist only inside `tests/`, and nothing in `aethra_sec/` can import them.

---

## Requirements

| Component | Version / note |
| --- | --- |
| Python | 3.10 - 3.14, with Tkinter (3.12 or 3.13 recommended) |
| MySQL or MariaDB | 8.0+ / 10.6+, reachable from the workstation |
| Nmap | 7.x — required for vulnerability assessment |
| Wireshark / TShark | 4.x — required for live capture (Npcap on Windows) |
| Snort | 2.9.x or 3.x — optional; alerts are ingested, never generated |

Python packages are pinned in [`requirements.txt`](requirements.txt):
`mysql-connector-python`, `argon2-cffi`, `python-nmap`, `pyshark`, `psutil`,
`python-dotenv`, `reportlab`, `openpyxl`, `pytest`.

---

## Quick start

Full step-by-step Windows instructions, including Npcap and the Snort service,
are in **[`docs/INSTALL_WINDOWS.md`](docs/INSTALL_WINDOWS.md)**.

**The short way** — double-click, or from a prompt:

```bat
setup.bat      :: once: virtual environment, dependencies, .env, schema, admin
run.bat        :: every time after that
```

`run.bat` passes its arguments through, so `run.bat --check` runs the
diagnostics and `run.bat --headless` starts the services without the interface.
Right-click → *Run as administrator* if you need live packet capture.

**The same steps by hand:**

```bat
:: 1. Create the environment
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

:: 2. Configure — copy the template and edit the values
copy .env.example .env
notepad .env

:: 3. Create the schema and seed roles, settings and mitigation guidance
python scripts\init_db.py
::    (or apply the SQL directly:  mysql -u root -p < sql\aethra_sec_schema.sql)

:: 4. Create the first administrator (the password is prompted for)
python scripts\create_admin.py --username admin

:: 5. Check the installation, then start
python scripts\health_check.py
python -m aethra_sec.main
```

On Linux use `./run.sh --setup` once and `./run.sh` afterwards — the same steps
with `python3 -m venv .venv` and `sudo apt-get install python3-tk`.

### Command line

```
python -m aethra_sec.main                start the desktop console
python -m aethra_sec.main --check        run diagnostics and exit
python -m aethra_sec.main --headless     run the services without the UI
python -m aethra_sec.main --no-migrate   start without touching the schema
python -m aethra_sec.main --version

python scripts/init_db.py                create/migrate, then seed
python scripts/init_db.py --verify       report schema state and record counts
python scripts/export_schema.py          regenerate sql/aethra_sec_schema.sql
python scripts/create_admin.py           create an account (password prompted)
python scripts/health_check.py [--json]  diagnostics, exit 0 = ready
```

Exit codes for `--check` and `health_check.py`: `0` ready, `1` a check failed,
`2` the services could not start.

---

## Configuration

All deployment configuration lives in `.env`, which is **never committed**.
[`.env.example`](.env.example) documents every variable. The essentials:

| Variable | Purpose |
| --- | --- |
| `AETHRA_DB_HOST` / `_PORT` / `_NAME` / `_USER` / `_PASSWORD` | MySQL connection |
| `AETHRA_NMAP_PATH`, `AETHRA_TSHARK_PATH`, `AETHRA_SNORT_PATH` | Tool locations (blank = auto-discover) |
| `AETHRA_SNORT_TRANSPORT` | `unixsock` · `tcp` · `syslog` · `file` · `disabled` |
| `AETHRA_AUTHORIZED_NETWORKS` | CIDRs you are authorised to scan and monitor |
| `AETHRA_ALLOW_PUBLIC_TARGETS` | Opt-in for a lab that uses public addressing |
| `AETHRA_CAPTURE_INTERFACE`, `AETHRA_CAPTURE_BPF` | Capture defaults |
| `AETHRA_OTP_ENABLED` + `AETHRA_SMTP_*` | Optional email second factor |

Detection thresholds, retention periods, refresh rates and the security policy
are stored in the database and edited on the **Settings** screen; deployment
values are shown there read-only, because changing a credential from inside a
running application is not a safe operation.

---

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System, component, data-flow and event architecture; ERD; folder map; roadmap |
| [`docs/INSTALL_WINDOWS.md`](docs/INSTALL_WINDOWS.md) | Windows installation, tool setup, Npcap, first run, troubleshooting |
| [`docs/DATABASE.md`](docs/DATABASE.md) | The 31 tables, their relationships, migrations, retention and backup |
| [`sql/aethra_sec_schema.sql`](sql/aethra_sec_schema.sql) | The complete schema as one file: creates the database, all 31 tables and the reference rows |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, authentication, administrator-approved password recovery, RBAC matrix, audit chain, input validation, boundaries |
| [`docs/SNORT_INTEGRATION.md`](docs/SNORT_INTEGRATION.md) | The four alert transports, Snort configuration, alert formats, verification |
| [`docs/UI_SCREEN_MAP.md`](docs/UI_SCREEN_MAP.md) | Every screen, its permission, its controls and its empty state |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Day-to-day operation: monitoring, assessing, investigating, reporting |

---

## Tests

```bash
python -m pytest tests/ -q
```

496 tests cover input validation and the authorisation boundary, the Nmap
profile catalogue, the PyShark mapper, all four Snort parsers and the binary
`Alertpkt` decoder, the analytics rules and risk engine, password hashing,
RBAC, the administrator-approved password recovery workflow end to end,
administrator account registration, the audit hash chain, the repositories
against a real MySQL schema, the interface logic, the exported SQL schema, the
launcher scripts, the worker-to-Tk bridge that keeps the console working on
Python 3.14, the sign-out return-to-login flow, and the interface regressions
fixed after 1.0.0 - incident device roll-up, incident read state, assessment
host fields, wheel and scrollbar behaviour, and the row context menu - and
the investigation experience built on top of them: the details drawer, the
palette's record search, the dashboard's time range and the table filters.

Database-backed tests need a reachable MySQL server and skip themselves
otherwise, so the pure-logic tests run anywhere. They use their own schema
(`aethra_sec_test` by default; override with `AETHRA_TEST_DB_NAME`) and never
touch the application's data.

---

## Authorised use

AETHRA-SEC must only be operated against networks, hosts and interfaces that
the operator is explicitly authorised to monitor or assess. It performs no
exploitation, no credential attacks and no automated mitigation. All mitigation
output is advisory and requires a human decision. Intended for academic Network
Security laboratories and authorised internal LAN environments.
