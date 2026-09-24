# AETHRA-SEC — Initial Audit (Phase 1)

Written before any change was made to the application. Nothing in
`aethra_sec/` was modified to produce this document.

- **Date:** 2026-09-16
- **Audited tree:** `C:\xampp\htdocs\AETHRA-SECNEW`
- **Application:** AETHRA-SEC 1.0.0 — Tkinter/ttk SOC desktop console

---

## 1. Project structure

| Package | Files | Lines | Role |
|---|---:|---:|---|
| `aethra_sec/ui` | 42 | 24,986 | Tkinter/ttk screens, widgets, theme, dispatch |
| `aethra_sec/services` | 22 | 11,138 | Capture, Snort, Nmap, assessment queue, reports |
| `aethra_sec/database` | 18 | 8,982 | Connection pool, migrations, repositories |
| `aethra_sec/integrations` | 20 | 7,497 | PyShark, Snort, Nmap adapters/parsers |
| `aethra_sec/analytics` | 9 | 4,112 | Anomaly rules, scope, traffic classes |
| `aethra_sec/models` | 15 | 3,852 | Domain models and enums |
| `aethra_sec/setup` | 8 | 3,693 | First-run wizard, interface discovery |
| `aethra_sec/core` | 9 | 2,212 | Application context, sessions, event bus |
| `aethra_sec/security` | 7 | 1,785 | Argon2 auth, RBAC, audit |
| `aethra_sec/config` | 5 | 1,434 | Settings and defaults |
| `aethra_sec/reports` | 3 | 1,281 | PDF/XLSX builders |
| `aethra_sec/utils` | 6 | 1,172 | Net, time, logging helpers |
| *(top level)* | 5 | 626 | `main.py`, `resources.py`, … |

**Total: 169 modules, 72,770 lines, 362 classes, 2,713 functions/methods.**

## 2. Entry point and startup sequence

- Launcher: `run.bat` → `python -m aethra_sec.main`
- Flags: `--check` (diagnostics and exit), `--headless`, `--no-migrate`
- Sequence: `main()` → single-instance guard (`core/single_instance.py`,
  Windows named mutex `Local\AETHRA-SEC.console`) → `ApplicationContext.start()`
  → migrations → services → Tk UI

## 3. Subsystem map (diagnostic targets)

| Feature | Primary modules |
|---|---|
| Authentication / RBAC | `security/authentication.py`, `security/rbac.py`, `security/password.py` |
| Database | `database/connection.py`, `database/migrations.py`, `database/repositories/*` |
| Dashboard | `ui/screens/dashboard.py`, `services/dashboard_service.py` |
| Live Monitoring | `ui/screens/traffic.py`, `services/packet_capture.py`, `integrations/pyshark_capture/*` |
| Hosts | `ui/screens/hosts.py`, `services/host_service.py`, `database/repositories/hosts.py` |
| Vulnerability Assessment | `ui/screens/vulnerabilities.py`, `services/nmap_service.py`, `services/assessment_queue.py`, `integrations/nmap/*` |
| IDS Alerts | `ui/screens/alerts.py`, `services/snort_service.py`, `integrations/snort/parser.py` |
| Incidents | `ui/screens/incidents.py`, `services/correlation_service.py` |
| Mitigation | `ui/screens/mitigation.py`, `services/mitigation_service.py` |
| Reports | `ui/screens/reports.py`, `services/report_service.py`, `reports/builder.py` |
| Logs / Audit | `ui/screens/logs.py`, `security/audit.py`, `services/log_service.py` |
| Users | `ui/screens/users.py`, `services/user_service.py` |
| Settings | `ui/screens/settings.py`, `services/settings_service.py`, `config/defaults.py` |
| Notifications | `services/notification_service.py`, `services/audio_alert_service.py` |

**Background workers:** scheduler in `core/application.py` (host-liveness sweep,
badge refresh, retention, backup), assessment queue worker, Snort ingest loop,
capture worker thread, `ui/dispatch.py` worker→Tk bridge.

**Subprocesses:** TShark (PyShark), Snort (in WSL), Nmap (`Popen` + Windows Job
Object adoption).

## 4. Existing tests

- `tests/` — **66 files**, currently **2,030 passing, 0 failing, 0 skipped**
- MySQL-backed tests use an isolated schema (`aethra_sec_test`) and skip when no
  server is reachable
- `tests/conftest.py` provides a session-scoped `tk_root` fixture

## 5. Git status

**There is no Git repository** (`.git` is absent). This is decisive for Phase 2:
the baseline cannot be a commit, so it must be a filesystem SHA-256 manifest
plus a read-only source copy.

## 6. Dependencies (`requirements.txt`)

`mysql-connector-python`, `argon2-cffi`, `python-nmap`, `pyshark`, `psutil`,
`python-dotenv`, `reportlab`, `openpyxl`, `pytest`. All installed in `.venv`.

## 7. TODO / FIXME / placeholder scan

- `TODO` / `FIXME` / `XXX` / `HACK` occurrences: **0**
- Functions whose body is only `pass`: **0**
- No demo/seed security data: `tests/test_database.py::test_no_security_records_are_seeded`
  already asserts `hosts`, `scans`, `scan_findings`, `snort_alerts`,
  `traffic_anomalies`, `incidents`, `traffic_records`, `traffic_aggregates`,
  `notifications` are all empty on a fresh install.

The tree is therefore a sound baseline: there is no pre-existing stub that a
"missing implementation" detector would flag as a false positive.

## 8. Existing diagnostic mechanisms

- `python -m aethra_sec.main --check` → `HealthService.run_diagnostics()`
  (`services/health_service.py`), printing per-check PASS/WARN/FAIL
- `scripts/health_check.py`, `scripts/check_snort_config.py`
- `database/migrations.py::verify_schema()`

The skills-test system reuses `--check` for the environment stage rather than
duplicating it.

## 9. Secrets — excluded from the baseline

`.env` (real database credentials) exists at the repository root. The baseline
**must not** contain it. Exclusions applied in Phase 2: `.env`, `.venv`,
`__pycache__`, `logs/`, `captures/`, `reports_output/`, `build/`, `New folder`,
and any `*.key`/`*.pem`.
