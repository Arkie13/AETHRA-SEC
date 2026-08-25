# AETHRA-SEC — System Architecture

**AETHRA-SEC: A Unified System for Automated Penetration Testing with Real-Time
Network Traffic Analysis and Immediate Threat Mitigation Recommender**

Version 1.0 · Windows desktop application · Python 3.10+ · Tkinter/ttk · MySQL

---

## 0. Governing principle — real data only

Every number, row, chart point and status light in AETHRA-SEC originates from one
of exactly four sources:

| Source | Produced by | Stored in |
|---|---|---|
| `NMAP` | a real `nmap` process invoked through `python-nmap` | `scans`, `scan_hosts`, `ports`, `scan_findings` |
| `PYSHARK` | real packets decoded by TShark/Wireshark through PyShark | `traffic_records`, `traffic_aggregates`, `hosts`, `host_observations` |
| `SNORT` | real Snort alerts received over the configured alert transport | `snort_alerts` |
| `CORRELATION` | deterministic rules applied to the three sources above | `traffic_anomalies`, `incidents`, `incident_events` |

There is **no code path anywhere in `aethra_sec/` that synthesises a packet, an
alert, a host, a vulnerability, an incident or a metric.** When a data set is
empty, the UI renders an explicit empty state ("No data available", "Waiting for
live network data…", "Snort unavailable") instead of filler.

Synthetic fixtures exist **only** under `tests/` and are never importable by the
running application.

---

## 1. Complete system architecture

```
                                  ┌────────────────────────┐
                                  │      OPERATOR (user)   │
                                  └───────────┬────────────┘
                                              │ credentials
                                  ┌───────────▼────────────┐
                                  │  AUTHENTICATION LAYER  │
                                  │  Argon2id · sessions   │
                                  │  lockout · optional OTP│
                                  └───────────┬────────────┘
                                              │ Session(user, role, permissions)
        ┌─────────────────────────────────────▼──────────────────────────────────┐
        │                    AETHRA-SEC DESKTOP APPLICATION (Tkinter)            │
        │  ┌──────────────┐   ┌──────────────────────────────────────────────┐   │
        │  │ Navigation   │   │  Screens: Dashboard · Network Monitor ·       │   │
        │  │ (RBAC-aware) │   │  Vulnerability Assessment · Hosts · Alerts ·  │   │
        │  └──────────────┘   │  Incidents · Mitigation · Reports · Logs ·    │   │
        │                     │  Users · System Health · Settings · Help      │   │
        │                     └──────────────────────────────────────────────┘   │
        └───────────────────────────────┬────────────────────────────────────────┘
                                        │ EventBus (thread-safe pub/sub)
                                        │ ServiceRegistry (RBAC-enforcing façade)
        ┌───────────────────────────────▼────────────────────────────────────────┐
        │                          SYSTEM SERVICES LAYER                          │
        │                                                                         │
        │  NmapService        PacketCaptureService       SnortService             │
        │  ├ target policy    ├ interface enumeration    ├ unixsock (Alertpkt)    │
        │  ├ profile builder  ├ bounded queue + drops    ├ tcp / syslog / file    │
        │  ├ worker thread    ├ decoder thread           ├ reader thread          │
        │  └ finding builder  └ batched persistence      └ alert parser           │
        │        │                      │                        │                │
        │        │                      ▼                        │                │
        │        │            TrafficAnalyzer (in-memory         │                │
        │        │            rolling windows, top-N)            │                │
        │        │                      │                        │                │
        │        │                      ▼                        │                │
        │        │            AnomalyRuleEngine (deterministic,  │                │
        │        │            configurable thresholds)           │                │
        │        │                      │                        │                │
        │        └──────────────┬───────┴────────────────────────┘                │
        │                       ▼                                                  │
        │              CorrelationService  ── RiskEngine ── MitigationService       │
        │              (dedup, aggregation, incident lifecycle)                     │
        │                       │                                                  │
        │   ReportService · NotificationService · HealthService · RetentionService  │
        └───────────────────────┬─────────────────────────────────────────────────┘
                                │ repository pattern, parameterised SQL
                    ┌───────────▼────────────┐
                    │  MySQL  (aethra_sec)   │  ← audit hash chain, FKs, indexes
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │  Dashboard · Reports   │
                    └────────────────────────┘
```

---

## 2. Component architecture

### 2.1 Layers

| Layer | Package | Responsibility | May depend on |
|---|---|---|---|
| Presentation | `aethra_sec.ui` | Tkinter screens, widgets, theme | core, models, service façade |
| Application core | `aethra_sec.core` | event bus, session, permissions, service registry, scheduler | config, utils |
| Services | `aethra_sec.services` | orchestration, threading, lifecycle, RBAC checks | integrations, analytics, database, security |
| Integrations | `aethra_sec.integrations` | thin, testable adapters to nmap / pyshark / snort | utils, models |
| Analytics | `aethra_sec.analytics` | pure functions + in-memory state; no I/O | models, config |
| Security | `aethra_sec.security` | hashing, authn, RBAC, audit, integrity | database, utils |
| Data | `aethra_sec.database` | connection pool, schema, migrations, repositories | models, config |
| Models | `aethra_sec.models` | frozen/plain dataclasses shared by every layer | stdlib only |
| Utilities | `aethra_sec.utils` | logging, validation, formatting, time, net | stdlib only |

Dependency direction is strictly downward. `analytics` and `integrations` never
import `ui`; `models` and `utils` import nothing from the project.

### 2.2 Threading model

| Thread | Owner | Work | Hand-off |
|---|---|---|---|
| Tk main loop | `ui.app` | rendering only | consumes `EventBus` deliveries via `root.after()` drain |
| `capture-reader` | `PacketCaptureService` | `pyshark.LiveCapture.sniff_continuously()` | bounded `queue.Queue` (drop-newest + counter) |
| `capture-worker` | `PacketCaptureService` | decode → analyzer → anomaly rules → batch insert | EventBus + repositories |
| `snort-reader` | `SnortService` | blocking socket/file read | parsed alert → EventBus + repository |
| `nmap-worker` | `NmapService` | one blocking `nmap` run per scan | EventBus + repositories |
| `scheduler` | `core.scheduler` | periodic health probes, aggregate flush, retention | services |

No blocking work ever runs on the Tk thread; no Tk widget is ever touched from a
worker thread. The bridge is `EventBus.subscribe()` + a thread-safe queue drained
by `root.after()` (see §10).

---

## 3. Data flow

```
   physical/virtual NIC
          │
          ▼
   TShark (Wireshark)  ──► PyShark ──► PacketMapper ──► CapturedPacket dataclass
                                                         │
                    ┌────────────────────────────────────┼───────────────────────┐
                    ▼                                    ▼                       ▼
            TrafficAnalyzer                    packet metadata batch     host observation
        (rolling 1s/60s windows,               (retention-capped         (first_seen/last_seen,
         top talkers, protocol mix)             INSERT ... batched)       protocols, MAC)
                    │                                    │                       │
                    ▼                                    ▼                       ▼
            AnomalyRuleEngine                    traffic_records          hosts / host_observations
      (ICMP/UDP/SYN/HTTP rate, port scan,               │
       host sweep — configurable thresholds)            │
                    │                                   ▼
                    │                          traffic_aggregates (flushed every N s)
                    ▼
            traffic_anomalies ─────────┐
                                       │
   Snort ──► transport ──► parser ──►  ├──► CorrelationService ──► incidents
            (unixsock/tcp/             │      · key = (src, dst, category)   │
             syslog/file)              │      · dedup + aggregation window   │
                                       │      · evidence linkage              ▼
   Nmap  ──► runner ──► parser ──►  ───┘      · RiskEngine severity      incident_events
            scan_findings                     · confidence by #sources         │
                                                                                ▼
                                                                     MitigationService
                                                                   (threat → recommendation)
                                                                                │
                                                                                ▼
                                                                      MySQL ──► Dashboard
                                                                            ──► Reports
```

**Traceability.** Every finding, anomaly, alert and incident event carries a
`source` column (`NMAP`, `PYSHARK`, `SNORT`, `CORRELATION`) and every incident
records exactly which evidence rows produced it. An incident built from a single
source is labelled as such — the UI never claims Nmap confirmed something Nmap
did not observe.

---

## 4. Database schema (ERD)

```
 roles ──< role_permissions >── permissions
   │
   └──< users >──┬──< sessions
                 ├──< login_attempts
                 ├──< password_reset_requests   (admin-approved recovery)
                 ├──< audit_logs            (hash-chained)
                 ├──< scans >──< scan_hosts >──< ports
                 │                  │
                 │                  └──< scan_findings
                 ├──< reports
                 ├──< notifications
                 └──< incidents (assigned_user_id)

 hosts ──┬──< host_observations
         ├──< scan_hosts
         ├──< snort_alerts        (src_host_id / dst_host_id)
         ├──< traffic_anomalies
         └──< incidents           (affected_host_id)

 traffic_records                 (per-packet metadata, retention-capped)
 traffic_aggregates              (per-interval rollups, long retention)

 snort_alerts ─────────┐
 traffic_anomalies ────┼──< incident_events >── incidents
 scan_findings ────────┘                            │
                                                    ├──< incident_notes
                                                    └──> mitigation_recommendations
                                                          ▲
                       threat_mitigation_mapping ─────────┘

 system_settings · integration_status · trusted_hosts · vuln_knowledge
 app_errors · schema_migrations · alert_classifications
```

Full DDL and column-level documentation: [`DATABASE.md`](DATABASE.md).

Design rules applied:

* every table has a surrogate `BIGINT UNSIGNED AUTO_INCREMENT` primary key;
* every security record carries `created_at`, and lifecycle records also carry
  `updated_at` / `first_seen` / `last_seen` / `resolved_at`;
* foreign keys with explicit `ON DELETE` behaviour (`RESTRICT` for evidence,
  `CASCADE` only for owned child rows);
* indexes on every field the UI filters or sorts by (timestamps, `src_ip`,
  `dst_ip`, `severity`, `status`, `signature_id`, `host_id`, `scan_id`,
  `incident_id`, `user_id`);
* unique constraints where identity is natural (`users.username`,
  `hosts.ip_address`, `permissions.code`, `(scan_host_id, protocol, port)`);
* `DATETIME(6)` stored in UTC everywhere, converted to local time only for
  display.

---

## 5. Folder structure

```
AETHRA-SECNEW/
├── aethra_sec/
│   ├── main.py                  entry point, lifecycle, graceful shutdown
│   ├── version.py
│   ├── config/                  settings.py · environment.py · defaults.py
│   ├── core/                    application.py · event_bus.py · events.py
│   │                            session.py · permissions.py · errors.py
│   │                            scheduler.py
│   ├── database/                connection.py · schema.py · migrations.py
│   │                            seed.py · repositories/*.py
│   ├── security/                password.py · authentication.py · rbac.py
│   │                            audit.py · integrity.py · otp.py
│   ├── models/                  user · host · scan · alert · traffic
│   │                            threat · incident · mitigation · system
│   ├── integrations/
│   │   ├── nmap/                runner.py · parser.py · profiles.py
│   │   ├── pyshark_capture/     interfaces.py · live_capture.py · mapper.py
│   │   └── snort/               transports.py · alertpkt.py · parser.py
│   ├── analytics/               traffic_analyzer.py · anomaly_rules.py
│   │                            risk_engine.py
│   ├── services/                packet_capture · nmap_service · snort_service
│   │                            correlation · mitigation · report · health
│   │                            notification · retention · user_service
│   │                            recovery_service · dashboard · host · log
│   │                            settings
│   ├── reports/                 builder.py · writers.py (CSV/Excel/PDF)
│   ├── ui/                      app.py · base.py · theme.py · login.py
│   │                            recovery.py · dispatch.py · state.py
│   │   ├── screens/             dashboard · traffic · vulnerabilities · hosts
│   │   │                        alerts · incidents · mitigation · reports
│   │   │                        logs · users · health · settings · about
│   │   └── widgets/             cards.py · tables.py · charts.py · dialogs.py
│   └── utils/                   logging.py · validation.py · formatting.py
│                                timeutil.py · net.py
├── run.bat / setup.bat          Windows launcher and first-run setup
├── run.sh                       Linux/macOS launcher (--setup does the same)
├── sql/                         aethra_sec_schema.sql (generated; whole schema)
├── scripts/                     init_db.py · create_admin.py · health_check.py
│                                export_schema.py
├── docs/                        ARCHITECTURE.md · DATABASE.md · SECURITY.md
│                                INSTALL_WINDOWS.md · SNORT_INTEGRATION.md
│                                UI_SCREEN_MAP.md · USER_GUIDE.md
└── tests/                       pytest suite (synthetic fixtures live ONLY here)
```

---

## 6. Module / class architecture

### Core
* `EventBus` — thread-safe publish/subscribe with per-subscriber bounded queues.
  Publishing never blocks a producer; a slow subscriber drops its own oldest
  events and increments a visible drop counter.
* `Session` / `SessionManager` — issues opaque tokens, tracks expiry and last
  activity, supports administrative invalidation ("force logout").
* `PermissionSet` / `Permission` — string-coded permissions resolved from the
  database at login and cached on the session.
* `ServiceRegistry` — single wiring point (dependency injection); every service
  is constructed once with its collaborators and shared with the UI.
* `PeriodicScheduler` — named jobs on fixed intervals, isolated failures.

### Integrations
* `nmap.ScanProfile` — a *whitelist* of argument fragments. User input never
  reaches the command line as free text; a profile plus a validated port range
  and a `-T<0..5>` timing token are the only inputs.
* `nmap.NmapResultParser` — converts `python-nmap`'s dict into
  `ScanHostResult` / `PortResult` / `ScanFinding` dataclasses.
* `pyshark_capture.PacketMapper` — defensive field extraction; every field is
  optional and missing layers never raise.
* `snort.AlertTransport` — abstract base; `UnixSocketAlertTransport`,
  `TcpAlertTransport`, `SyslogAlertTransport`, `AlertFileTransport`.
* `snort.AlertPktDecoder` — decodes Snort's binary `Alertpkt` datagram
  (Alert Socket IPC) by anchoring on the trailing `Event` struct, which makes it
  independent of the compiled `SNAPLEN`.
* `snort.parse_alert_line` — auto-detects `alert_fast`, `alert_csv`,
  `alert_json` (Snort 3) and syslog-wrapped variants.

### Analytics (pure, unit-tested, no I/O)
* `TrafficAnalyzer` — bounded rolling windows → pps, bps, protocol mix,
  top-N talkers/ports, per-host activity.
* `AnomalyRuleEngine` — six deterministic rules, thresholds injected from
  configuration, each emitting evidence counts and a human-readable observation.
* `RiskEngine` — transparent additive scoring; returns both a severity and the
  list of factors that produced it.

---

## 7. UI screen map

```
LoginScreen ──(authenticated)──► MainWindow
                                   ├── Dashboard             (all roles)
                                   ├── Network Monitoring    (MONITOR_VIEW)
                                   ├── Vulnerability Assess. (SCAN_RUN / SCAN_VIEW)
                                   ├── Hosts ──► Host Detail (HOST_VIEW)
                                   ├── Alerts ──► Alert Detail(ALERT_VIEW)
                                   ├── Incidents ──► Investigation (INCIDENT_VIEW)
                                   ├── Mitigation            (MITIGATION_VIEW / _MANAGE)
                                   ├── Reports               (REPORT_GENERATE)
                                   ├── Logs & Audit          (LOG_VIEW, admin)
                                   ├── Users                 (USER_MANAGE, admin)
                                   ├── System Health         (all roles, detail gated)
                                   ├── Settings              (SETTINGS_MANAGE, admin)
                                   ├── Help / About          (all roles)
                                   └── Logout
```

Detailed widget inventory: [`UI_SCREEN_MAP.md`](UI_SCREEN_MAP.md).

---

## 8. Integration architecture

| Tool | Mechanism | Availability probe | Failure surface |
|---|---|---|---|
| Nmap | `python-nmap` → `nmap` subprocess, argv list (never a shell string) | resolve executable + `nmap --version` | "Nmap is not available. Install/configure Nmap before running vulnerability assessments." |
| Wireshark/TShark | PyShark spawns `tshark`; explicit `tshark_path` honoured | resolve executable + `tshark -v` | actual capture error text is shown (e.g. permission denied / Npcap missing) |
| Snort | Alert Socket IPC (`alert_unixsock`) primary; TCP, UDP-syslog, and alert-file tailing as configurable alternatives | transport bind/connect + last-alert timestamp | "Snort unavailable" + the configured transport and the exact reason |
| MySQL | `mysql-connector-python` pooled connections | `SELECT 1` ping + schema version check | "DATABASE OFFLINE" banner; services degrade, application keeps running |

The Snort transport choice matters operationally: `alert_unixsock` is the
mechanism named by the system design and is used on Linux/WSL sensors; Windows
Snort builds do not implement Unix domain sockets, so a Windows sensor uses the
file or syslog transport. All four carry **real** Snort output — none of them
generate alerts. See [`SNORT_INTEGRATION.md`](SNORT_INTEGRATION.md).

---

## 9. Security architecture

Defence in depth, mapped to STRIDE:

| Threat | Control |
|---|---|
| **S**poofing | Argon2id password hashing, per-user salts, generic login errors, failed-attempt lockout, opaque session tokens with expiry, optional email OTP |
| **T**ampering | 100 % parameterised SQL, least-privilege DB account, append-only audit log with SHA-256 hash chaining, admin-only integrity verification, no destructive delete of evidence |
| **R**epudiation | Every security-relevant action written to `audit_logs` with user, action, target, result, timestamp and host context |
| **I**nformation disclosure | RBAC enforced in the service layer (not only the UI), credentials never logged, secrets read from environment, error messages sanitised for end users |
| **D**enial of service | Bounded queues, backpressure counters, batched writes, retention limits, DoS-pattern detection that **alerts only** — never auto-blocks |
| **E**levation of privilege | Permission checks inside every mutating service method; UI hiding is cosmetic only; role changes audited |

Details, including the log-integrity algorithm: [`SECURITY.md`](SECURITY.md).

**Authorisation boundary.** `NmapService` refuses any target outside the
configured authorised networks (RFC1918 + loopback by default), refuses
shell metacharacters, and builds argv from whitelisted fragments. There is no
exploitation capability, no credential attack capability, and no automated
mitigation action anywhere in the codebase — mitigation is recommendation-only.

---

## 10. Real-time event architecture

`aethra_sec.core.events` defines the event vocabulary:

```
PACKET_BATCH_PROCESSED   TRAFFIC_STATS_UPDATED   TRAFFIC_ANOMALY_DETECTED
CAPTURE_STARTED          CAPTURE_STOPPED         CAPTURE_ERROR
SNORT_ALERT_RECEIVED     SNORT_STATUS_CHANGED
NMAP_SCAN_STARTED        NMAP_SCAN_PROGRESS      NMAP_SCAN_COMPLETED   NMAP_SCAN_FAILED
INCIDENT_CREATED         INCIDENT_UPDATED        MITIGATION_GENERATED
DATABASE_STATUS_CHANGED  SERVICE_STATUS_CHANGED  NOTIFICATION_RAISED
REPORT_GENERATED         SYSTEM_ERROR
```

Producers publish from worker threads. The UI subscribes once per screen; the
`EventBus` places the payload on that subscriber's bounded queue, and
`MainWindow` drains all queues on a `root.after(refresh_ms)` tick, so widget
mutation always happens on the Tk thread. Screens therefore update from live
events rather than polling the whole database every second; only aggregate
counters that cannot be derived incrementally are re-queried, and those use
narrow indexed queries.

---

## 11. Implementation roadmap (delivered in this order)

| Phase | Content | Status |
|---|---|---|
| 1 | Project architecture & scaffolding | ✅ |
| 2 | Configuration, utilities, core (event bus, RBAC vocabulary) | ✅ |
| 3 | MySQL schema, migrations, seeds, repositories | ✅ |
| 4 | Authentication, sessions, RBAC, audit hash chain | ✅ |
| 5 | Nmap integration + assessment service | ✅ |
| 6 | PyShark live capture pipeline | ✅ |
| 7 | Snort Alert Socket IPC + alternative transports | ✅ |
| 8 | Traffic analytics + deterministic anomaly rules | ✅ |
| 9 | Threat correlation, risk engine, incident lifecycle | ✅ |
| 10 | Mitigation recommendation engine + knowledge base | ✅ |
| 11 | Dashboard and live widgets | ✅ |
| 12 | Alerts, incidents, hosts, investigation views | ✅ |
| 13 | Reporting (CSV / Excel / PDF) | ✅ |
| 14 | Security hardening, audit, log integrity verification | ✅ |
| 15 | Performance safeguards (bounded queues, batching, retention) | ✅ |
| 16 | Test suite | ✅ |
| 17 | Packaging, Windows installation, first-run experience | ✅ |
