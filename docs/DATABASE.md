# AETHRA-SEC database

MySQL 8.0+ / MariaDB 10.6+, InnoDB, `utf8mb4_unicode_ci`. Thirty-one tables, created
in dependency order by `aethra_sec/database/schema.py` and applied by
`aethra_sec/database/migrations.py`.

**The whole schema as one file:** [`sql/aethra_sec_schema.sql`](../sql/aethra_sec_schema.sql)
creates the database, all 31 tables and the reference rows a working
installation needs. Apply it directly if you would rather not run the
application to build the schema:

```bash
mysql -u root -p < sql/aethra_sec_schema.sql
```

It is generated from the definitions above by `scripts/export_schema.py`, and a
test fails if the file and the code ever disagree — so the SQL always describes
exactly what the application builds. Re-run the exporter and commit the result
after any schema change.

Two rules govern everything in this document:

1. **Only real observations are stored.** Seeding creates roles, permissions,
   settings and the mitigation knowledge base. It creates no users, hosts,
   scans, alerts, anomalies or incidents. Those tables fill only when Nmap,
   TShark or Snort produce something (§1).
2. **Every statement is parameterised.** No SQL is built by concatenating
   operator input. Identifiers used in `ORDER BY`/`WHERE` come from a
   per-query whitelist in `repositories/base.py`; anything else raises
   `SqlIdentifierError` before the statement is built (§98).

---

## 1. Table groups

### Schema management

| Table | Purpose |
| --- | --- |
| `schema_migrations` | `version`, `name`, `applied_at` — one row per applied migration |

### Identity and access

| Table | Purpose |
| --- | --- |
| `roles` | `ADMIN`, `USER` |
| `permissions` | The 27 permission codes with name, description and category |
| `role_permissions` | Role → permission grants |
| `users` | Accounts. Holds `password_hash` + `password_algorithm`; **never a password** |
| `login_attempts` | Every attempt, successful or not, with reason and host context |
| `sessions` | Issued sessions by **token fingerprint** — the token itself is never stored |
| `password_reset_requests` | The administrator-reviewed recovery queue: who asked, from where, who decided, and the **digest** of the one-time code — never the code |
| `audit_logs` | Append-only hash-chained audit trail (`previous_hash`, `record_hash`) |

### Inventory

| Table | Purpose |
| --- | --- |
| `hosts` | Discovered hosts: addresses, OS, status, risk level, discovery source, first/last seen |
| `host_observations` | Per-interface packet/byte counters per host, from live capture |
| `trusted_hosts` | Addresses an administrator has marked expected, with the reason |

### Assessment (Nmap)

| Table | Purpose |
| --- | --- |
| `scans` | One row per assessment: target, profile, port spec, timing, the exact argument list, status, timings, counts, `nmap_version`, `command_line` |
| `scan_hosts` | Per-host result within a scan |
| `ports` | Per-port result: state, service, product, version, CPE, reason |
| `scan_findings` | Derived findings with `observation`, `concern`, `risk_level`, `risk_rationale`, `evidence`, `verification_required` |
| `vuln_knowledge` | Optional local knowledge base matched against observed services. Empty by default — AETHRA-SEC does not ship a vulnerability database |

### Monitoring (PyShark / TShark)

| Table | Purpose |
| --- | --- |
| `traffic_records` | Packet **metadata** (no payloads): time, interface, endpoints, ports, protocol, length, TTL, TCP flags, MACs |
| `traffic_aggregates` | Fixed-interval rollups: packet/byte counts per protocol, unique endpoints, rates, `dropped_packets` |

### Detection and response

| Table | Purpose |
| --- | --- |
| `snort_alerts` | Real Snort alerts: `alert_time` vs `received_at` with `time_source`, GID/SID/rev, message, classification, priority, endpoints, `transport`, `raw_alert`, `dedup_key`, `duplicate_count` |
| `traffic_anomalies` | Threshold-rule detections: `observed_value`, `threshold_value`, `window_seconds`, `evidence` |
| `incidents` | Correlated incidents: `reference`, category, severity, `confidence`, `evidence_sources`, per-source counts, `risk_score`, `risk_rationale`, `detection_latency_seconds`, `evaluation` |
| `incident_events` | Chronological evidence timeline pointing back at the source row |
| `incident_notes` | Analyst notes |
| `mitigation_recommendations` | Guidance entries. 15 built-ins are seeded (`is_builtin = 1`); administrators may add their own |
| `threat_mitigation_mapping` | Category (+ optional service/severity conditions) → recommendation |

### Operations

| Table | Purpose |
| --- | --- |
| `reports` | Generated reports: type, period, scope, `record_counts` per section, export path and size |
| `system_settings` | The 40 tunable settings with type, category, description and who last changed each |
| `integration_status` | Last known state of each subsystem, with `last_success` and `last_error` |
| `notifications` | In-application notifications raised by real events |
| `app_errors` | Recorded subsystem errors surfaced on the Logs screen |

---

## 2. Relationships that matter

```
users ──< sessions, login_attempts, audit_logs, notifications
      └─< password_reset_requests (user_id = who asked, reviewed_by = who decided)
roles ──< role_permissions >── permissions
      └─< users

scans ──< scan_hosts ──< ports
      └─< scan_findings >── hosts

hosts ──< host_observations
      └─< trusted_hosts (by address)

snort_alerts ──┐
traffic_anomalies ──┼──> incidents ──< incident_events
scan_findings ──┘                  └─< incident_notes
                                   └── mitigation_recommendations

mitigation_recommendations >── threat_mitigation_mapping ── (threat category)
```

Evidence rows carry `incident_id`, so an incident can always be traced back to
the exact alerts, anomalies and findings that produced it, and each of those
rows keeps the raw evidence it came from.

`incidents` and `mitigation_recommendations` are created **before**
`snort_alerts` and `traffic_anomalies` because those tables carry foreign keys
into them; `CREATE_TABLE_STATEMENTS` encodes that order, and `_drop_all` in the
test fixtures reverses it.

---

## 3. Migrations

```bat
python scripts\init_db.py            create, migrate and seed
python scripts\init_db.py --verify   report state without changing anything
python scripts\init_db.py --no-seed  migrate only

python scripts\export_schema.py      regenerate sql\aethra_sec_schema.sql
```

Either path produces the same database. Applying the SQL file gives a schema
identical to the one the application builds — same columns, indexes and foreign
keys — and records the migration version, so the application then starts against
it without re-applying anything.

* Each migration has an integer version and is recorded in
  `schema_migrations`; applying them twice is a no-op.
* `verify_schema()` reports the current version and any missing tables; the
  System Health screen shows the same result.
* The application migrates on start unless launched with `--no-migrate`.
* `LATEST_VERSION` in `migrations.py` is the target; `current_version(db)`
  is what the database actually has.

| Version | Name | What it adds |
| --- | --- | --- |
| 1 | `initial_schema` | Every table in `CREATE_TABLE_STATEMENTS` |
| 2 | `password_recovery_requests` | `password_reset_requests`, the administrator-reviewed recovery queue |
| 3 | `incident_read_state` | `incidents.viewed_at` / `viewed_by`, so the sidebar counter can report unread incidents |
| 4 | `hostname_lookup_state` | `hosts.hostname_checked_at`, which separates "no DNS record" from "nobody has looked yet" |
| 5 | `os_detail_columns` | `os_version` and `os_cpe` on `hosts` and `scan_hosts`, so a fingerprint's build and its CPE are kept rather than discarded |

Migration 2 is a plain `CREATE TABLE IF NOT EXISTS`, so it is a no-op on a
database created after it was written and adds only the one table to an
installation created before it. Migrations 3, 4 and 5 add columns and check
`information_schema` first, so they are equally safe to re-run. No account or
evidence data is touched by any of them: migrations 4 and 5 leave existing
rows at `NULL` and `''` respectively, which is the truthful starting state —
nothing was ever recorded in those columns for those hosts.

The account needs `CREATE`, `ALTER`, `INDEX` and `REFERENCES` while migrations
run. In steady state `SELECT, INSERT, UPDATE, DELETE` is enough — see
[`INSTALL_WINDOWS.md`](INSTALL_WINDOWS.md) §2.

---

## 4. Seeded data

`seed_all()` writes, idempotently:

| Content | Rows |
| --- | --- |
| Roles | 2 (`ADMIN`, `USER`) |
| Permissions and their role grants | 27 |
| System settings | 43 |
| Mitigation recommendations | 15 built-in entries |

Nothing else. A freshly seeded database has zero users, zero hosts, zero scans,
zero alerts, zero anomalies and zero incidents — `init_db.py` prints those
counts so you can see it, and a test asserts it
(`test_no_security_records_are_seeded`).

---

## 5. Retention

Retention is enforced by `RetentionService`, run on a schedule by the
application. Every period is a setting on the Settings screen; `0` means
"keep indefinitely".

| Setting | Default |
| --- | --- |
| `retention.traffic_records_hours` | 24 |
| `retention.traffic_aggregates_days` | 30 |
| `retention.snort_alerts_days` | 90 |
| `retention.audit_logs_days` | 365 |
| `retention.scan_history_days` | 365 |
| `retention.prune_interval_minutes` | 60 |

Packet metadata is the highest-volume table by far, which is why its default is
hours rather than days. Two capture settings bound the write rate directly:
`capture.max_packet_rows_per_minute` (default 6000) and
`capture.persist_packet_metadata` (set it false to keep aggregates only).

Pruning the audit trail removes the oldest records; the hash chain is verified
from the oldest **retained** record onward, so a legitimate prune does not read
as tampering.

---

## 6. Backup and restore

**From the application.** *Settings → Database backup* takes a backup, saves a
copy anywhere you choose, and can run one automatically on an interval you set
(off by default). It runs the same `mysqldump` shown below, keeps a configurable
number of files, and audits every backup, copy and deletion. The countdown for
the automatic run is measured from the newest backup on disk, so a restart does
not delay it. See `docs/UI_SCREEN_MAP.md` for the full description.

**By hand**, or to restore:

```bat
mysqldump -u aethra_app -p --single-transaction --routines aethra_sec > aethra_sec_backup.sql
mysql -u aethra_app -p aethra_sec < aethra_sec_backup.sql
```

`--single-transaction` keeps InnoDB consistent without locking out a running
capture. Back up before every upgrade. The dump contains password hashes and
the audit trail — protect it exactly as you would the live database. AETHRA-SEC
never restores a backup for you: bringing a database back is a decision with
consequences an operator should be making deliberately, at the command line.

After a restore, run `python scripts\health_check.py` and verify the audit
chain from the **Logs & Audit** screen (*Verify integrity*). A restore from an
older backup will report the records that are missing rather than pretending
the chain is intact.

---

## 7. Querying safely from outside the application

Read-only ad-hoc queries are fine — the schema is plain SQL. Two cautions:

* Never write to `audit_logs` by hand. Every row's `record_hash` covers the
  previous row's hash; an inserted, edited or deleted row makes verification
  fail from that point on, which is exactly what it is designed to do.
* Do not change `password_hash` directly. Use the User Management screen or
  `scripts/create_admin.py`, so the algorithm marker stays consistent with the
  stored hash and the change is audited.
