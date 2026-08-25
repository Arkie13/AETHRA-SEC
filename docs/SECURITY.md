# AETHRA-SEC security architecture

AETHRA-SEC is a security tool, so its own security posture is part of the
product. This document states what it protects, how, and — just as important —
what it deliberately refuses to do.

---

## 1. Operating boundaries

These are hard limits in the code, not policy statements.

| AETHRA-SEC will | AETHRA-SEC will never |
| --- | --- |
| Assess hosts inside the configured authorised networks | Exploit a vulnerability, or run any exploitation framework |
| Run Nmap with arguments from a fixed profile catalogue | Build a command line from operator free text |
| Capture traffic on an interface an operator selects | Attack, disable or degrade any host or service |
| Ingest alerts from a Snort sensor you run | Generate, invent or synthesise an alert |
| Recommend mitigation steps, with reasons | Apply a mitigation, block an IP, or change a firewall rule |
| Record every action in an audit trail | Guess or test credentials against anything |

Mitigation is advisory (§89, §90). Every recommendation names the action, why
it matters, how to verify it worked — and states that a human must decide.

### The authorisation boundary

`AETHRA_AUTHORIZED_NETWORKS` (CIDR list) defines what may be assessed. The
check runs on **addresses**, not names:

1. `validate_target()` parses the target into a kind (`ip`, `cidr`, `range`,
   `hostname`) and, where cheap, the concrete addresses it covers. Oversized
   networks are refused outright rather than attempted.
2. `unauthorized_addresses()` returns every address outside the boundary; the
   service refuses the scan and names each offending address.
3. `AETHRA_ALLOW_PUBLIC_TARGETS=true` is the only way to reach public
   addressing, and it is opt-in for labs that legitimately use it.

A refused scan is recorded as `SCAN_REFUSED` in the audit trail.

---

## 2. Authentication

| Property | Implementation |
| --- | --- |
| Hashing | **Argon2id** (`time_cost=3`, `memory=64 MiB`, `parallelism=2`) via `argon2-cffi` |
| Fallback | **PBKDF2-HMAC-SHA256**, 600,000 iterations, per-password salt — used only when `argon2-cffi` is unavailable |
| Storage | `password_hash` + `password_algorithm`. Plaintext passwords are never stored, logged or included in an exception message |
| Verification | Cross-algorithm: a PBKDF2 hash still verifies after Argon2id becomes available, and is **upgraded on next successful login** |
| Policy | Minimum 12 characters and at least three of: lowercase, uppercase, digits, symbols |
| Lockout | `security.max_failed_logins` (default 5) consecutive failures lock the account for `security.lockout_minutes` (default 15) |
| Sessions | Opaque tokens; only a **fingerprint** is stored in `sessions`. Idle timeout `security.session_timeout_minutes` (default 60) |
| Second factor | Optional email OTP, off unless `AETHRA_OTP_ENABLED=true` and SMTP is configured. The System Health screen always shows the true state |

**Account enumeration is not possible from the login screen.** An unknown
username and a wrong password produce the identical message. A locked account
is reported as locked — that is deliberate, because the operator needs to know
why they cannot sign in, and reaching lockout already required knowing the
account exists.

Every attempt, successful or not, is written to `login_attempts` with its
reason, and to the audit trail as `LOGIN_SUCCESS` / `LOGIN_FAILED` /
`LOGIN_LOCKED`.

### Password recovery: an administrator decides, never the system

A forgotten password is a real problem for a console that has no mail server to
trust and no help desk to call. AETHRA-SEC solves it without self-service: the
operator asks, an administrator verifies who they are, and only then can the
operator set a new password. Nothing in the chain changes a credential on its
own.

| Step | Who | What actually happens |
| --- | --- | --- |
| 1. Request | The operator, from the sign-in screen | A row is queued in `password_reset_requests` with status `PENDING`. **No credential changes.** |
| 2. Review | An administrator holding `user.reset_approve` | They confirm identity out of band — in person, by phone, by a manager |
| 3. Approve | The same administrator | A one-time code is minted, shown to them **once**, and stored only as a SHA-256 digest in `code_hash` |
| 4. Redeem | The operator, from the sign-in screen | The code is verified in constant time, the approval is consumed atomically, and the operator's own new password is hashed and stored |

The controls that make it safe:

| Control | Detail |
| --- | --- |
| No enumeration | The request form returns the identical acknowledgement for a real account, an unknown username and a malformed one. An unknown username queues nothing — it is audited instead, so a probe is visible without filling the queue |
| Rate limit | At most 3 requests per account per 24 hours, and never two open requests at once |
| Request expiry | A pending request expires after `security.reset_request_ttl_hours` (default 24) |
| Code expiry | An approval expires after `security.reset_code_ttl_minutes` (default 60), enforced both when the code is presented and by a background job |
| Single use | Consumption is a guarded `UPDATE ... WHERE status = 'APPROVED'`, so a replayed code updates no row and is refused |
| Bounded guessing | `security.reset_max_code_attempts` wrong codes (default 5) revoke the approval outright |
| Bound to one account | The digest is checked against the request for that username only |
| Password policy | The new password must pass the same policy as any other, and must differ from the current one |
| Session invalidation | Completing a recovery ends every session of that account |
| Never disclosed | The code is never written to the database in readable form, never logged, and never appears in an audit detail |
| Fully audited | `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_APPROVED`, `PASSWORD_RESET_REJECTED`, `PASSWORD_RESET_COMPLETED`, `PASSWORD_RESET_EXPIRED` — including the failures, with the reason |

The two entry points that need no session — raising a request and redeeming a
code — are the only ones in the application, and neither can change anything
without an administrator's prior decision.

An administrator can still reset a password directly from **Users → Reset
password**; that path issues a temporary password and forces a change at next
sign-in. Recovery is for the case where the *operator* asks, and it leaves the
new password known only to them.

---

## 3. Authorisation (RBAC)

27 permissions, resolved from the database at sign-in and cached on the
session. Every service method that changes state calls
`AccessControl.require()`; a refusal raises `PermissionDeniedError`, is audited
as `PERMISSION_DENIED`, and shows the operator a generic message that does not
leak the permission code. Navigation entries the session cannot use are not
rendered at all — the UI hides what the service layer would refuse anyway.

| Category | Permission | ADMIN | USER |
| --- | --- | :---: | :---: |
| dashboard | `dashboard.view` | ✔ | ✔ |
| monitoring | `monitor.view` | ✔ | ✔ |
| monitoring | `monitor.control` | ✔ | ✔ |
| monitoring | `monitor.export` | ✔ | ✔ |
| assessment | `scan.view` | ✔ | ✔ |
| assessment | `scan.run` | ✔ | ✔ |
| assessment | `scan.stop` | ✔ | ✔ |
| inventory | `host.view` | ✔ | ✔ |
| inventory | `host.manage` | ✔ | — |
| detection | `alert.view` | ✔ | ✔ |
| detection | `alert.manage` | ✔ | — |
| detection | `incident.view` | ✔ | ✔ |
| detection | `incident.manage` | ✔ | — |
| detection | `evaluation.classify` | ✔ | — |
| mitigation | `mitigation.view` | ✔ | ✔ |
| mitigation | `mitigation.manage` | ✔ | — |
| reporting | `report.generate` | ✔ | ✔ |
| reporting | `report.export` | ✔ | ✔ |
| administration | `health.view` | ✔ | ✔ |
| administration | `health.detail` | ✔ | — |
| administration | `log.view` | ✔ | — |
| administration | `log.export` | ✔ | — |
| administration | `log.verify` | ✔ | — |
| administration | `user.manage` | ✔ | — |
| administration | `user.reset_approve` | ✔ | — |
| administration | `settings.manage` | ✔ | — |
| administration | `data.maintain` | ✔ | — |

An analyst (USER) can monitor, assess, read incidents and produce reports. Only
an administrator can change thresholds, register or manage accounts, approve
password recovery, classify detections, read or verify the audit trail, or edit
mitigation guidance.

A role change takes effect immediately rather than at some later sign-in: the
permission set is resolved at login and cached on the session, so changing an
account's role ends that account's sessions and is audited separately as
`USER_ROLE_CHANGED`.

---

## 4. The audit trail

`audit_logs` is append-only and hash-chained (§32, §56):

```
record_hash = SHA256( previous_hash ‖ canonical(fields) )
```

`canonical(fields)` is a stable serialisation of the record's own columns, and
the row id participates — records are inserted first, then their hash written,
so the id is part of the material. The first record chains from a fixed genesis
value.

*Verify integrity* on the **Logs & Audit** screen re-computes the whole chain
and reports three kinds of issue:

| Issue | Meaning |
| --- | --- |
| `CONTENT` | A record's stored hash no longer matches its contents — it was edited after it was written |
| `CHAIN` | A record's `previous_hash` does not match the record before it — something was deleted or inserted |
| `ORDER` | Records are out of chronological order for their ids |

A failure is displayed as `LOG INTEGRITY WARNING` and is never silently
repaired. Retention pruning removes the oldest records, and verification starts
from the oldest retained record, so routine pruning does not read as tampering.

What is audited: sign-in and sign-out, permission refusals, account changes,
setting changes, scan start/stop/refusal, capture start/stop, Snort connect and
disconnect, incident and alert workflow changes, analyst classifications,
mitigation edits, report generation and data maintenance.

---

## 5. Input validation

The only operator text that reaches an external tool is a port specification
and a target, and both are parsed, not escaped.

| Input | Rule |
| --- | --- |
| Port range | Strict grammar: digits, commas and single hyphens only (`80`, `22,80,443`, `1-1024`). Bounds 1–65535, ranges must ascend. Anything else — `;`, `&&`, `$( )`, backticks, newlines, `--script=` — is refused |
| Target | Must parse as an IPv4/IPv6 address, CIDR, hyphen range or hostname. Metacharacters and whitespace are refused. Oversized networks are refused |
| Timing | One of `T0`–`T5` |
| NSE categories | Allow-list only. `exploit`, `brute`, `dos`, `intrusive`, `malware` and `auth` are permanently forbidden |
| Username | 3–32 characters, letters/digits/`.`/`_`/`-`, not leading or trailing punctuation |
| Password | See §2. The value never appears in an error message |
| Export filename | Separators and `..` stripped; the resolved path must stay inside the export directory |
| BPF filter | Passed to TShark as a single argument, never through a shell |

---

## 6. Subprocess safety

* Nmap runs through `python-nmap` with an **argument list**, never a shell
  string, and never `shell=True`.
* The argument list is assembled from a `ScanProfile` — a fixed catalogue of
  seven profiles — plus a validated port spec and timing token. Operator text
  is never concatenated into it.
* No profile carries an exploitation, brute-force or DoS argument; a test
  asserts this for every catalogued profile.
* TShark is launched by PyShark with an argument list; the interface name comes
  from the enumerated interface list, and the BPF filter is a single argument.
* The exact `command_line` and `arguments` used for each scan are stored with
  the scan, so what ran is always reviewable.

---

## 7. SQL safety

Every statement uses `%s` placeholders with a parameter tuple. Identifiers that
cannot be parameterised — sort columns, filter columns — are checked against a
per-query whitelist (`QueryFilter.allowed_columns`); an unknown identifier
raises `SqlIdentifierError` before any SQL is built. There is no code path in
which operator input becomes part of a statement's text.

---

## 8. Secrets

* Database credentials, SMTP credentials and tool paths come from environment
  variables, loaded from `.env`. Nothing is hard-coded.
* `.env` is in `.gitignore`. `.env.example` documents every variable and
  contains no real value.
* `describe_environment()` redacts any variable whose name contains
  `PASSWORD`, `SECRET`, `TOKEN` or `KEY`; `DatabaseSettings.redacted()` reports
  `(set)` / `(not set)` instead of the password. The System Health and Settings
  screens use those redacted views.
* Passwords are never written to a log at any level. OTP codes are stored
  hashed with an expiry and are single-use.
* Report exports contain security findings; treat them as sensitive. Database
  dumps contain password hashes and the audit trail.

---

## 9. Failure behaviour

The application always starts, even when a subsystem is unusable. A missing
Nmap, an offline database or an absent Snort sensor is reported on the login
window and on the System Health screen; it never becomes a traceback and never
becomes a green indicator. Errors shown to operators are safe summaries; the
detail — including stack traces — goes to the log file and `app_errors`.

A subsystem is shown as healthy **only when it answered a probe**. Nothing is
assumed to work because it is configured (§120).

---

## 10. Reporting a security problem

If you find a weakness in AETHRA-SEC itself, report it to the maintainers of
this repository with enough detail to reproduce it. Do not exercise it against
a system you are not authorised to test — which is the same rule the
application enforces on itself.
