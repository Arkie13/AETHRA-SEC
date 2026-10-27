# AETHRA-SEC — System Stability, Performance and Bug Audit

**Date:** 2026-10-05 · **Version audited:** 1.0.0 · **Schema version:** 22
**Scope:** `C:\xampp\htdocs\AETHRA-SECNEW` — full repository

---

## 1. Executive summary

This audit looked for crashes, leaks, bottlenecks, lifecycle defects and
fabricated behaviour, and attempted to reproduce the reported symptom that the
application or its capture "stops after extended operation".

**The headline result is a negative one, and it is worth stating plainly: no
crash, leak, orphan or unbounded-growth defect was found, and the reported
long-run stop did not reproduce.** That conclusion rests on a 15-minute
instrumented run against real traffic rather than on reading the code.

This is less surprising than it sounds. Most of what this audit asks for —
bounded queues, batched UI updates, batched database writes, a row-rate cap, a
bounded pcap ring, counters that separate captured from displayed — was
implemented and measured in earlier work on this system. The audit's value here
is confirmation under load, plus the small number of genuine findings in §3.

**One destructive mistake was avoided and is worth recording.** Two capture
processes were running while AETHRA-SEC was not, which looks exactly like an
orphaned-subprocess defect. Their command lines show they are the operator's
own capture writing to `C:\Snort-wsl\capture\cap.pcap`, unrelated to
AETHRA-SEC. Killing them as "orphans" would have destroyed a running capture.
Process name alone is not evidence of ownership.

---

## 2. Architecture reviewed

```
Tk UI  (one thread, never touched from a worker)
  |  aethra_sec.ui.dispatch.post   <- the only worker -> UI bridge
Services          PacketCapture · Snort · Nmap · Correlation · Notification
  |                Mitigation · Dashboard · Report · Health · Retention
Workers           capture worker · assessment queue · scheduler · audio worker
  |
Integrations      Npcap/TShark (field extraction) · Snort transports · Nmap
  |
Database          MariaDB 10.4, pooled, forward-only migrations (22 applied)
```

Verified structurally: **no module under `services/`, `analytics/`,
`integrations/` or `database/` imports `tkinter` at all**, so a worker
physically cannot touch a widget. The single sanctioned bridge is
`ui.dispatch.post`.

---

## 3. Bugs and findings

### F-01 · Code-integrity baseline drift · Severity: INFO · `skills_test`

`test.bat` reports stage 3 FAIL. Investigated: the difference is legitimate drift from
this session's own changes (`date_modified`, `dns.a`/`dns.aaaa`, peer
visibility). The system's own verdict is correct and honest:
*"SOURCE DIFFERS FROM THE BASELINE, BUT EVERY TEST PASSES"*.

**Not a defect.** Regenerating the baseline is an operator decision, not an
audit fix — doing it automatically would adopt whatever is currently on disk as
known-good, which is exactly what that system exists to prevent.

### F-02 · Apparent orphaned capture processes · Severity: NONE (false positive)

`tshark.exe` (PID 21380) and `dumpcap.exe` (PID 6668) were running with no
AETHRA-SEC process present. Command-line inspection:

```
tshark.exe  -i 5 -w C:\Snort-wsl\capture\cap.pcap -b duration:10 -b files:30
dumpcap.exe ... -w C:\Snort-wsl\capture\cap.pcap ...
```

These are the operator's own capture. AETHRA-SEC writes to its own `captures/`
directory under a different naming scheme. **No AETHRA-SEC orphans exist** —
confirmed again by the lifecycle test in §12, which ends at zero children.

### F-03 · Single decode worker is the scaling ceiling · Severity: P4 · capture

`capture.decode_workers` defaults to `1`. One worker drains the 20,000-entry
queue doing host discovery, protocol analysis, anomaly rules and batching. At
the rates measured here (~160 pkt/s sustained, bursting to ~900) it was never
the limit: peak queue depth was **305 of 20,000**.

Under a genuine flood it would be the first thing to saturate. **Not changed**:
raising it without a flood to measure against would be tuning by guesswork, and
the existing backpressure already sheds correctly and counts what it sheds.

### F-04 · Database round-trip spikes under write bursts · Severity: P5 · database

Median round trip **1.2 ms**, maximum **96.4 ms**, with the spikes coinciding
with batch flushes. No connection or cursor leak: the pool uses a context
manager that discards a connection on `MySQLError` and releases it in
`finally`, and idle connections are pinged only after `PING_IDLE_SECONDS`
rather than on every checkout.

**Not changed.** A 96 ms spike on a background writer is not a user-visible
problem, and the UI thread does not issue these queries.

### F-05 · Reported long-run stop · Severity: P0 if real · **DID NOT REPRODUCE**

15 minutes of continuous real capture: state remained `CAPTURING` for all 59
samples, 142,620 packets, zero drops, zero decode errors. The application log
records **no error-driven capture stop** — every recorded stop is clean, with
`0 dropped`.

**NOT REPRODUCED — the symptom did not occur in a 15-minute window.** This does
not prove the report false; it means a longer run, or the specific conditions
that produced it, are needed. See §14.

---

## 4-10 · Areas audited and found sound

Each of these was checked against the code and, where measurable, against the
running system.

| Area | Checked | Result |
|---|---|---|
| Bare `except:` | whole tree | **none** |
| Exception swallowing | `pass`-only handlers | 6, all documented and deliberate (diagnostics, optional fields) |
| Packet buffers | `packet_view` | `_retained` and `_pending` are `deque(maxlen=…)`; `_ingest` is capacity-guarded *before* append |
| View drops vs capture loss | `ingest()` | counted separately and documented as "dropped from the view … still analysed and stored" |
| Analyzer growth | `traffic_analyzer` | buckets trimmed by cutoff **and** `_max_buckets`; `MAX_KEYS_PER_BUCKET = 4000` |
| Duplicate capture workers | service + reader | state-machine guard under a lock, plus `if self.is_running: return` in the reader |
| Worker join | `packet_capture` | `_stop_worker.set()` then `worker.join(timeout=10)` |
| Snort tailing | `transports` | seeks to EOF, tracks position, detects truncation — **no reread, no O(n²)** |
| Nmap output | `runner` | `-oX -` structured XML, parsed with `ElementTree` — no terminal-text parsing |
| Failed scan ≠ Safe | `derive_security_result` | explicit: *"An unreachable host is never Safe, and a failed scan is never Safe"* |
| Log growth | `utils/logging` | `RotatingFileHandler` with `maxBytes`/`backupCount`; log had already rotated 3.8 MB → 0.2 MB |
| Badge counters | alerts | SQL `COUNT`, **0.9 ms** — not a Python scan of the table |
| Worker → UI | all layers | no worker-side module imports `tkinter` |

### Database indexes and query cost (measured, live data)

`traffic_records` carries a composite `(captured_at, src_ip, length)` index
added for the top-sources query — previously a measured cause of UI lag.

| Query the UI actually runs | Time |
|---|---|
| unreviewed alert count (sidebar badge) | 0.9 ms |
| recent alerts page (200) | 18.0 ms |
| traffic_records recent (200) | 5.1 ms |
| **traffic top sources, 24 h** | **90.4 ms** |
| hosts inventory (200) | 65.6 ms |
| audit page (200) | 5.3 ms |

Retention is working: `traffic_records` fell from 1,750,151 rows to 625,150
between sessions, without operator action and without touching security
records.

---

## 11. Changes implemented

**None.** No code was modified by this audit.

That is the honest outcome. Every candidate fix was either (a) already
implemented, (b) a false positive, or (c) a change that would have been tuning
without evidence — and this system's standing rule is that unmeasured changes
are not improvements. The measurements in §12 are the deliverable.

---

## 12. Tests performed

### Automated

| Suite | Result |
|---|---|
| `test.bat` (7-stage skills test) | 6 PASS, 1 baseline-drift FAIL (F-01), 53 behavioural tests pass |
| `pytest tests/` | **2,610 passed, 1 skipped, 0 failed** |

### Sustained operation — 15 minutes, real traffic, real database

59 samples at 15-second intervals through the real `PacketCaptureService`.

| Metric | Result |
|---|---|
| Capture state | `CAPTURING` for all 59 samples — never stopped on its own |
| Packets captured | 142,620 |
| **TShark drops** | **0** |
| Decode errors | 0 |
| Rows persisted / shed by rate cap | 47,991 / 94,621 |
| Queue depth | peak **305 of 20,000**, final 0 |
| RSS | 53.3 → 92.9 MB, peak 93.7 |
| RSS first half → second half | 84.4 → 92.8 MB, **flat over the final 75 s** (92.7 → 92.9) |
| Threads | 15 → 10, max 15 |
| TShark children | **exactly 2** throughout (tshark + its dumpcap child) |
| View retained | capped at 20,000 — the bound holding exactly |
| DB round trip | median 1.2 ms, max 96.4 ms |

### Lifecycle — stop, restart, stop, shut down

```
stop      -> state=STOPPED     tshark children=0
start     -> state=CAPTURING   captured=149
stop      -> tshark children=0
shutdown  -> threads 15 -> 3
```

No orphaned subprocess, no thread leak, clean restart.

---

## 13. Before vs after measurements

**None to report.** No change was made, so there is no "after". The figures in
§12 are a baseline for the system as it stands.

---

## 14. Remaining issues

1. **The long-run stop (F-05) is unexplained, not disproved.** Fifteen minutes
   of ordinary traffic did not reproduce it. A longer run, or the specific
   conditions under which it was seen, is the next step. The `flood_probe`
   diagnostic already in the tree records Tk main-loop lag, queue depth, RSS,
   threads and database latency to CSV and is armed with
   `AETHRA_FLOOD_PROBE=1`.

2. **Flood behaviour is still unmeasured.** The reported freeze under an HTTP
   flood has never been reproduced with instrumentation attached. Until it is,
   `decode_workers` (F-03) should not be changed.

3. **NOT TESTED — DEPENDENCY UNAVAILABLE:** Snort alert ingest under load. No
   sensor was writing during this audit, so the ingest path was exercised only
   by its unit tests, not by live alert volume.

4. **NOT TESTED:** UI responsiveness during the sustained run. The 15-minute
   test drove the service layer directly, without a Tk main loop, so main-loop
   lag was not sampled. The probe exists for this; it needs a GUI session.

---

## 15. Recommendations

1. **Run the flood probe during the next real flood.** It is the only way to
   settle F-03 and F-05, and it is already built and tested.
2. **Leave `decode_workers` at 1** until a measured flood shows the queue
   pinning. Peak depth here was 1.5% of capacity.
3. **Regenerate the skills-test baseline** when the current tree is accepted as
   known-good — deliberately, from a verified state, never automatically.
4. **Keep retention enabled.** It demonstrably reclaimed 1.1 M rows without
   touching security records.
5. **Do not treat process name as ownership.** F-02 would have destroyed a
   running capture. Check the command line.

---

## Appendix · What was deliberately not done

- No module rewritten, no working code replaced for style.
- No index added: none of the measured queries justified one.
- No threshold invented. Where a number appears it was measured.
- No test disabled or weakened.
- No data deleted; no table dropped; no schema reset.
- No failure converted into a success state.
