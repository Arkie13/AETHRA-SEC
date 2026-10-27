# Changelog

## 2026-10-05 — System stability, performance and bug audit

**No application code was changed by this audit.** Every candidate fix was
either already implemented, a false positive, or a change that would have been
tuning without evidence. The deliverable is the measurement, recorded in
`AETHRA-SEC_SYSTEM_STABILITY_AUDIT.md`.

### Bug fixes
- None required. No crash, leak, orphan, unbounded buffer or swallowed
  exception was found.
- **False positive retracted:** two capture processes running with AETHRA-SEC
  closed were the operator's own, writing to `C:\Snort-wsl\capture\cap.pcap`.
  Not AETHRA-SEC orphans, and not killed.
- **Did not reproduce:** the reported long-run stop. 15 minutes of continuous
  real capture stayed in `CAPTURING` for all 59 samples.

### Performance — verified, not changed
- Sustained run: 142,620 packets, **0 TShark drops**, 0 decode errors.
- Queue peak **305 of 20,000** (1.5% of capacity).
- RSS 53.3 → 92.9 MB, flat over the final 75 s — bounded, not leaking.
- Threads 15 → 10; exactly 2 TShark children throughout; 0 after stop.

### Database — verified, not changed
- Sidebar badge uses SQL `COUNT` (0.9 ms), not a Python table scan.
- Slowest UI query is top-sources over 24 h at 90.4 ms, served by the
  composite `(captured_at, src_ip, length)` index.
- Pool releases connections in `finally` and discards on `MySQLError`; idle
  connections pinged only after a threshold, not per checkout.
- Retention reclaimed `traffic_records` from 1,750,151 to 625,150 rows with no
  loss of security records.

### Capture — verified, not changed
- `_retained` and `_pending` are `deque(maxlen=…)`; `_ingest` is
  capacity-guarded before append.
- Packets dropped from the *view* are counted separately from network loss.
- Duplicate capture prevented by a state-machine guard under a lock plus a
  reader-level guard.
- Lifecycle: stop → 0 children, restart → `CAPTURING`, shutdown → threads 15 → 3.

### Snort — verified, not changed
- Alert tailer seeks to EOF, tracks position and detects truncation. No reread
  of the alert file per poll, so no O(n²) growth and no duplicate ingest.
- **NOT TESTED — DEPENDENCY UNAVAILABLE:** live alert volume; no sensor was
  writing during the audit.

### Nmap — verified, not changed
- Structured XML (`-oX -`) parsed with `ElementTree`; no terminal-text parsing.
- A failed or unreachable scan is never reported as Safe.

### UI — verified, not changed
- No module under `services/`, `analytics/`, `integrations/` or `database/`
  imports `tkinter`, so a worker cannot touch a widget.
- **NOT TESTED:** main-loop lag during sustained load. The 15-minute run drove
  the service layer directly, without a Tk main loop.

### Logging — verified, not changed
- `RotatingFileHandler` with size and backup limits; the log had already
  rotated from 3.8 MB to 0.2 MB.

### Tests
- `pytest tests/` — **2,610 passed, 1 skipped, 0 failed**.
- `test.bat` — 6 of 7 stages PASS. Stage 3 reports baseline drift from this
  session's own earlier changes and correctly states
  *"source differs from the baseline, but every test passes"*.
