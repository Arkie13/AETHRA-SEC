# AETHRA-SEC Offline Skills Test

A diagnostic and code-recovery assistant. When something in AETHRA-SEC has
been broken, it tells you **which feature fails**, **which file**, **which
function**, and **what the code used to say** — then stops, so that you make
the repair yourself.

**It never edits your source.** Not a patch, not a restore, not a checkout.

---

## For the student

Double-click **`test.bat`** in the project root, or run it from a terminal.

```
test.bat                 full diagnostic run
test.bat --no-modules    skip the per-module import scan (about a minute faster)
```

When everything is healthy you get `PASS`. When something is broken you get a
diagnosis like this:

```
==========================================================================
 BUG DETECTED
==========================================================================

Feature:   IDS Alerts
Action:    Severity mapping
File:      aethra_sec/analytics/risk_engine.py
Function:  RiskEngine.severity_for_snort_priority
Test:      skills_test/tests/test_ids.py::test_priority_one_is_high

Expected:  Snort priority 1 is its most severe; it must not read as
           anything less.

What happened:
    AssertionError: assert <Severity.LOW: 'LOW'> is <Severity.HIGH: 'HIGH'>
```

followed by the **current code**, the **known-good code to copy**, and where
to paste it. Fix it by hand, save, and run `test.bat` again.

### Reading the result

| Stage | What it means when it fails |
|---|---|
| Environment | Python is too old, or you are not in the project root |
| Dependencies | a required package is not installed — run `setup.bat` |
| Code Integrity | the source differs from the known-good baseline |
| Behavioural Tests | the application actually misbehaves |
| Database | MySQL is unreachable (this only skips database tests) |
| Module Imports | some module no longer imports at all |
| Code Recovery | `FOUND` means the original code is available to show you |

**Code Integrity FAIL on its own is not a bug.** Any legitimate edit makes the
source differ from the baseline. The stage that decides is *Behavioural
Tests*: it is the one that proves the program does the wrong thing.

If a run reports a **ROOT CAUSE** section, fix that first — a file that does
not parse, or that is missing, makes everything downstream of it fail too.

---

## Looking up code yourself

```
python skills_test\tools\code_recovery.py --file aethra_sec\models\host.py --function cvss_band
python skills_test\tools\code_recovery.py --file aethra_sec\analytics\traffic_classes.py
python skills_test\tools\code_recovery.py --all
```

It prints the baseline text. It does not write anything.

---

## How it works

```
skills_test/
  baseline/
    baseline_manifest.json    SHA-256, size and timestamp of 244 source files
    source/                   a read-only copy of the known-good source
  tools/
    make_baseline.py          records the baseline (run once, from a healthy tree)
    analysis.py               hash + AST comparison: missing functions, changed
                              signatures, stubs, commented-out logic, lost imports
    coverage.py               the @covers decorator that ties a test to its code
    runner.py                 the eight-stage diagnostic that test.bat calls
    code_recovery.py          prints known-good code for a file or function
    ai_review.py              optional local-only explanation (Ollama)
  tests/                      behavioural regression tests
  reports/
    initial_audit.md          the pre-change audit of the project
    skills_test_report.md     written on every run
    code_changes.md           every difference from the baseline, with diffs
    AI_REVIEW.md              written only if a local Ollama is present
```

A failing test knows which code it was about, because each test declares it:

```python
@covers("aethra_sec/models/host.py", "derive_security_result",
        feature="Vulnerability Assessment", action="Security result")
def test_a_host_that_did_not_answer_is_not_safe() -> None:
    ...
```

That is what lets the diagnosis jump from "this behaviour is wrong" to "here
is the original text of that exact function".

---

## Rules this system keeps

- **It never modifies application source.** No edit, no restore, no patch, no
  version-control command. Verified by the sabotage suite: after every
  scenario the broken file was still broken.
- **It never invents code.** Every replacement shown is read from the
  baseline. When the baseline has nothing to show, it says so instead of
  producing something plausible.
- **It never hides the change.** The professor's modification stays exactly
  where it is until you repair it.
- **It works offline.** No internet, no cloud service, no telemetry. The
  optional AI is local-only (`127.0.0.1:11434`) and is skipped when absent,
  which never affects the result.
- **No fabricated security data.** The tests use isolated fixtures in a
  separate test schema; production hosts, alerts and findings are never read
  or written.

---

## Re-recording the baseline

Only from a system you know is healthy:

```
python skills_test\tools\make_baseline.py --force
```

It refuses without `--force`, because re-recording after a modification would
adopt that modification as "known good" and the diagnosis would then find
nothing.
