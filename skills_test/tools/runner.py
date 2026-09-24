"""The skills test: detect, diagnose, and show the code to paste back.

Run through ``test.bat``. Eight stages, in the order that makes a diagnosis
trustworthy:

1-2  environment and dependencies  - is the failure even about the code?
3    code integrity                - what differs from the baseline?
4    behavioural regression tests  - does it actually misbehave?
5    database                      - is persistence intact?
6    module imports                - does every module still load?
7    code recovery                 - what should the code say?
8    report                        - written to skills_test/reports/

Stage 4 is the one that decides. A structural difference alone is not a bug -
a legitimate edit looks identical to a sabotage - so the diagnosis leads with
a failing behaviour and uses the structural finding to explain it.

**This tool never modifies the application.** It reads, compares and prints.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# The student copies the known-good code out of this window. A Windows console
# defaults to cp1252, which turns every character the source uses outside that
# set - the section sign in these docstrings, for one - into "?" on the way
# out. Pasting that back would introduce a second fault while fixing the first.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):  # pragma: no cover - redirected output
        pass

from skills_test.tools import analysis  # noqa: E402

REPORTS = ROOT / "skills_test" / "reports"
FAILURES = REPORTS / "failures.json"
RULE = "=" * 74


def rule(text: str = "") -> None:
    print(RULE)
    if text:
        print(f" {text}")
        print(RULE)


@dataclass
class Stage:
    name: str
    status: str = "PENDING"
    detail: str = ""


@dataclass
class Outcome:
    stages: list[Stage] = field(default_factory=list)
    diagnoses: list[dict] = field(default_factory=list)
    structural: list = field(default_factory=list)
    test_total: int = 0
    test_failed: int = 0

    def stage(self, name: str) -> Stage:
        found = Stage(name)
        self.stages.append(found)
        return found


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------
def check_environment(outcome: Outcome) -> None:
    stage = outcome.stage("Environment")
    version = sys.version_info
    if version < (3, 10):
        stage.status, stage.detail = "FAIL", f"Python {version.major}.{version.minor} is too old"
        return
    if not (ROOT / "aethra_sec").is_dir():
        stage.status, stage.detail = "FAIL", "the aethra_sec package is missing"
        return
    stage.status = "PASS"
    stage.detail = f"Python {version.major}.{version.minor}.{version.micro}"


def check_dependencies(outcome: Outcome) -> None:
    stage = outcome.stage("Dependencies")
    missing = []
    for module in ("mysql.connector", "argon2", "psutil", "dotenv", "pytest"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        stage.status = "FAIL"
        stage.detail = "missing: " + ", ".join(missing)
        return
    stage.status, stage.detail = "PASS", "all required packages import"


def check_integrity(outcome: Outcome) -> None:
    stage = outcome.stage("Code Integrity")
    report = analysis.compare_tree()
    if report.baseline_missing:
        stage.status = "FAIL"
        stage.detail = "no baseline - run skills_test/tools/make_baseline.py"
        return
    outcome.structural = report.findings
    serious = [f for f in report.findings if f.severity in ("CRITICAL", "WARNING")]
    if not serious:
        stage.status = "PASS"
        stage.detail = f"{report.unchanged} files match the baseline"
        return
    stage.status = "FAIL"
    critical = sum(1 for f in serious if f.severity == "CRITICAL")
    stage.detail = (
        f"{len(report.changed_files)} changed, {len(report.deleted_files)} deleted, "
        f"{critical} critical"
    )


def run_behavioural(outcome: Outcome) -> None:
    stage = outcome.stage("Behavioural Tests")
    if FAILURES.exists():
        FAILURES.unlink()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "skills_test/tests", "-q", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if not FAILURES.exists():
        stage.status = "ERROR"
        stage.detail = "the test run produced no results"
        tail = (result.stdout or result.stderr or "").strip().splitlines()[-12:]
        stage.detail += "\n" + "\n".join(tail)
        return
    data = json.loads(FAILURES.read_text(encoding="utf-8"))
    outcome.test_total = data["total"]
    outcome.test_failed = data["failed"]
    failed = [r for r in data["results"] if r["outcome"] == "failed"]
    if not failed:
        stage.status = "PASS"
        stage.detail = f"{data['passed']} behavioural tests passed"
        return
    stage.status = "FAIL"
    stage.detail = f"{len(failed)} of {data['total']} failed"
    for record in failed:
        outcome.diagnoses.append(build_diagnosis(record, outcome.structural))


def check_database(outcome: Outcome) -> None:
    stage = outcome.stage("Database")
    try:
        from aethra_sec.config.settings import load_settings
        from aethra_sec.database.connection import server_reachable

        settings = load_settings()
        if not server_reachable(settings.database):
            stage.status = "SKIP"
            stage.detail = "no MySQL server reachable (database tests skipped)"
            return
        stage.status, stage.detail = "PASS", "server reachable"
    except Exception as exc:  # noqa: BLE001
        stage.status, stage.detail = "SKIP", f"could not check: {exc}"


def check_modules(outcome: Outcome) -> None:
    """Every application module must still import."""
    stage = outcome.stage("Module Imports")
    broken: list[str] = []
    for path in sorted((ROOT / "aethra_sec").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        result = subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            cwd=ROOT, capture_output=True, text=True,
        )
        if result.returncode != 0:
            first = [
                line for line in (result.stderr or "").strip().splitlines()
                if line and not line.startswith(" ")
            ]
            broken.append(f"{module}: {first[-1] if first else 'import failed'}")
    if broken:
        stage.status = "FAIL"
        stage.detail = "\n".join(broken[:10])
        for entry in broken:
            module = entry.split(":", 1)[0]
            relative = module.replace(".", "/") + ".py"
            outcome.diagnoses.append({
                "feature": "Application startup", "action": "Module import",
                "path": relative, "qualname": "",
                "expected": "the module imports cleanly",
                "actual": entry.split(":", 1)[1].strip(),
                "test": "module import check",
                "structural": [
                    f for f in outcome.structural if f.path == relative
                ],
            })
        return
    stage.status, stage.detail = "PASS", "every module imports"


def build_diagnosis(record: dict, structural: list) -> dict:
    """Join a failing test to the baseline evidence for its target."""
    target = record.get("target") or {}
    path = target.get("path", "")
    qualname = target.get("qualname", "")
    related = [
        f for f in structural
        if f.path == path and (not qualname or f.qualname == qualname
                               or qualname.startswith(f.qualname))
    ]
    if not related:
        related = [f for f in structural if f.path == path]
    return {
        "feature": target.get("feature") or "(not declared)",
        "action": target.get("action") or record["name"],
        "path": path,
        "qualname": qualname,
        "expected": record.get("docstring", ""),
        "actual": record.get("message", ""),
        "test": record["nodeid"],
        "structural": related,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_header() -> None:
    rule()
    print(" AETHRA-SEC OFFLINE SKILLS TEST")
    rule()
    print()


def print_stages(outcome: Outcome) -> None:
    total = len(outcome.stages)
    for index, stage in enumerate(outcome.stages, start=1):
        dots = "." * max(3, 28 - len(stage.name))
        print(f"[{index}/{total}] {stage.name} {dots} {stage.status}")
    print()


#: Findings that explain every other failure in the run, so they are shown
#: first. A file that does not parse, or that is gone, takes the modules that
#: import it with it - and the per-test diagnoses below would then all point at
#: whichever file each test happened to name.
ROOT_CAUSE_KINDS = ("SYNTAX_ERROR", "DELETED_FILE", "MISSING_IMPORT")


def print_root_causes(outcome: Outcome) -> bool:
    """Show the findings that make everything else fail. True if any."""
    causes = [f for f in outcome.structural if f.kind in ROOT_CAUSE_KINDS]
    if not causes:
        return False
    rule("ROOT CAUSE - FIX THIS FIRST")
    print()
    print(" The failures below all follow from this. Repair it, run test.bat")
    print(" again, and the other reports will very likely disappear with it.")
    print()
    for finding in causes:
        rule(finding.kind.replace("_", " "))
        print()
        print(f" File:     {finding.path}")
        if finding.qualname:
            print(f" Function: {finding.qualname}")
        for line in finding.detail.splitlines():
            print(f" {line}")
        if finding.current_code:
            print()
            rule("CURRENT CODE (around the problem)")
            print()
            print(finding.current_code)
        if finding.baseline_code:
            print()
            rule("KNOWN-GOOD CODE - COPY THIS")
            print()
            print(finding.baseline_code)
        print()
        rule("MANUAL ACTION REQUIRED")
        print()
        print(f" 1. Open:    {finding.path}")
        if finding.kind == "SYNTAX_ERROR":
            print(" 2. Fix the syntax at the line named above.")
            print("    To see the original text of any function in this file:")
            print(f"       python skills_test\\tools\\code_recovery.py "
                  f"--file {finding.path} --function <name>")
        elif finding.kind == "MISSING_IMPORT":
            print(" 2. Add the import line above, with the other imports.")
        elif finding.kind == "DELETED_FILE":
            print(" 2. Recreate the file with the contents above.")
        print(" 3. Save the file, then run test.bat again.")
        print()
        print(" test.bat does not edit the file. You make the change.")
        print()
    return True


def print_diagnosis(index: int, diagnosis: dict, total: int) -> None:
    rule(f"BUG {index} OF {total}" if total > 1 else "BUG DETECTED")
    print()
    print(f"Feature:   {diagnosis['feature']}")
    print(f"Action:    {diagnosis['action']}")
    print(f"File:      {diagnosis['path'] or '(not identified)'}")
    if diagnosis["qualname"]:
        print(f"Function:  {diagnosis['qualname']}")
    print(f"Test:      {diagnosis['test']}")
    if diagnosis["expected"]:
        print(f"\nExpected:  {diagnosis['expected']}")
    if diagnosis["actual"]:
        print("\nWhat happened:")
        for line in diagnosis["actual"].splitlines()[:6]:
            print(f"    {line}")

    findings = diagnosis["structural"]
    if not findings:
        print()
        rule("NO DIFFERENCE FROM THE BASELINE IN THIS FILE")
        print()
        print(" The behaviour is wrong but this file matches the known-good")
        print(" copy. The cause is probably in a different file, or in")
        print(" configuration or data rather than code.")
        print()
        print(" Nothing is shown to paste: there is no baseline difference to")
        print(" undo, and inventing a replacement would be a guess.")
        print()
        return

    for finding in findings:
        print()
        rule(f"{finding.kind.replace('_', ' ')}")
        print()
        if finding.detail:
            for line in finding.detail.splitlines():
                print(f" {line}")
        if finding.current_code:
            print()
            rule("CURRENT CODE")
            print()
            print(finding.current_code)
        if finding.baseline_code:
            print()
            rule("KNOWN-GOOD CODE - COPY THIS")
            print()
            print(finding.baseline_code)
        print()
        rule("MANUAL ACTION REQUIRED")
        print()
        print(f" 1. Open:    {finding.path}")
        if finding.qualname:
            print(f" 2. Find:    {finding.qualname}")
            print(" 3. Replace it with the KNOWN-GOOD CODE above.")
        elif finding.kind == "DELETED_FILE":
            print(" 2. Recreate the file with the contents above.")
        elif finding.kind == "MISSING_IMPORT":
            print(" 2. Add the import line above, with the other imports.")
        print(" 4. Save the file.")
        print(" 5. Run test.bat again.")
        print()
        print(" test.bat does not edit the file. You make the change.")
        print()


def print_structural_only(outcome: Outcome) -> None:
    """Changes found, but nothing misbehaves."""
    serious = [f for f in outcome.structural if f.severity in ("CRITICAL", "WARNING")]
    if not serious:
        return
    rule("SOURCE DIFFERS FROM THE BASELINE, BUT EVERY TEST PASSES")
    print()
    print(" These files are not what the baseline recorded. No behavioural")
    print(" test fails, so this may be legitimate work rather than a fault.")
    print(" They are listed so you can judge:")
    print()
    for finding in serious[:20]:
        where = finding.path + (f" :: {finding.qualname}" if finding.qualname else "")
        print(f"   [{finding.severity:8}] {finding.kind:24} {where}")
    if len(serious) > 20:
        print(f"   ... and {len(serious) - 20} more")
    print()
    print(" To see the known-good code for any of them:")
    print("   python skills_test\\tools\\code_recovery.py --file <path> "
          "--function <name>")
    print()


def write_report(outcome: Outcome, passed: bool) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    manifest = analysis.load_manifest()
    lines = [
        "# AETHRA-SEC Skills Test Report",
        "",
        f"- **Run:** {datetime.now().isoformat(timespec='seconds')}",
        f"- **Baseline recorded:** {manifest.get('created', '(none)')}",
        f"- **Baseline files:** {manifest.get('file_count', 0)}",
        f"- **Version control:** {manifest.get('vcs', 'unknown')}",
        f"- **Result:** {'PASS' if passed else 'FAIL'}",
        "",
        "## Stages",
        "",
        "| Stage | Result | Detail |",
        "|---|---|---|",
    ]
    for stage in outcome.stages:
        detail = stage.detail.replace("\n", "<br>").replace("|", "\\|")
        lines.append(f"| {stage.name} | {stage.status} | {detail} |")

    lines += ["", "## Behavioural tests", "",
              f"- total: {outcome.test_total}", f"- failed: {outcome.test_failed}", ""]

    if outcome.diagnoses:
        lines += ["## Diagnoses", ""]
        for index, diagnosis in enumerate(outcome.diagnoses, start=1):
            lines += [
                f"### {index}. {diagnosis['feature']} - {diagnosis['action']}", "",
                f"- **File:** `{diagnosis['path']}`",
                f"- **Function:** `{diagnosis['qualname'] or '-'}`",
                f"- **Test:** `{diagnosis['test']}`",
                f"- **Expected:** {diagnosis['expected'] or '-'}",
                "", "**What happened**", "", "```",
                diagnosis["actual"] or "(no message)", "```", "",
            ]
            for finding in diagnosis["structural"]:
                lines += [f"**{finding.kind}** - {finding.detail}", ""]
                if finding.current_code:
                    lines += ["Current code:", "", "```python",
                              finding.current_code, "```", ""]
                if finding.baseline_code:
                    lines += ["Known-good code (paste this):", "", "```python",
                              finding.baseline_code, "```", ""]

    changed = [f for f in outcome.structural if f.severity != "INFO"]
    if changed:
        lines += ["## All differences from the baseline", "",
                  "| Severity | Kind | File | Function |", "|---|---|---|---|"]
        for finding in changed:
            lines.append(
                f"| {finding.severity} | {finding.kind} | `{finding.path}` "
                f"| `{finding.qualname or '-'}` |"
            )
        lines.append("")

    lines += [
        "## Manual repair",
        "",
        "This system never edits source. For each diagnosis above: open the",
        "file, find the function, paste the known-good code, save, and run",
        "`test.bat` again.",
        "",
    ]
    path = REPORTS / "skills_test_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_changes_report(outcome: Outcome) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    report = analysis.compare_tree()
    lines = [
        "# Code Changes Against the Baseline", "",
        f"Generated {datetime.now().isoformat(timespec='seconds')}.",
        "",
        f"- files matching the baseline: {report.unchanged}",
        f"- modified: {len(report.changed_files)}",
        f"- deleted: {len(report.deleted_files)}",
        f"- added (not in the baseline): {len(report.added_files)}",
        "",
    ]
    for title, items in (("Modified files", report.changed_files),
                         ("Deleted files", report.deleted_files),
                         ("Added files", report.added_files)):
        lines += [f"## {title}", ""]
        lines += [f"- `{p}`" for p in items] or ["_none_"]
        lines.append("")
    lines += ["## Findings", ""]
    for finding in report.findings:
        lines += [
            f"### {finding.kind} - `{finding.path}`"
            + (f" :: `{finding.qualname}`" if finding.qualname else ""),
            "", f"- severity: {finding.severity}", f"- {finding.detail}", "",
        ]
        if finding.diff:
            lines += ["```diff", finding.diff, "```", ""]
    path = REPORTS / "code_changes.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-modules", action="store_true",
                        help="skip the per-module import check (it is slow)")
    arguments = parser.parse_args(argv)

    print_header()
    outcome = Outcome()

    check_environment(outcome)
    check_dependencies(outcome)
    check_integrity(outcome)
    run_behavioural(outcome)
    check_database(outcome)
    if arguments.no_modules:
        outcome.stage("Module Imports").status = "SKIP"
    else:
        check_modules(outcome)

    recovery = outcome.stage("Code Recovery")
    recovery.status = "FOUND" if outcome.diagnoses else "NONE NEEDED"

    print_stages(outcome)

    blocking = [s for s in outcome.stages
                if s.status in ("FAIL", "ERROR") and s.name != "Code Integrity"]
    passed = not outcome.diagnoses and not blocking

    had_root_cause = print_root_causes(outcome)

    if outcome.diagnoses and had_root_cause:
        # Everything below is downstream of the root cause; listing fifteen
        # misattributed diagnoses after it would bury the one that matters.
        rule("DOWNSTREAM FAILURES")
        print()
        print(f" {len(outcome.diagnoses)} behavioural test(s) also failed. They are")
        print(" listed in the report rather than here, because they are very")
        print(" likely consequences of the root cause above.")
        print()
        for diagnosis in outcome.diagnoses[:8]:
            print(f"   - {diagnosis['feature']}: {diagnosis['action']}")
        if len(outcome.diagnoses) > 8:
            print(f"   ... and {len(outcome.diagnoses) - 8} more")
        print()
    elif outcome.diagnoses:
        for index, diagnosis in enumerate(outcome.diagnoses, start=1):
            print_diagnosis(index, diagnosis, len(outcome.diagnoses))
    elif any(s.status in ("FAIL", "ERROR") for s in outcome.stages):
        for stage in outcome.stages:
            if stage.status in ("FAIL", "ERROR") and stage.name != "Code Integrity":
                rule(f"{stage.name.upper()} FAILED")
                print()
                for line in stage.detail.splitlines():
                    print(f"  {line}")
                print()
        print_structural_only(outcome)
    else:
        print_structural_only(outcome)

    report = write_report(outcome, passed)
    changes = write_changes_report(outcome)
    outcome.stages.append(Stage("Report", "PASS", str(report)))

    rule("SKILLS TEST RESULT")
    print()
    if passed:
        print("  PASS - every required behavioural test passed.")
        if any(f.severity != "INFO" for f in outcome.structural):
            print("  (The source differs from the baseline; see above.)")
    else:
        print("  FAIL - see the diagnosis above.")
        print()
        print("  Repair the code by hand, then run test.bat again.")
    print()
    print(f"  Report:  {report.relative_to(ROOT)}")
    print(f"  Changes: {changes.relative_to(ROOT)}")
    print()
    rule()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
