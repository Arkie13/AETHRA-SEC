"""Show the known-good code for something that is broken.

This tool answers one question - "what did this used to say?" - and answers it
by reading the baseline. It never writes to the application, never restores a
file, and never generates an implementation: if the baseline does not contain
the code, it says so rather than inventing something plausible.

Usage:

    python skills_test/tools/code_recovery.py --file aethra_sec/models/host.py
    python skills_test/tools/code_recovery.py --file <path> --function <name>
    python skills_test/tools/code_recovery.py --all          # every finding
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools import analysis  # noqa: E402

RULE = "=" * 74


def banner(text: str) -> str:
    return f"{RULE}\n {text}\n{RULE}"


def show_function(relative: str, qualname: str) -> int:
    """Print the baseline text of one function beside the current one."""
    baseline = analysis.baseline_function(relative, qualname)
    current = analysis.current_function(relative, qualname)

    if baseline is None:
        print(banner("NOT IN THE BASELINE"))
        print(f"\n{relative} :: {qualname}\n")
        print("This function is not recorded in the known-good baseline, so")
        print("there is no original implementation to show. It may be new, or")
        print("the name may be spelled differently.")
        print()
        print("Nothing is generated here: inventing an implementation would be")
        print("a guess presented as a repair.")
        return 1

    print(banner(f"{relative}  ::  {qualname}"))
    if current is None:
        print("\nStatus:  MISSING from the current file")
    elif current.source == baseline.source:
        print("\nStatus:  matches the baseline (nothing to restore)")
        return 0
    else:
        print("\nStatus:  DIFFERS from the baseline")
        print(f"\n{banner('CURRENT CODE')}\n")
        print(current.source)

    print(f"\n{banner('KNOWN-GOOD CODE - COPY THIS')}\n")
    print(baseline.source)
    print()
    print(RULE)
    print(" MANUAL ACTION REQUIRED")
    print(RULE)
    print(f"\n 1. Open:    {relative}")
    print(f" 2. Find:    {qualname}")
    print(" 3. Replace it with the KNOWN-GOOD CODE above.")
    print(" 4. Save the file.")
    print(" 5. Run test.bat again.\n")
    print(" This tool does not edit the file. You make the change.")
    return 0


def show_file(relative: str) -> int:
    """Print a whole baseline file, for the case where one was deleted."""
    baseline_path = analysis.SOURCE / relative
    if not baseline_path.exists():
        print(f"{relative} is not in the baseline; nothing to show.")
        return 1
    current = ROOT / relative
    print(banner(f"{relative}"))
    print(f"\nStatus:  {'MISSING' if not current.exists() else 'present'}")
    print(f"\n{banner('KNOWN-GOOD FILE - COPY THIS')}\n")
    print(analysis.read(baseline_path))
    print(RULE)
    print(f"\n MANUAL ACTION: recreate {relative} with the contents above.")
    print(" This tool does not write the file.\n")
    return 0


def show_all() -> int:
    """Every structural finding, with its baseline code."""
    report = analysis.compare_tree()
    if report.baseline_missing:
        print("No baseline recorded. Run:")
        print("  python skills_test/tools/make_baseline.py")
        return 2
    findings = [f for f in report.findings if f.severity != "INFO"]
    if not findings:
        print("The source matches the baseline. Nothing to recover.")
        return 0
    for finding in findings:
        print()
        print(banner(finding.kind.replace("_", " ")))
        print(f"\nFile:     {finding.path}")
        if finding.qualname:
            print(f"Function: {finding.qualname}")
        print(f"Problem:  {finding.detail}")
        if finding.current_code:
            print(f"\n{banner('CURRENT CODE')}\n")
            print(finding.current_code)
        if finding.baseline_code:
            print(f"\n{banner('KNOWN-GOOD CODE - COPY THIS')}\n")
            print(finding.baseline_code)
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", help="repository-relative path")
    parser.add_argument("--function", help="function or Class.method")
    parser.add_argument("--all", action="store_true", help="every finding")
    arguments = parser.parse_args(argv)

    if arguments.all or not arguments.file:
        return show_all()
    if arguments.function:
        return show_function(arguments.file, arguments.function)
    return show_file(arguments.file)


if __name__ == "__main__":
    raise SystemExit(main())
