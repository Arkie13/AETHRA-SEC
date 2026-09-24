"""Run the AETHRA-SEC diagnostics from the command line.

    python scripts/health_check.py            human-readable report
    python scripts/health_check.py --json     machine-readable report

Exit codes: ``0`` ready, ``1`` one or more checks failed, ``2`` the services
could not be started at all.

The report states what is actually true of this installation - which tools were
found, whether capture is running, whether Snort is connected, how many records
are stored. Nothing is assumed to be healthy because it is configured (§1, §57).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aethra_sec.config.settings import load_settings  # noqa: E402
from aethra_sec.core.application import ApplicationContext  # noqa: E402
from aethra_sec.utils.logging import configure_logging  # noqa: E402
from aethra_sec.version import APP_NAME, APP_VERSION  # noqa: E402


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="health_check",
        description="Report the state of every AETHRA-SEC subsystem.",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the report as JSON"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="print only the summary line and the failures",
    )
    return parser.parse_args(argv)


def _print_text(report, quiet: bool) -> None:
    """Print the diagnostics report as text."""
    width = 78
    print("=" * width)
    print(f"{APP_NAME} {APP_VERSION} - system diagnostics")
    print("=" * width)
    for check in report.checks:
        failed = str(check.result) not in ("PASS",)
        if quiet and not failed:
            continue
        print(f"[{str(check.result):<7}] {check.name}")
        print(f"          {check.summary}")
        if check.remedy:
            print(f"          -> {check.remedy}")
    print("-" * width)
    print(
        f"{report.passed} passed, {report.warnings} warning(s), "
        f"{report.failures} failure(s)."
    )
    print(
        "System is ready." if report.is_ready
        else "System is NOT ready - resolve the failures above."
    )
    print("=" * width)


def _print_json(report) -> None:
    """Print the diagnostics report as JSON."""
    print(json.dumps(
        {
            "application": APP_NAME,
            "version": APP_VERSION,
            "generated_at": report.generated_at.isoformat(),
            "ready": report.is_ready,
            "passed": report.passed,
            "warnings": report.warnings,
            "failures": report.failures,
            "checks": [
                {
                    "name": check.name,
                    "result": str(check.result),
                    "summary": check.summary,
                    "remedy": check.remedy,
                }
                for check in report.checks
            ],
        },
        indent=2,
    ))


def main(argv: Sequence[str] | None = None) -> int:
    """Start the services, run the diagnostics and report the outcome."""
    arguments = _parse_arguments(argv)
    settings = load_settings()
    configure_logging(settings.log_dir, "ERROR" if arguments.json else settings.log_level)

    context = ApplicationContext(settings)
    context.start(run_migrations_on_start=False)
    try:
        if context.health is None:
            print(
                "Diagnostics unavailable: the service layer did not start. "
                "Check the database configuration in .env.",
                file=sys.stderr,
            )
            return 2

        report = context.health.run_diagnostics()
        if arguments.json:
            _print_json(report)
        else:
            _print_text(report, arguments.quiet)
        return 0 if report.is_ready else 1
    finally:
        context.shutdown("health check complete")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
