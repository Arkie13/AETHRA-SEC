"""AETHRA-SEC entry point (§74).

    python -m aethra_sec.main            start the desktop console
    python -m aethra_sec.main --check    run diagnostics and exit
    python -m aethra_sec.main --headless start services without the interface

The application always starts, even when a subsystem is unusable: the login
window and the System Health screen report exactly what is wrong instead of the
process dying with a traceback (§58).
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from aethra_sec.config.settings import load_settings
from aethra_sec.core.application import ApplicationContext
from aethra_sec.utils.logging import configure_logging, get_logger
from aethra_sec.version import APP_FULL_NAME, APP_NAME, APP_VERSION

LOGGER = get_logger("main")


def _parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="aethra-sec",
        description=APP_FULL_NAME,
        epilog=(
            "AETHRA-SEC must only be operated against networks you are "
            "authorised to monitor or assess."
        ),
    )
    parser.add_argument(
        "--check", action="store_true",
        help="run diagnostics, print the result and exit",
    )
    parser.add_argument(
        "--headless", action="store_true",
        help="start the services without the desktop interface",
    )
    parser.add_argument(
        "--no-migrate", action="store_true",
        help="do not create or migrate the database schema on start",
    )
    parser.add_argument(
        "--version", action="version", version=f"{APP_NAME} {APP_VERSION}"
    )
    return parser.parse_args(argv)


def run_diagnostics(context: ApplicationContext) -> int:
    """Print the diagnostics report and return a process exit code."""
    if context.health is None:
        print("Diagnostics unavailable: services did not initialise.")
        return 2

    report = context.health.run_diagnostics()
    width = 78
    print("=" * width)
    print(f"{APP_NAME} {APP_VERSION} - system diagnostics")
    print("=" * width)
    for check in report.checks:
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
    return 0 if report.is_ready else 1


def run_headless(context: ApplicationContext) -> int:
    """Run the services without a user interface until interrupted."""
    import time

    print(f"{APP_NAME} {APP_VERSION} running headless. Press Ctrl+C to stop.")
    if context.health is not None:
        for name, status in context.health.probe_all().items():
            print(f"  {name:<12} {status.display_state:<12} {status.detail}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Start AETHRA-SEC."""
    arguments = _parse_arguments(argv)
    settings = load_settings()
    configure_logging(settings.log_dir, settings.log_level)

    context = ApplicationContext(settings)
    report = context.start(run_migrations_on_start=not arguments.no_migrate)

    for error in report.errors:
        LOGGER.error("Startup error: %s", error)
    for warning in report.warnings:
        LOGGER.warning("Startup warning: %s", warning)

    try:
        if arguments.check:
            return run_diagnostics(context)
        if arguments.headless:
            return run_headless(context)
        return _run_desktop(context)
    finally:
        context.shutdown("process exit")


def _run_desktop(context: ApplicationContext) -> int:
    """Show the login window and, on success, the console."""
    try:
        import tkinter  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        print(
            "The desktop interface needs Tkinter, which is not available in "
            f"this Python installation ({exc}).\n"
            "On Windows, reinstall Python with the 'tcl/tk and IDLE' option.\n"
            "On Debian/Ubuntu: sudo apt-get install python3-tk\n"
            "Use --check or --headless to run without the interface.",
            file=sys.stderr,
        )
        return 2

    from aethra_sec.ui import dispatch
    from aethra_sec.ui.app import run_console
    from aethra_sec.ui.login import prepare_root, prompt_login

    # One Tk root, one process, for the whole session. The loop lets an operator
    # sign out and hand the console to another account without restarting: the
    # database pool and the background services stay up between sign-ins.
    root, fonts = prepare_root(context)
    try:
        while True:
            session = prompt_login(root, context, fonts)
            if session is None:
                LOGGER.info("Sign-in cancelled; exiting.")
                break
            outcome = run_console(root, context, fonts, session)
            if outcome != "sign out":
                break
            LOGGER.info("Operator signed out; returning to the login window.")
    finally:
        dispatch.shutdown()
        try:
            root.destroy()
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
