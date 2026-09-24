"""AETHRA-SEC entry point (§74).

    python -m aethra_sec.main            start the desktop console
    python -m aethra_sec.main --check    run diagnostics and exit
    python -m aethra_sec.main --headless start services without the interface
    python -m aethra_sec.main --setup    run the first-run setup wizard

The packaged ``AETHRA-SEC.exe`` runs exactly this, so a shortcut, a terminal and
a developer checkout all take the same path.

The application always starts, even when a subsystem is unusable: the login
window and the System Health screen report exactly what is wrong instead of the
process dying with a traceback (§58). :mod:`aethra_sec.runtime` is installed
before anything else so that promise also holds in a windowed build, where the
process has no console for a traceback to go to.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from aethra_sec import runtime
from aethra_sec.config import paths
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
        "--setup", action="store_true",
        help="run the first-run setup wizard, even if already configured",
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

    # Before anything else: a packaged build has no console, and an exception
    # written to a stream that is None takes the process with it.
    runtime.ensure_streams()
    paths.ensure_data_dirs()

    settings = load_settings()
    configure_logging(settings.log_dir, settings.log_level)
    runtime.install()
    LOGGER.info(
        "%s %s starting (%s).", APP_NAME, APP_VERSION, paths.describe()["mode"]
    )

    if not (arguments.check or arguments.headless):
        outcome = _run_setup_if_needed(force=arguments.setup)
        if outcome is not None:
            return outcome
        # Setup writes the configuration file this process has already read,
        # so the settings are re-read before the services are built.
        settings = load_settings()

    # Before any service starts: a second console would run a second assessment
    # queue and a second Snort ingest against the same database. Diagnostics
    # are short-lived and read-only, so --check may run beside a console.
    if not arguments.check:
        from aethra_sec.core import single_instance

        if not single_instance.acquire(settings.log_dir):
            return _report_already_running(headless=arguments.headless)

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


#: Exit code when another console already holds the single-instance lock.
EXIT_ALREADY_RUNNING = 3


def _report_already_running(*, headless: bool) -> int:
    """Tell the operator another console is running, then exit."""
    message = (
        f"{APP_NAME} is already running on this computer. Use the open console "
        "window - a second copy would start a second assessment queue and a "
        "second Snort ingest against the same database."
    )
    LOGGER.warning("Start refused: another %s console is already running.", APP_NAME)
    if headless:
        print(message, file=sys.stderr)
        return EXIT_ALREADY_RUNNING
    try:
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        messagebox.showinfo(APP_NAME, message, parent=root)
        root.destroy()
    except Exception:  # noqa: BLE001 - the log line above still records it
        print(message, file=sys.stderr)
    return EXIT_ALREADY_RUNNING


def _run_setup_if_needed(force: bool = False) -> int | None:
    """Show the setup wizard when this installation is not configured yet.

    Returns:
        ``None`` to carry on starting the application, or a process exit code
        when the operator cancelled setup. Cancelling before anything was
        applied leaves the machine untouched, and starting an unconfigured
        application would only produce a login window that cannot reach a
        database - so that case exits instead of pretending.
    """
    from aethra_sec.setup.wizard import setup_is_required

    if not force and not setup_is_required():
        return None

    try:
        import tkinter  # noqa: F401
    except Exception:  # noqa: BLE001
        print(
            "This installation has not been configured yet and the graphical "
            "setup needs Tkinter, which is unavailable here.\n"
            "Run the console setup instead:  python -m aethra_sec.setup.console",
            file=sys.stderr,
        )
        return 2

    LOGGER.info("Configuration not found; starting the first-run setup wizard.")
    from aethra_sec.setup.wizard import run_wizard

    if not run_wizard():
        LOGGER.info("Setup was cancelled before anything was applied.")
        return 0
    LOGGER.info("Setup completed; continuing to start the application.")
    return None


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
