"""Console setup, for ``setup.bat`` and for headless installs.

This is the same setup as the graphical wizard, asked as questions instead of
drawn as a form. It shares every piece of logic with it - the same detection
probes, the same configuration writer, the same database provisioning, the same
administrator creation and the same health report - so a machine set up from the
command line ends up identical to one set up from the window.

Passwords are read with :func:`getpass.getpass` and never echoed, never printed
back and never written anywhere except into the Argon2id hash (the account
password) or the configuration file (the database and SMTP passwords).

Run it with ``--defaults`` to accept every suggested answer without prompting,
which is what an unattended reinstall needs.
"""

from __future__ import annotations

import argparse
import getpass
from collections.abc import Sequence
from pathlib import Path

from aethra_sec.config import paths
from aethra_sec.config.settings import load_settings
from aethra_sec.setup import configfile, detection, provisioning
from aethra_sec.setup.healthcheck import run_health_check
from aethra_sec.setup.interfaces import detect_interfaces, monitoring_position_note
from aethra_sec.version import APP_NAME, APP_VERSION

RULE = "=" * 62


def _say(text: str = "") -> None:
    """Print a line, tolerating a console that cannot encode it."""
    try:
        print(text)
    except UnicodeEncodeError:  # pragma: no cover - legacy code page
        print(text.encode("ascii", "replace").decode("ascii"))


def _heading(title: str) -> None:
    """A section heading."""
    _say()
    _say(RULE)
    _say(f"  {title}")
    _say(RULE)


def _ask(label: str, default: str = "", *, assume: bool = False) -> str:
    """Read one visible answer, offering a default."""
    suffix = f" [{default}]" if default else ""
    if assume:
        _say(f"  {label}{suffix}: {default}")
        return default
    answer = input(f"  {label}{suffix}: ").strip()
    return answer or default


def _ask_secret(label: str) -> str:
    """Read one answer without echoing it."""
    return getpass.getpass(f"  {label}: ")


def _ask_yes_no(question: str, default: bool = False, *, assume: bool = False) -> bool:
    """Read a yes/no answer."""
    suffix = "[Y/n]" if default else "[y/N]"
    if assume:
        _say(f"  {question} {suffix}: {'y' if default else 'n'}")
        return default
    while True:
        answer = input(f"  {question} {suffix}: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        _say("    Answer y or n.")


def _report_probe(probe: detection.ProbeResult) -> None:
    """Print one probe result and the steps behind it."""
    _say(f"  [{probe.status:<4}] {probe.name}")
    _say(f"         {probe.detail}")
    for step in probe.evidence:
        _say(f"           - {step}")
    if probe.remedy:
        _say(f"         -> {probe.remedy}")


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def _step_admin(existing_admins: Sequence[str], assume: bool) -> tuple[str, str, str]:
    """Collect the administrator's username, password and email.

    Returns ``("", "", "")`` when an administrator already exists and the
    operator chose not to add another - which is the safe answer, because an
    existing administrator is never overwritten.
    """
    _heading("STEP 1 of 7 - ADMINISTRATOR ACCOUNT")
    if existing_admins:
        _say(f"  An administrator already exists: {', '.join(existing_admins)}")
        _say("  Existing accounts keep their password and their email address.")
        if not _ask_yes_no("Create an additional administrator?", False, assume=assume):
            return "", "", ""

    _say("  Sign-in is a username and a password. There is no second factor and")
    _say("  no login code is ever emailed. The password is stored as an Argon2id")
    _say("  hash; the plaintext is never written anywhere.")
    _say()

    while True:
        username = _ask("Admin username")
        password = _ask_secret("Admin password")
        confirm = _ask_secret("Confirm admin password")
        email = _ask("Admin email address")
        problem = provisioning.validate_admin_input(username, password, confirm, email)
        if not problem:
            return username, password, email
        _say(f"    {problem}")
        if assume:
            return "", "", ""


def _step_database(config: configfile.ConfigFile, assume: bool) -> dict[str, str]:
    """Collect and test the database connection."""
    _heading("STEP 2 of 7 - DATABASE")
    _say("  MySQL or MariaDB. XAMPP users: start MySQL first; the default")
    _say("  account is 'root' with an empty password.")
    _say()
    values = {
        "host": _ask("Database host", config.get("AETHRA_DB_HOST", "127.0.0.1"), assume=assume),
        "port": _ask("Database port", config.get("AETHRA_DB_PORT", "3306"), assume=assume),
        "name": _ask("Database name", config.get("AETHRA_DB_NAME", "aethra_sec"), assume=assume),
        "user": _ask("Database user", config.get("AETHRA_DB_USER", "root"), assume=assume),
    }
    if assume:
        values["password"] = config.get("AETHRA_DB_PASSWORD", "")
        _say("  Database password: (kept from the existing configuration)")
    else:
        values["password"] = _ask_secret("Database password (blank for none)")
    return values


def _step_tools(config: configfile.ConfigFile, assume: bool) -> dict[str, str]:
    """Detect and verify the security tools."""
    _heading("STEP 3 of 7 - SECURITY TOOLS")
    _say("  Each tool is run, not merely located. This takes a few seconds.")
    _say()

    nmap_path = _ask("Nmap executable (blank = discover)", config.get("AETHRA_NMAP_PATH", ""), assume=assume)
    tshark_path = _ask("TShark executable (blank = discover)", config.get("AETHRA_TSHARK_PATH", ""), assume=assume)
    snort_path = _ask("Snort executable (blank = discover)", config.get("AETHRA_SNORT_PATH", ""), assume=assume)
    snort_config = _ask("Snort configuration (blank = none)", config.get("AETHRA_SNORT_CONFIG", ""), assume=assume)

    _say()
    probes = [
        detection.probe_nmap(Path(nmap_path) if nmap_path else None),
        detection.probe_tshark(Path(tshark_path) if tshark_path else None),
        detection.probe_pyshark(),
        detection.probe_snort(
            Path(snort_path) if snort_path else None,
            Path(snort_config) if snort_config else None,
        ),
        detection.probe_npcap(),
    ]
    for probe in probes:
        _report_probe(probe)

    # Pin what was verified, so the next start uses the tool that was tested.
    return {
        "nmap_path": nmap_path or probes[0].path,
        "tshark_path": tshark_path or probes[1].path,
        "snort_path": snort_path or probes[3].path,
        "snort_config": snort_config,
        "snort_transport": _ask(
            "Snort alert ingest (disabled/file/tcp/syslog/unixsock)",
            config.get("AETHRA_SNORT_TRANSPORT", "disabled"), assume=assume,
        ),
        "snort_alert_file": _ask(
            "Snort alert file (for the 'file' transport)",
            config.get("AETHRA_SNORT_ALERT_FILE", ""), assume=assume,
        ),
    }


def _step_interface(tshark_path: str, config: configfile.ConfigFile, assume: bool):
    """List the real interfaces and let the operator choose one."""
    _heading("STEP 4 of 7 - NETWORK INTERFACE")
    report = detect_interfaces(Path(tshark_path) if tshark_path else None)

    if not report.interfaces:
        _say("  No network interfaces were detected.")
        for warning in report.warnings:
            _say(f"  WARNING: {warning}")
        return "", report

    for index, item in enumerate(report.interfaces, start=1):
        marker = " <- recommended" if item is report.recommended else ""
        _say(f"  {index:2d}. {item.display_label}{marker}")
        if item.subnet:
            _say(f"      subnet {item.subnet}   gateway {item.gateway or 'none'}   "
                 f"mac {item.mac or 'unknown'}")
    _say()
    if report.reason:
        _say(f"  {report.reason}")
    for warning in report.warnings:
        _say(f"  WARNING: {warning}")
    _say()

    default_index = "1"
    configured = config.get("AETHRA_CAPTURE_INTERFACE", "")
    for index, item in enumerate(report.interfaces, start=1):
        if item.name == configured or item is report.recommended:
            default_index = str(index)
            if item.name == configured:
                break

    while True:
        answer = _ask("Interface number (0 to choose later in the app)", default_index, assume=assume)
        if answer == "0":
            return "", report
        try:
            chosen = report.interfaces[int(answer) - 1]
        except (ValueError, IndexError):
            _say("    Enter one of the numbers listed above.")
            if assume:
                return "", report
            continue
        _say()
        _say(f"  {monitoring_position_note(chosen)}")
        return chosen.name, report


def _step_email(config: configfile.ConfigFile, admin_email: str, assume: bool) -> dict[str, str]:
    """Collect the optional SMTP settings and offer a real delivery test."""
    _heading("STEP 5 of 7 - EMAIL NOTIFICATIONS (OPTIONAL)")
    _say("  Email carries notifications only. Sign-in never uses it, so leaving")
    _say("  this empty costs nothing but the notifications.")
    _say("  Gmail: smtp.gmail.com, port 587, STARTTLS, and a 16-character App")
    _say("  Password rather than the account password.")
    _say()

    settings: dict[str, str] = {
        "smtp_host": "", "smtp_port": "587", "smtp_user": "",
        "smtp_password": "", "smtp_from": "", "smtp_to": "",
        "smtp_starttls": "true",
    }
    if not _ask_yes_no("Configure email notifications now?", bool(config.get("AETHRA_SMTP_HOST")), assume=assume):
        _say("  Skipped. SMTP NOT CONFIGURED.")
        return settings

    settings["smtp_host"] = _ask("SMTP host", config.get("AETHRA_SMTP_HOST", "smtp.gmail.com"), assume=assume)
    settings["smtp_port"] = _ask("SMTP port", config.get("AETHRA_SMTP_PORT", "587"), assume=assume)
    settings["smtp_user"] = _ask("SMTP username", config.get("AETHRA_SMTP_USER", ""), assume=assume)
    settings["smtp_password"] = (
        config.get("AETHRA_SMTP_PASSWORD", "") if assume
        else _ask_secret("SMTP password (not echoed)")
    )
    settings["smtp_from"] = _ask("Sender address", config.get("AETHRA_SMTP_FROM", "") or settings["smtp_user"], assume=assume)
    settings["smtp_to"] = _ask("Notify address", config.get("AETHRA_SMTP_TO", "") or admin_email, assume=assume)
    settings["smtp_starttls"] = "true" if settings["smtp_port"] != "465" else "false"
    return settings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    """Run console setup. Returns a process exit code."""
    parser = argparse.ArgumentParser(
        prog="aethra-sec-setup",
        description=f"{APP_NAME} first-run setup (console).",
    )
    parser.add_argument(
        "--defaults", action="store_true",
        help="accept every suggested answer without prompting",
    )
    parser.add_argument(
        "--check-only", action="store_true",
        help="run the health check against the current configuration and exit",
    )
    arguments = parser.parse_args(argv)
    assume = bool(arguments.defaults)

    paths.ensure_data_dirs()

    _say(RULE)
    _say(f"  {APP_NAME} {APP_VERSION} - SETUP")
    _say(RULE)
    _say(f"  Configuration file : {paths.config_file()}")
    _say(f"  Application data   : {paths.data_dir()}")

    if arguments.check_only:
        settings = load_settings()
        _say()
        _say(run_health_check(settings).render())
        return 0

    config = configfile.load()

    existing_admins: tuple[str, ...] = ()
    if config.exists:
        existing_admins = provisioning.existing_administrators(load_settings().database)

    username, password, email = _step_admin(existing_admins, assume)
    database = _step_database(config, assume)
    tools = _step_tools(config, assume)
    interface, _report = _step_interface(tools["tshark_path"], config, assume)
    smtp = _step_email(config, email, assume)

    # ---- apply ------------------------------------------------------------
    _heading("STEP 6 of 7 - APPLYING AND CHECKING")
    try:
        port = int(database["port"])
    except ValueError:
        port = 3306
    try:
        smtp_port = int(smtp["smtp_port"])
    except ValueError:
        smtp_port = 587

    values = configfile.build_values(
        db_host=database["host"],
        db_port=port,
        db_name=database["name"],
        db_user=database["user"],
        db_password=database["password"],
        nmap_path=tools["nmap_path"],
        tshark_path=tools["tshark_path"],
        snort_path=tools["snort_path"],
        snort_config=tools["snort_config"],
        snort_transport=tools["snort_transport"],
        snort_alert_file=tools["snort_alert_file"],
        capture_interface=interface,
        authorized_networks=config.get(
            "AETHRA_AUTHORIZED_NETWORKS",
            "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8",
        ),
        smtp_host=smtp["smtp_host"],
        smtp_port=smtp_port,
        smtp_user=smtp["smtp_user"],
        smtp_password=smtp["smtp_password"],
        smtp_from=smtp["smtp_from"],
        smtp_to=smtp["smtp_to"] or email,
        smtp_starttls=smtp["smtp_starttls"] == "true",
    )

    try:
        written = configfile.write(values)
    except OSError as exc:
        _say(f"  [FAIL] The configuration could not be written: {exc}")
        return 2
    _say(f"  [ OK ] Configuration written to {written}")
    restricted, detail = configfile.permissions_are_restricted(written)
    _say(f"  [{' OK ' if restricted else 'WARN'}] Permissions: {detail}")

    settings = load_settings(written)

    provision = provisioning.prepare_database(settings.database)
    _say(f"  [{' OK ' if provision.ok else 'FAIL'}] Database: {provision.detail}")
    if provision.preserved_rows:
        kept = ", ".join(f"{n}={c}" for n, c in provision.preserved_rows.items())
        _say(f"         Existing records kept: {kept}")
    if not provision.ok:
        if provision.remedy:
            _say(f"         -> {provision.remedy}")
        return 2

    if username:
        admin = provisioning.create_administrator(
            settings.database, username, password, email,
            allow_additional=bool(existing_admins),
        )
        del password
        _say(f"  [{' OK ' if admin.ok else 'FAIL'}] Administrator: {admin.detail}")
        if not admin.ok:
            return 2

    _say()
    _say(run_health_check(settings, selected_interface=interface).render())

    _heading("STEP 7 of 7 - FINISHED")
    _say(f"  Sign in as         : {username or (existing_admins[0] if existing_admins else '(existing account)')}")
    _say("  Sign-in method     : username and password (no second factor)")
    _say(f"  Logs               : {paths.log_dir()}")
    _say(f"  Reports            : {paths.report_dir()}")
    _say()
    _say("  Start AETHRA-SEC from the desktop shortcut, or with run.bat.")
    _say()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
