"""Explain why the Snort ingest is in the state it is in.

    python scripts/check_snort_config.py

"SNORT DISABLED" on the header means the application resolved the transport to
``disabled``. That can happen for several reasons which look identical from the
interface, and editing ``.env`` again does not distinguish between them:

* the ``.env`` file is not where the application looks for it;
* it is named ``.env.txt`` - Explorer hides known extensions, so a file saved
  from Notepad as "``.env``" routinely is not one;
* a **real environment variable** is shadowing the file. The loader uses
  ``override=False`` deliberately, so a value already in the environment wins
  over the file. That is correct for deployment and baffling at a desk;
* the file was edited after the application started; ``.env`` is read once.

This script reports what is actually true of each of those, and needs no
database and no running application.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aethra_sec.config.environment import (  # noqa: E402
    load_env_file,
    loaded_env_file,
    project_root,
)

#: Keys that decide whether the ingest runs, in the order they matter.
SNORT_KEYS = (
    "AETHRA_SNORT_TRANSPORT",
    "AETHRA_SNORT_ALERT_FILE",
    "AETHRA_SNORT_SOCKET_PATH",
    "AETHRA_SNORT_TCP_HOST",
    "AETHRA_SNORT_TCP_PORT",
    "AETHRA_SNORT_SYSLOG_HOST",
    "AETHRA_SNORT_SYSLOG_PORT",
    "AETHRA_SNORT_PATH",
    "AETHRA_SNORT_CONFIG",
)


def _pre_existing() -> dict[str, str]:
    """Snort keys already in the real environment, before ``.env`` is read."""
    return {key: os.environ[key] for key in SNORT_KEYS if key in os.environ}


def _report_env_file(root: Path) -> Path | None:
    """Say which .env file was found, or what was found instead."""
    expected = root / ".env"
    print(f"Project root : {root}")

    if expected.is_file():
        print(f".env         : found ({expected})")
        return expected

    print(f".env         : NOT FOUND at {expected}")
    # The single most common cause on Windows, worth naming precisely.
    lookalikes = sorted(
        path.name
        for path in root.glob(".env*")
        if path.is_file() and path.name != ".env"
    )
    if lookalikes:
        print(f"               but these exist: {', '.join(lookalikes)}")
        if ".env.txt" in lookalikes:
            print(
                "               -> '.env.txt' is the file you edited. Explorer\n"
                "                  hides known extensions, so Notepad saved it\n"
                "                  with .txt appended. Rename it to '.env'."
            )
        elif ".env.example" in lookalikes:
            print(
                "               -> only the template is here. Copy it:\n"
                "                     copy .env.example .env\n"
                "                  then edit '.env', not '.env.example'."
            )
    return None


def _report_raw_lines(env_path: Path) -> None:
    """Show every Snort line in the file, with duplicates called out."""
    print("\nSnort lines in .env:")
    seen: dict[str, int] = {}
    found = False
    for number, raw in enumerate(
        env_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw.strip()
        if not line or line.startswith("#") or "SNORT" not in line.upper():
            continue
        key = line.partition("=")[0].strip()
        found = True
        repeat = ""
        if key in seen:
            repeat = f"   <-- also set on line {seen[key]}; this later one wins"
        seen[key] = number
        print(f"  {number:>4}: {line}{repeat}")
    if not found:
        print("  (none - the file sets no AETHRA_SNORT_* key at all)")


def _report_shadowing(pre_existing: dict[str, str], env_path: Path | None) -> bool:
    """Report real environment variables that override the file.

    Returns True when something is being shadowed, because that is the one
    cause where editing ``.env`` cannot possibly help.
    """
    if not pre_existing:
        return False
    print("\nReal environment variables set BEFORE .env was read:")
    shadowed = False
    file_keys: set[str] = set()
    if env_path is not None:
        for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                file_keys.add(line.partition("=")[0].strip())
    for key, value in pre_existing.items():
        clash = key in file_keys
        shadowed = shadowed or clash
        note = "   <-- OVERRIDES .env" if clash else ""
        print(f"  {key}={value}{note}")
    if shadowed:
        print(
            "\n  These win over .env by design, so the file is being ignored for\n"
            "  those keys. Clear them in this shell and start again:\n"
            "     set AETHRA_SNORT_TRANSPORT=          (Windows cmd)\n"
            "  or remove them from the system environment."
        )
    return shadowed


def main() -> int:
    """Print the diagnosis and return an exit code."""
    print("=" * 70)
    print("AETHRA-SEC - why is the Snort ingest in this state?")
    print("=" * 70)

    pre_existing = _pre_existing()
    root = project_root()
    env_path = _report_env_file(root)

    if env_path is not None:
        _report_raw_lines(env_path)

    load_env_file()
    loaded = loaded_env_file()
    print(f"\nLoaded by app: {loaded if loaded else 'nothing'}")

    shadowed = _report_shadowing(pre_existing, env_path)

    from aethra_sec.config.settings import load_settings

    snort = load_settings().snort
    print("\n" + "-" * 70)
    print(f"Resolved transport : {snort.transport}")
    print(f"Ingest enabled     : {snort.enabled}")
    print(f"Description        : {snort.describe()}")
    print("-" * 70)

    if not snort.enabled:
        print("\nRESULT: the ingest is DISABLED, which is what the header shows.")
        if env_path is None:
            print("Cause  : no .env file was found - see above.")
        elif shadowed:
            print("Cause  : a real environment variable is overriding .env.")
        else:
            print(
                "Cause  : .env was read but AETHRA_SNORT_TRANSPORT is still\n"
                "         'disabled'. Check the spelling of the key and that the\n"
                "         value is one of: unixsock, file, tcp, syslog."
            )
        return 1

    if snort.transport == "file":
        target = snort.alert_file
        print(f"\nAlert file         : {target}")
        if target is None:
            print("  -> AETHRA_SNORT_ALERT_FILE is not set. The ingest has")
            print("     nothing to tail.")
            return 1
        if Path(target).is_file():
            size = Path(target).stat().st_size
            print(f"  -> exists, {size} bytes")
            if size == 0:
                print("     Empty is normal until Snort's first alert fires.")
        else:
            print("  -> DOES NOT EXIST YET.")
            print("     Snort creates it on its first alert, so this is expected")
            print("     if Snort has not matched anything. To let AETHRA-SEC")
            print("     attach and wait, create it once:")
            print(f"        type nul > {target}")
            # The bell-character trap has no other symptom than this.
            if "\x07" in str(target) or "\x08" in str(target):
                print("\n     WARNING: this path contains a control character.")
                print("     You almost certainly wrapped it in DOUBLE QUOTES in")
                print("     .env, where \\a and \\b are escape sequences. Remove")
                print("     the quotes - write the path bare.")

    print("\nRESULT: configuration looks correct. If the header still reads")
    print("DISABLED, the application was started before .env was edited -")
    print("restart it, because .env is read once at startup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
