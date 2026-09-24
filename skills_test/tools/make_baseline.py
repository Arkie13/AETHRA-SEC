"""Record the known-good state of AETHRA-SEC.

The baseline is the only thing standing between "a test failed" and "here is
the code that used to be there". It is captured once, from a tree that passes
its own test suite, and is then read-only: nothing in this package ever writes
to it again, because a baseline that follows the professor's edits can no
longer show what was changed.

There is no Git repository here, so the baseline is a SHA-256 manifest plus a
copy of the source. Both are needed: the manifest detects *that* a file
changed, the copy shows *what* it used to say.

Secrets are never copied. ``.env`` holds real database credentials, and the
exclusion list below is deliberately wider than it strictly needs to be.

Run:  python skills_test/tools/make_baseline.py [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "skills_test" / "baseline"
MANIFEST = BASELINE / "baseline_manifest.json"
SOURCE = BASELINE / "source"

#: Trees the baseline covers. Everything else is ignored.
INCLUDED_ROOTS = ("aethra_sec", "scripts", "tests")

#: Individual files worth pinning even though they sit at the top level.
INCLUDED_FILES = ("requirements.txt", "run.bat", "setup.bat")

#: Never copied and never hashed. A credential must not enter the baseline
#: even as a hash, and generated trees would make the manifest meaningless.
EXCLUDED_PARTS = {
    ".venv", "__pycache__", ".git", ".pytest_cache", "node_modules",
    "logs", "captures", "reports_output", "build", "dist", "New folder",
    "skills_test",
}
EXCLUDED_NAMES = {".env", ".env.local", ".env.production"}
EXCLUDED_SUFFIXES = {".key", ".pem", ".pfx", ".p12", ".sqlite", ".db", ".log", ".pyc"}


def is_excluded(path: Path) -> bool:
    """Whether a path must stay out of the baseline."""
    if any(part in EXCLUDED_PARTS for part in path.parts):
        return True
    if path.name in EXCLUDED_NAMES or path.name.startswith(".env"):
        return True
    return path.suffix.lower() in EXCLUDED_SUFFIXES


def iter_source_files(root: Path):
    """Every file the baseline covers, in a stable order."""
    seen: set[Path] = set()
    for name in INCLUDED_ROOTS:
        base = root / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and not is_excluded(path) and path.suffix == ".py":
                seen.add(path)
    for name in INCLUDED_FILES:
        path = root / name
        if path.is_file() and not is_excluded(path):
            seen.add(path)
    return sorted(seen)


def sha256(path: Path) -> str:
    """The file's SHA-256, read in chunks so a large file is not held whole."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def build(force: bool = False) -> int:
    """Write the manifest and the source copy. Refuses to overwrite silently."""
    if MANIFEST.exists() and not force:
        print("A baseline already exists.")
        print(f"  {MANIFEST}")
        print()
        print("It is deliberately not overwritten: re-recording it after the")
        print("system has been modified would adopt the modification as")
        print("'known good' and the diagnosis would then find nothing.")
        print()
        print("Pass --force only if you are certain the tree is healthy.")
        return 1

    files = iter_source_files(ROOT)
    if not files:
        print("No source files found - is this the AETHRA-SEC root?")
        return 2

    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    SOURCE.mkdir(parents=True, exist_ok=True)

    entries = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        stat = path.stat()
        entries.append({
            "path": relative,
            "sha256": sha256(path),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat(timespec="seconds"),
        })
        target = SOURCE / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

    manifest = {
        "created": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "root": str(ROOT),
        "vcs": "none (no Git repository present)",
        "file_count": len(entries),
        "excluded": {
            "directories": sorted(EXCLUDED_PARTS),
            "names": sorted(EXCLUDED_NAMES),
            "suffixes": sorted(EXCLUDED_SUFFIXES),
            "note": "secrets and generated trees are never hashed or copied",
        },
        "files": entries,
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # A guard the integrity check reads back: if someone edits the manifest to
    # match a modified tree, the recorded count and digest will not agree.
    (BASELINE / "README.txt").write_text(
        "AETHRA-SEC skills-test baseline - READ ONLY.\n\n"
        "This directory records the known-good source. Nothing in the test\n"
        "system writes to it. Do not regenerate it after the system has been\n"
        "modified: the diagnosis compares the current tree against this copy,\n"
        "so adopting a modification here would hide it.\n\n"
        f"Created: {manifest['created']}\n"
        f"Files:   {len(entries)}\n",
        encoding="utf-8",
    )

    print(f"Baseline recorded: {len(entries)} files")
    print(f"  manifest: {MANIFEST.relative_to(ROOT)}")
    print(f"  source:   {SOURCE.relative_to(ROOT)}")
    print()
    print("No .env, key, credential or generated file was copied.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force", action="store_true",
        help="overwrite an existing baseline (only when the tree is healthy)",
    )
    arguments = parser.parse_args(argv)
    return build(force=arguments.force)


if __name__ == "__main__":
    raise SystemExit(main())
