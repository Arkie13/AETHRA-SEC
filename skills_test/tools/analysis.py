"""Compare the current tree against the baseline, structurally.

A hash tells you a file changed; it does not tell you what to paste back.
This module works at the level the student repairs at - the function - so the
diagnosis can name a file, a function, and the exact lines that differ.

Everything here is read-only. Nothing in this package writes to
``aethra_sec/`` or to ``skills_test/baseline/``.

The detections implemented, in the order they are worth trusting:

* a **deleted file** or a **missing function** - unambiguous;
* a **changed signature** - unambiguous;
* a **body that became a stub** where the baseline had an implementation;
* a **baseline call that is now commented out**;
* a **missing import** the current file still needs;
* any **other body change**, reported as a line diff.

None of these on its own proves a bug: a legitimate edit looks the same. They
are evidence, and the behavioural tests are what decide.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "skills_test" / "baseline"
MANIFEST = BASELINE / "baseline_manifest.json"
SOURCE = BASELINE / "source"


# ---------------------------------------------------------------------------
# Reading the two trees
# ---------------------------------------------------------------------------
def load_manifest() -> dict:
    """The recorded baseline, or an empty manifest when none exists."""
    if not MANIFEST.exists():
        return {}
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def sha256_text(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def read(path: Path) -> str:
    """A file's text, or ``""`` when it cannot be read."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


# ---------------------------------------------------------------------------
# Function-level model
# ---------------------------------------------------------------------------
@dataclass
class Function:
    """One function or method, with the text needed to show it back."""

    qualname: str
    signature: str
    source: str
    lineno: int
    end_lineno: int
    body_is_stub: bool
    decorators: tuple[str, ...] = ()


def _signature(node: ast.AST) -> str:
    """The def line as written, normalised to one line."""
    try:
        args = ast.unparse(node.args)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - older ast, exotic syntax
        args = "..."
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{prefix} {node.name}({args})"  # type: ignore[attr-defined]


def _is_stub(node: ast.AST) -> bool:
    """A body that does nothing: ``pass``, a bare ``return``, or ``return None``.

    A docstring does not count as doing something, so it is stripped first.
    """
    body = list(node.body)  # type: ignore[attr-defined]
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body:
        return True
    if len(body) != 1:
        return False
    only = body[0]
    if isinstance(only, ast.Pass):
        return True
    if isinstance(only, ast.Return):
        return only.value is None or (
            isinstance(only.value, ast.Constant) and only.value.value is None
        )
    if isinstance(only, ast.Raise):
        # `raise NotImplementedError` is a stub too.
        name = getattr(getattr(only.exc, "func", only.exc), "id", "")
        return name == "NotImplementedError"
    return False


def functions_in(source: str) -> dict[str, Function]:
    """Every function and method in a module, keyed by qualified name."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    lines = source.splitlines()
    found: dict[str, Function] = {}

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min(
                    [child.lineno] + [d.lineno for d in child.decorator_list]
                )
                end = child.end_lineno or child.lineno
                found[f"{prefix}{child.name}"] = Function(
                    qualname=f"{prefix}{child.name}",
                    signature=_signature(child),
                    source="\n".join(lines[start - 1:end]),
                    lineno=start,
                    end_lineno=end,
                    body_is_stub=_is_stub(child),
                    decorators=tuple(
                        ast.unparse(d) for d in child.decorator_list
                    ),
                )
                walk(child, f"{prefix}{child.name}.")

    walk(tree, "")
    return found


def imports_in(source: str) -> set[str]:
    """Every name an ``import`` statement binds in this module."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """One structural difference from the baseline."""

    kind: str          # DELETED_FILE | MISSING_FUNCTION | SIGNATURE_CHANGED | ...
    path: str
    qualname: str = ""
    detail: str = ""
    baseline_code: str = ""
    current_code: str = ""
    diff: str = ""
    severity: str = "INFO"   # CRITICAL | WARNING | INFO

    def title(self) -> str:
        where = f"{self.path}" + (f" :: {self.qualname}" if self.qualname else "")
        return f"[{self.kind}] {where}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    added_files: list[str] = field(default_factory=list)
    unchanged: int = 0
    baseline_missing: bool = False

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]


_CALL = re.compile(r"^\s*#\s*([A-Za-z_][\w.]*\s*\(.*\)|[\w.]+\s*=\s*.+)\s*$")


def _commented_out(baseline_src: str, current_src: str) -> list[str]:
    """Baseline statements that now appear only inside a comment."""
    current_comments = [
        line.strip().lstrip("#").strip()
        for line in current_src.splitlines()
        if _CALL.match(line)
    ]
    if not current_comments:
        return []
    baseline_body = {
        line.strip() for line in baseline_src.splitlines() if line.strip()
    }
    return [c for c in current_comments if c in baseline_body]


def _diff(baseline_code: str, current_code: str, path: str, qualname: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            baseline_code.splitlines(), current_code.splitlines(),
            fromfile=f"baseline/{path}::{qualname}",
            tofile=f"current/{path}::{qualname}",
            lineterm="", n=2,
        )
    )


def compare_file(relative: str) -> list[Finding]:
    """Every structural difference in one file."""
    baseline_path = SOURCE / relative
    current_path = ROOT / relative
    findings: list[Finding] = []

    if not current_path.exists():
        findings.append(Finding(
            kind="DELETED_FILE", path=relative, severity="CRITICAL",
            detail="The file exists in the baseline but not in the current tree.",
            baseline_code=read(baseline_path),
        ))
        return findings

    baseline_src, current_src = read(baseline_path), read(current_path)
    if baseline_src == current_src:
        return findings

    # A file that no longer parses is its own diagnosis.
    try:
        ast.parse(current_src)
    except SyntaxError as exc:
        findings.append(Finding(
            kind="SYNTAX_ERROR", path=relative, severity="CRITICAL",
            detail=f"line {exc.lineno}: {exc.msg}",
            current_code="\n".join(
                current_src.splitlines()[max(0, (exc.lineno or 1) - 3):(exc.lineno or 1) + 2]
            ),
            baseline_code="",
        ))
        return findings

    base_funcs, cur_funcs = functions_in(baseline_src), functions_in(current_src)

    for qualname, baseline_fn in base_funcs.items():
        current_fn = cur_funcs.get(qualname)
        if current_fn is None:
            findings.append(Finding(
                kind="MISSING_FUNCTION", path=relative, qualname=qualname,
                severity="CRITICAL",
                detail="Present in the baseline, absent from the current file.",
                baseline_code=baseline_fn.source,
            ))
            continue
        if baseline_fn.signature != current_fn.signature:
            findings.append(Finding(
                kind="SIGNATURE_CHANGED", path=relative, qualname=qualname,
                severity="CRITICAL",
                detail=f"baseline: {baseline_fn.signature}\n"
                       f"current : {current_fn.signature}",
                baseline_code=baseline_fn.source,
                current_code=current_fn.source,
                diff=_diff(baseline_fn.source, current_fn.source, relative, qualname),
            ))
            continue
        if baseline_fn.source == current_fn.source:
            continue
        if current_fn.body_is_stub and not baseline_fn.body_is_stub:
            findings.append(Finding(
                kind="IMPLEMENTATION_REMOVED", path=relative, qualname=qualname,
                severity="CRITICAL",
                detail="The body does nothing; the baseline had an implementation.",
                baseline_code=baseline_fn.source,
                current_code=current_fn.source,
                diff=_diff(baseline_fn.source, current_fn.source, relative, qualname),
            ))
            continue
        commented = _commented_out(baseline_fn.source, current_fn.source)
        kind = "COMMENTED_OUT_LOGIC" if commented else "BODY_CHANGED"
        findings.append(Finding(
            kind=kind, path=relative, qualname=qualname,
            severity="WARNING",
            detail=("now only a comment: " + "; ".join(commented)) if commented
                   else "The body differs from the baseline.",
            baseline_code=baseline_fn.source,
            current_code=current_fn.source,
            diff=_diff(baseline_fn.source, current_fn.source, relative, qualname),
        ))

    for qualname, current_fn in cur_funcs.items():
        if qualname not in base_funcs:
            findings.append(Finding(
                kind="ADDED_FUNCTION", path=relative, qualname=qualname,
                severity="INFO",
                detail="Not in the baseline. This is only a note, not a fault.",
                current_code=current_fn.source,
            ))

    lost = imports_in(baseline_src) - imports_in(current_src)
    for name in sorted(lost):
        # Only report an import the file still refers to.
        if re.search(rf"\b{re.escape(name)}\b", current_src):
            line = next(
                (l for l in baseline_src.splitlines()
                 if re.match(rf"\s*(from .+ )?import\b.*\b{re.escape(name)}\b", l)),
                f"import {name}",
            )
            findings.append(Finding(
                kind="MISSING_IMPORT", path=relative, qualname=name,
                severity="CRITICAL",
                detail=f"{name!r} is still used in this file but no longer imported.",
                baseline_code=line.strip(),
            ))
    return findings


def compare_tree() -> Report:
    """Compare every baselined file against the current tree."""
    manifest = load_manifest()
    report = Report()
    if not manifest:
        report.baseline_missing = True
        return report

    recorded = {entry["path"]: entry for entry in manifest.get("files", [])}
    for relative, entry in sorted(recorded.items()):
        current = ROOT / relative
        if not current.exists():
            report.deleted_files.append(relative)
            report.findings.extend(compare_file(relative))
            continue
        if sha256_text(current) == entry["sha256"]:
            report.unchanged += 1
            continue
        report.changed_files.append(relative)
        report.findings.extend(compare_file(relative))

    for path in sorted(ROOT.rglob("*.py")):
        from skills_test.tools.make_baseline import INCLUDED_ROOTS, is_excluded

        if is_excluded(path):
            continue
        try:
            relative = path.relative_to(ROOT).as_posix()
        except ValueError:  # pragma: no cover
            continue
        if not relative.split("/")[0] in INCLUDED_ROOTS:
            continue
        if relative not in recorded:
            report.added_files.append(relative)
    return report


def baseline_function(relative: str, qualname: str) -> Function | None:
    """The baseline text of one function, for display."""
    return functions_in(read(SOURCE / relative)).get(qualname)


def current_function(relative: str, qualname: str) -> Function | None:
    """The current text of one function, for display."""
    return functions_in(read(ROOT / relative)).get(qualname)
