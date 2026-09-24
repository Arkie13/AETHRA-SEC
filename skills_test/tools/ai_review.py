"""Optional local explanation of the evidence. Never authoritative.

If Ollama is already installed and running on this machine, this asks it to
explain findings the test system has *already established*. It is a reading
aid, nothing more. The authority is, in order: the failing regression test,
the current source, the baseline source, and the hash comparison.

Three rules this file enforces rather than merely states:

* **Local only.** The single endpoint is ``127.0.0.1:11434``. No source ever
  leaves the machine, and there is no configuration that would let it.
* **No invented code.** The model is asked for an explanation, and the
  baseline text is inserted by this script, not by the model. A repair always
  comes from the baseline.
* **Never fatal.** No Ollama, no model, no network - the review is skipped and
  the skills test is unaffected.

Run:  python skills_test/tools/ai_review.py
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills_test.tools import analysis  # noqa: E402

#: Loopback only. Not configurable on purpose.
ENDPOINT = "http://127.0.0.1:11434/api/generate"
REPORT = ROOT / "skills_test" / "reports" / "AI_REVIEW.md"
TIMEOUT = 60


def available() -> tuple[bool, str]:
    """Whether a local Ollama is reachable, and which model to use."""
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:11434/api/tags", timeout=3
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return False, ""
    models = [m.get("name", "") for m in data.get("models", [])]
    return (True, models[0]) if models else (False, "")


def explain(model: str, finding) -> str:
    """Ask the local model to explain one finding. Explanation only."""
    prompt = (
        "You are helping a student read a diagnostic report for a Python\n"
        "security application. Explain, in at most four sentences, what the\n"
        "difference below would do to the program's behaviour.\n\n"
        "Do NOT write replacement code. Do NOT suggest an implementation.\n"
        "The correct code is already known and will be shown separately.\n\n"
        f"File: {finding.path}\n"
        f"Function: {finding.qualname}\n"
        f"Kind of change: {finding.kind}\n\n"
        f"--- known-good ---\n{finding.baseline_code[:1500]}\n"
        f"--- current ---\n{finding.current_code[:1500]}\n"
    )
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps({
            "model": model, "prompt": prompt, "stream": False,
            "options": {"temperature": 0.1},
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8")).get("response", "").strip()
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return f"(the local model did not answer: {exc})"


def main() -> int:
    ok, model = available()
    if not ok:
        print("OFFLINE AI: SKIPPED")
        print("  No local Ollama instance answered on 127.0.0.1:11434.")
        print("  This does not affect the skills test result.")
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(
            "# AI Review\n\n**SKIPPED** - no local Ollama instance was "
            "reachable on 127.0.0.1:11434.\n\nThis does not affect the skills "
            "test. The authoritative evidence is the regression tests, the "
            "current source, the baseline source and the hash comparison.\n",
            encoding="utf-8",
        )
        return 0

    report = analysis.compare_tree()
    findings = [f for f in report.findings if f.severity in ("CRITICAL", "WARNING")]
    lines = [
        "# AI Review", "",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- Local model: `{model}` (via Ollama on 127.0.0.1)",
        "",
        "> This is an explanation of evidence the test system already",
        "> established. It is **not authoritative** and it never proposes",
        "> code. Every replacement shown in this report is the actual",
        "> baseline text, inserted by the script rather than by the model.",
        "",
    ]
    if not findings:
        lines += ["No differences from the baseline to explain.", ""]
    for index, finding in enumerate(findings, start=1):
        print(f"  explaining {index}/{len(findings)}: {finding.path}")
        lines += [
            f"## {index}. {finding.kind} - `{finding.path}`", "",
            f"- **Function:** `{finding.qualname or '-'}`",
            f"- **Evidence:** {finding.detail}",
            f"- **Confidence:** {'high' if finding.severity == 'CRITICAL' else 'medium'}"
            " (from the hash and AST comparison, not from the model)",
            "", "**Current code**", "", "```python",
            finding.current_code or "(absent)", "```", "",
            "**Known-good code (from the baseline)**", "", "```python",
            finding.baseline_code or "(not in the baseline)", "```", "",
            "**Local model's explanation**", "", explain(model, finding), "",
        ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"OFFLINE AI: written to {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
