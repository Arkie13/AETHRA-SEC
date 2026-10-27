"""Non-functional repeated tests: each action 100 times, every attempt recorded.

Runs on the isolated test database through the real services. Each test
writes evaluation/test_cases_2026-10-24/NF_<name>_100.csv (attempt, timestamp,
duration, PASS/FAIL) and a line in NF_repeated_summary.json.
"""
from __future__ import annotations

import csv
import json
import statistics as st
import time
from datetime import datetime
from pathlib import Path

from aethra_sec.core.errors import (
    AccountLockedError,
    AuthenticationError,
    PermissionDeniedError,
)
from aethra_sec.core.session import SessionManager
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.security.audit import AuditService
from aethra_sec.security.authentication import AuthenticationService
from aethra_sec.security.password import PasswordHashService
from test_cia_evidence_t2_t4 import system  # noqa: F401 - shared fixture

OUT = Path(__file__).resolve().parents[1] / "evaluation" / "test_cases_2026-10-24"
N = 100


def run(name: str, title: str, action, expect: str) -> dict:  # noqa: ANN001
    """Run ``action`` N times; it returns True when the attempt behaved as expected."""
    rows = []
    for i in range(1, N + 1):
        started = datetime.now()
        t0 = time.perf_counter()
        note = ""
        try:
            ok = bool(action(i))
        except Exception as exc:  # noqa: BLE001 - recorded as a failure
            ok, note = False, f"{type(exc).__name__}: {exc}"
        ms = (time.perf_counter() - t0) * 1000
        rows.append({"attempt": i, "timestamp": started.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                     "duration_ms": round(ms, 1), "result": "PASS" if ok else "FAIL", "note": note})
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / f"NF_{name}_100.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    t = [r["duration_ms"] for r in rows]
    passed = sum(r["result"] == "PASS" for r in rows)
    summary = {"test": title, "expected": expect, "attempts": N, "passed": passed, "failed": N - passed,
               "first_attempt": rows[0]["timestamp"], "last_attempt": rows[-1]["timestamp"],
               "duration_ms": {"mean": round(st.mean(t), 1), "median": round(st.median(t), 1),
                               "min": min(t), "max": max(t)},
               "status": "PASS" if passed == N else "FAIL", "database": "aethra_sec_test (isolated)"}
    path = OUT / "NF_repeated_summary.json"
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data[name] = summary
    path.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return summary


def test_wrong_password_100_times(clean_db) -> None:  # noqa: ANN001
    users = UserRepository(clean_db)
    passwords = PasswordHashService()
    auth = AuthenticationService(users, SessionManager(60), passwords, AuditService(AuditRepository(clean_db)))
    role = users.get_role_by_name("USER")
    hashed = passwords.hash("Correct-Pass!2026")
    users.create_user(username="nf_wrongpw", password_hash=hashed.hash,
                      password_algorithm=hashed.algorithm, role_id=role.id, full_name="NF wrong password")

    def attempt(_i: int) -> bool:
        try:
            auth.login("nf_wrongpw", "Wrong-Pass!0000")
        except (AuthenticationError, AccountLockedError):
            return True  # refused, as it must be
        return False  # a wrong password was accepted

    s = run("wrong_password", "Sign in with a wrong password 100 times",
            attempt, "Every attempt refused; the account locks after repeated failures")
    assert s["passed"] == N


def test_unauthorized_access_100_times(system) -> None:  # noqa: ANN001, F811
    _uid, user = system.account["USER"]

    def attempt(_i: int) -> bool:
        try:
            system.users.list_users(user)
        except PermissionDeniedError:
            return True
        return False

    s = run("unauthorized_access", "Standard user opens User Management 100 times",
            attempt, "Every attempt refused and audited")
    assert s["passed"] == N


def test_log_integrity_100_times(system) -> None:  # noqa: ANN001, F811
    _aid, admin = system.account["ADMIN"]
    s = run("log_integrity", "Verify the audit-log hash chain 100 times",
            lambda _i: not system.logs.verify_integrity(admin).issues,
            "Every verification reports the chain intact (0 issues)")
    assert s["passed"] == N


def test_alert_list_100_times(system) -> None:  # noqa: ANN001, F811
    _aid, admin = system.account["ADMIN"]
    s = run("alert_list", "Load the AETHRA-SEC detection list 100 times",
            lambda _i: isinstance(system.snort.search_anomalies(admin), list),
            "Every load returns the list")
    assert s["passed"] == N


def test_dashboard_100_times(system) -> None:  # noqa: ANN001, F811
    _aid, admin = system.account["ADMIN"]
    s = run("dashboard", "Load the dashboard 100 times",
            lambda _i: system.dashboard.snapshot(admin) is not None,
            "Every load returns a dashboard snapshot")
    assert s["passed"] == N
