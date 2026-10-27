"""Non-functional test: sign in 100 times and record every attempt.

Each attempt signs in through the real AuthenticationService (Argon2id
hashing, as on the live system), confirms a session was issued, then signs
out. The time of each attempt, its duration and Pass/Fail are written to
evaluation/test_cases_2026-10-24/NF_login_100.csv with a summary JSON.

Runs on the isolated test database; it writes nothing to production.
"""
from __future__ import annotations

import csv
import json
import statistics as st
import time
from datetime import datetime
from pathlib import Path

from aethra_sec.core.session import SessionManager
from aethra_sec.database.repositories.audit import AuditRepository
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.security.audit import AuditService
from aethra_sec.security.authentication import AuthenticationService
from aethra_sec.security.password import PasswordHashService

OUT = Path(__file__).resolve().parents[1] / "evaluation" / "test_cases_2026-10-24"
ATTEMPTS = 100
PASSWORD = "NF-Login-Test!2026"


def test_sign_in_100_times(clean_db) -> None:  # noqa: ANN001
    users = UserRepository(clean_db)
    passwords = PasswordHashService()  # same hashing as the application
    sessions = SessionManager(60)
    auth = AuthenticationService(users, sessions, passwords, AuditService(AuditRepository(clean_db)))
    role = users.get_role_by_name("ADMIN")
    hashed = passwords.hash(PASSWORD)
    users.create_user(username="nf_login_test", password_hash=hashed.hash,
                      password_algorithm=hashed.algorithm, role_id=role.id, full_name="NF login test")

    rows = []
    for n in range(1, ATTEMPTS + 1):
        started = datetime.now()
        t0 = time.perf_counter()
        error = ""
        try:
            result = auth.login("nf_login_test", PASSWORD)
            ok = result.session is not None and sessions.get(result.session.token) is not None
            if ok:
                auth.logout(result.session)
        except Exception as exc:  # noqa: BLE001 - recorded as a failed attempt
            ok, error = False, f"{type(exc).__name__}: {exc}"
        ms = (time.perf_counter() - t0) * 1000
        rows.append({"attempt": n, "timestamp": started.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                     "duration_ms": round(ms, 1), "result": "PASS" if ok else "FAIL", "error": error})

    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "NF_login_100.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    times = [r["duration_ms"] for r in rows]
    passed = sum(r["result"] == "PASS" for r in rows)
    summary = {
        "test": "Sign in 100 times (sign in, confirm session, sign out)",
        "database": "aethra_sec_test (isolated)", "hashing": "Argon2id, as on the live system",
        "first_attempt": rows[0]["timestamp"], "last_attempt": rows[-1]["timestamp"],
        "attempts": ATTEMPTS, "passed": passed, "failed": ATTEMPTS - passed,
        "success_rate_pct": round(100 * passed / ATTEMPTS, 2),
        "duration_ms": {"mean": round(st.mean(times), 1), "median": round(st.median(times), 1),
                        "min": min(times), "max": max(times), "sd": round(st.stdev(times), 1)},
        "criterion": "All 100 attempts succeed",
        "status": "PASS" if passed == ATTEMPTS else "FAIL",
    }
    (OUT / "NF_login_100_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    assert passed == ATTEMPTS, f"{ATTEMPTS - passed} sign-in(s) failed"
