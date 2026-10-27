"""Write the step-by-step procedures into the mitigation recommendations.

Repeatable and additive. It touches only the four columns migration 25 added -
``enforcement_point``, ``procedure_steps``, ``rollback_steps`` and
``operational_warnings`` - and only for the recommendation codes it has a
guide for. Existing rows keep their ids; the five prose fields an
administrator may have edited (explanation, why_it_matters, immediate_action,
long_term_action, verification_steps) are left exactly as they are, except
``verification_steps``, which is rewritten only when the guide supplies one
and the operator asks for it with --replace-verification.

Nothing is deleted, no row is created, and no recommendation outside the
guide set is touched.

    python scripts/load_mitigation_guides.py [--dry-run] [--replace-verification]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8")

COLUMNS = (
    "enforcement_point",
    "procedure_steps",
    "rollback_steps",
    "operational_warnings",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change and write nothing")
    parser.add_argument("--replace-verification", action="store_true",
                        help="also replace verification_steps with the "
                             "guide's version")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.disable(logging.INFO)
    from aethra_sec.core.application import ApplicationContext
    from aethra_sec.database.mitigation_guides import GUIDES

    context = ApplicationContext()
    context.start()
    db = context.db

    missing_columns = [
        name for name in COLUMNS
        if not db.query_one(
            "SELECT 1 AS present FROM information_schema.columns "
            "WHERE table_schema = DATABASE() "
            "AND table_name = 'mitigation_recommendations' "
            "AND column_name = %s", (name,))
    ]
    if missing_columns:
        print(f"  the schema is missing {', '.join(missing_columns)}; "
              "run the migrations first")
        context.shutdown("mitigation guides")
        return 2

    updated = skipped = absent = 0
    for code, guide in sorted(GUIDES.items()):
        row = db.query_one(
            "SELECT id, threat_name, enforcement_point FROM "
            "mitigation_recommendations WHERE code = %s", (code,))
        if row is None:
            print(f"  {code:22s} NOT PRESENT in the database - skipped, "
                  "no row created")
            absent += 1
            continue

        fields = dict(guide)
        if not args.replace_verification:
            fields.pop("verification_steps", None)
        assignments = ", ".join(f"{name} = %s" for name in fields)
        values = [fields[name] for name in fields]

        already = bool((row.get("enforcement_point") or "").strip())
        if args.dry_run:
            print(f"  {code:22s} would {'refresh' if already else 'fill'} "
                  f"{len(fields)} field(s) on id={row['id']}")
            skipped += 1
            continue

        db.execute(
            f"UPDATE mitigation_recommendations SET {assignments}, "
            "updated_at = NOW(6) WHERE id = %s",
            (*values, int(row["id"])),
        )
        print(f"  {code:22s} {'refreshed' if already else 'filled':9s} "
              f"id={row['id']}  {row['threat_name']}")
        updated += 1

    total = db.query_value("SELECT COUNT(*) FROM mitigation_recommendations")
    with_guide = db.query_value(
        "SELECT COUNT(*) FROM mitigation_recommendations "
        "WHERE enforcement_point IS NOT NULL AND enforcement_point <> ''")
    print()
    print(f"  recommendations in the database : {total}")
    print(f"  now carrying a full procedure   : {with_guide}")
    if args.dry_run:
        print(f"  dry run - {skipped} row(s) would have been written")
    else:
        print(f"  written                         : {updated}")
    if absent:
        print(f"  guide codes with no row         : {absent}")
    context.shutdown("mitigation guides")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
