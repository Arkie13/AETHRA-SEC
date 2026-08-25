"""Admin-only endpoint: the real registration list.

The only place any name or email is ever visible - the artifact-based
approach this replaces never captured them at all.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import db
from ..models import AdminRegistrationOut
from ..security import verify_admin_token

router = APIRouter()


@router.get("/admin/registrations", response_model=list[AdminRegistrationOut])
def list_registrations(_: None = Depends(verify_admin_token)) -> list[AdminRegistrationOut]:
    rows = db.list_registrations()
    return [
        AdminRegistrationOut(name=row["name"], email=row["email"], created_at=row["created_at"])
        for row in rows
    ]
