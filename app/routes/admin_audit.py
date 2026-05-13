"""Admin audit log viewer."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.db import get_db
from app.models import AccessLog
from app.templating import templates

router = APIRouter()


@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_view(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(AccessLog).order_by(AccessLog.ts.desc())
    cq = select(func.count()).select_from(AccessLog)
    if action:
        q = q.where(AccessLog.action == action)
        cq = cq.where(AccessLog.action == action)
    total = await db.scalar(cq) or 0
    rows = (await db.scalars(q.limit(limit).offset(offset))).all()

    # Pull distinct action names for the filter dropdown
    actions = (await db.scalars(
        select(AccessLog.action).distinct().order_by(AccessLog.action)
    )).all()

    return templates.TemplateResponse(
        request, "pages/admin_audit.html",
        {"user": admin, "rows": rows, "total": total, "limit": limit,
         "offset": offset, "actions": actions, "current_action": action},
    )
