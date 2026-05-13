"""Admin-only user management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password, require_admin
from app.db import get_db
from app.models import AccessLog, User
from app.templating import templates

router = APIRouter()


@router.get("/admin/users", response_class=HTMLResponse)
async def list_users(
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    users = (await db.scalars(select(User).order_by(User.created_at))).all()
    return templates.TemplateResponse(
        request, "pages/admin_users.html",
        {"user": admin, "users": users},
    )


@router.post("/admin/users")
async def create_user(
    request: Request,
    email: str = Form(...),
    display_name: str = Form(...),
    password: str = Form(...),
    role: str = Form("regular"),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if role not in {"admin", "regular"}:
        raise HTTPException(status_code=400, detail="bad role")
    email = email.strip().lower()
    if await db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="email already exists")
    u = User(
        email=email, display_name=display_name.strip(),
        password_hash=hash_password(password), role=role, is_active=1,
    )
    db.add(u)
    db.add(AccessLog(
        user_id=admin.id, action="admin_create_user",
        ip=request.client.host if request.client else None,
        details_json=f'{{"new_user":"{email}","role":"{role}"}}',
    ))
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{uid}/disable")
async def disable_user(
    request: Request, uid: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    u = await db.get(User, uid)
    if not u:
        raise HTTPException(status_code=404)
    if u.id == admin.id:
        raise HTTPException(status_code=400, detail="cannot disable self")
    u.is_active = 0
    db.add(AccessLog(
        user_id=admin.id, action="admin_disable_user",
        ip=request.client.host if request.client else None,
        details_json=f'{{"target_user_id":{uid}}}',
    ))
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{uid}/reset")
async def reset_password(
    request: Request, uid: int,
    password: str = Form(...),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    u = await db.get(User, uid)
    if not u:
        raise HTTPException(status_code=404)
    u.password_hash = hash_password(password)
    db.add(AccessLog(
        user_id=admin.id, action="admin_reset_pw",
        ip=request.client.host if request.client else None,
        details_json=f'{{"target_user_id":{uid}}}',
    ))
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)
