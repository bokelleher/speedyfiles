"""First-run setup wizard.

When the `users` table is empty, every route except /setup and /static/*
redirects to /setup. The wizard collects the admin account, site identity,
and (optional) initial mail config, then redirects to /dash logged-in.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.auth import hash_password, make_session_cookie
from app.config import settings as env_settings
from app.db import get_db
from app.models import AccessLog, User
from app.templating import templates
from app.utils import utcnow

log = logging.getLogger(__name__)
router = APIRouter()


async def _is_unsetup(db: AsyncSession) -> bool:
    """True if the install is still in its fresh state (no users yet)."""
    count = await db.scalar(select(func.count()).select_from(User)) or 0
    return count == 0


@router.get("/setup", response_class=HTMLResponse)
async def setup_form(request: Request, db: AsyncSession = Depends(get_db)):
    if not await _is_unsetup(db):
        # Already configured — bounce to login. Don't let a re-runner steal admin.
        return RedirectResponse("/login", status_code=303)
    site_name = await settings_store.get(db, "site.name", env_settings.app_name)
    public_url = await settings_store.get(db, "site.public_base_url",
                                          env_settings.public_base_url)
    return templates.TemplateResponse(
        request, "pages/setup.html",
        {"error": None, "site_name": site_name, "public_url": public_url},
    )


@router.post("/setup")
async def setup_submit(
    request: Request,
    admin_email: str = Form(...),
    admin_name: str = Form(...),
    admin_password: str = Form(...),
    admin_password_confirm: str = Form(...),
    site_name: str = Form(...),
    public_base_url: str = Form(...),
    # Mail (optional — can be left blank, configured later)
    smtp_host: str = Form(""),
    smtp_port: str = Form(""),
    smtp_security: str = Form("starttls"),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    mail_from_address: str = Form(""),
    mail_from_name: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    if not await _is_unsetup(db):
        return RedirectResponse("/login", status_code=303)

    # Validation
    error = None
    if len(admin_password) < 10:
        error = "Admin password must be at least 10 characters."
    elif admin_password != admin_password_confirm:
        error = "Admin passwords do not match."
    elif "@" not in admin_email:
        error = "Admin email is required and must be a valid address."
    elif not public_base_url.startswith(("http://", "https://")):
        error = "Public base URL must start with http:// or https://"
    if error:
        return templates.TemplateResponse(
            request, "pages/setup.html",
            {"error": error, "site_name": site_name, "public_url": public_base_url},
            status_code=400,
        )

    # 1. Create the admin
    admin = User(
        email=admin_email.strip().lower(),
        display_name=admin_name.strip(),
        password_hash=hash_password(admin_password),
        role="admin", is_active=1, created_at=utcnow(), last_login_at=utcnow(),
    )
    db.add(admin)
    await db.flush()

    # 2. Persist site identity
    await settings_store.set(db, "site.name", site_name.strip(), user_id=admin.id)
    await settings_store.set(db, "site.public_base_url",
                             public_base_url.strip().rstrip("/"), user_id=admin.id)

    # 3. Persist mail (only if provided)
    if smtp_host.strip():
        port_int = 587
        try:
            if smtp_port.strip():
                port_int = max(1, min(65535, int(smtp_port)))
        except ValueError:
            port_int = 587
        await settings_store.set(db, "mail.host", smtp_host.strip(), user_id=admin.id)
        await settings_store.set(db, "mail.port", port_int, user_id=admin.id)
        await settings_store.set(db, "mail.security",
                                 smtp_security if smtp_security in ("none","starttls","tls") else "starttls",
                                 user_id=admin.id)
        if smtp_username.strip():
            await settings_store.set(db, "mail.username", smtp_username.strip(), user_id=admin.id)
            await settings_store.set(db, "mail.auth_method", "login", user_id=admin.id)
            if smtp_password:
                await settings_store.set(db, "mail.password", smtp_password,
                                         secret=True, user_id=admin.id)
        else:
            await settings_store.set(db, "mail.auth_method", "none", user_id=admin.id)
        if mail_from_address.strip():
            await settings_store.set(db, "mail.from_address",
                                     mail_from_address.strip(), user_id=admin.id)
        if mail_from_name.strip():
            await settings_store.set(db, "mail.from_name",
                                     mail_from_name.strip(), user_id=admin.id)

    # 4. Audit + commit
    db.add(AccessLog(
        user_id=admin.id, action="setup_complete",
        ip=request.client.host if request.client else None,
    ))
    await db.commit()

    # 5. Log them in
    cookie_value, _csrf = make_session_cookie(admin.id)
    resp = RedirectResponse("/dash", status_code=303)
    resp.set_cookie(
        env_settings.session_cookie_name,
        cookie_value,
        max_age=env_settings.session_max_age_seconds,
        httponly=True,
        secure=not env_settings.debug,
        samesite="lax",
        path="/",
    )
    log.info("first-run setup completed: admin=%s site=%r", admin.email, site_name)
    return resp


# ----------------------------------------------------------------------------
# Setup-required middleware: redirect to /setup when no users exist.
# Mounted in main.py via app.middleware('http').
# ----------------------------------------------------------------------------

# Paths allowed BEFORE setup is complete
_PRE_SETUP_ALLOWED = (
    "/setup", "/static/", "/healthz", "/favicon.ico",
)


async def setup_required_middleware(request: Request, call_next):
    """If no admin exists yet, redirect to /setup for any non-allowlisted path."""
    path = request.url.path
    if any(path.startswith(p) for p in _PRE_SETUP_ALLOWED):
        return await call_next(request)
    # Cheap check via the engine — avoid a per-request session dep
    from app.db import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        if await _is_unsetup(db):
            return RedirectResponse("/setup", status_code=303)
    return await call_next(request)
