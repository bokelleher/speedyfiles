"""Admin-only runtime settings pages (mail server, site, ...).

First page: /admin/settings/mail — SMTP config with a "Send test email" button.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.auth import require_admin
from app.db import get_db
from app.email import send_test_email
from app.models import User
from app.templating import templates

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/admin/settings", response_class=HTMLResponse)
async def settings_index(request: Request, admin: User = Depends(require_admin)):
    return templates.TemplateResponse(
        request, "pages/admin_settings_index.html", {"user": admin},
    )


@router.get("/admin/settings/mail", response_class=HTMLResponse)
async def mail_settings_get(
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    cfg = await settings_store.get_section(db, "mail")
    return templates.TemplateResponse(
        request, "pages/admin_settings_mail.html",
        {"user": admin, "cfg": cfg, "message": None, "error": None,
         "test_result": None},
    )


@router.post("/admin/settings/mail")
async def mail_settings_save(
    request: Request,
    host: str = Form(...),
    port: int = Form(...),
    security: str = Form("starttls"),
    auth_method: str = Form("none"),
    username: str = Form(""),
    password: str = Form(""),
    keep_password: str = Form(""),       # "1" if user left password blank to keep existing
    from_address: str = Form(...),
    from_name: str = Form(""),
    helo: str = Form(""),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if security not in {"none", "starttls", "tls"}:
        security = "starttls"
    if auth_method not in {"none", "login", "plain"}:
        auth_method = "none"
    if port < 1 or port > 65535:
        port = 587

    values = {
        "host": host.strip(),
        "port": port,
        "security": security,
        "auth_method": auth_method,
        "username": username.strip(),
        "from_address": from_address.strip(),
        "from_name": from_name.strip(),
        "helo": helo.strip(),
    }
    # Only overwrite the password if a non-blank value was submitted.
    # (When `keep_password=1`, the form sent us an empty password field and we
    # leave the stored value alone.)
    for k, v in values.items():
        await settings_store.set(db, f"mail.{k}", v, user_id=admin.id)
    if password and not keep_password:
        await settings_store.set(db, "mail.password", password, secret=True, user_id=admin.id)
    elif auth_method == "none":
        # No auth → clear any stored password.
        await settings_store.set(db, "mail.password", "", secret=True, user_id=admin.id)
    await db.commit()
    return RedirectResponse("/admin/settings/mail?saved=1", status_code=303)


@router.post("/admin/settings/mail/test")
async def mail_settings_test(
    request: Request,
    test_to: str = Form(...),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    cfg = await settings_store.get_section(db, "mail")
    test_result: dict = {"ok": False, "to": test_to, "message": ""}
    try:
        await send_test_email(db, test_to.strip())
        test_result["ok"] = True
        test_result["message"] = f"Test email queued to {test_to}."
    except Exception as e:  # noqa: BLE001
        test_result["message"] = f"{type(e).__name__}: {e}"
        log.exception("test email failed")
    return templates.TemplateResponse(
        request, "pages/admin_settings_mail.html",
        {"user": admin, "cfg": cfg, "message": None, "error": None,
         "test_result": test_result},
    )
