"""Site identity settings (admin-only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.auth import require_admin
from app.config import settings as env_settings
from app.db import get_db
from app.templating import templates

router = APIRouter()


@router.get("/admin/settings/site", response_class=HTMLResponse)
async def site_get(
    request: Request,
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    cfg = await settings_store.get_section(db, "site")
    return templates.TemplateResponse(
        request, "pages/admin_settings_site.html",
        {"user": admin, "cfg": cfg, "fallback_name": env_settings.app_name,
         "fallback_url": env_settings.public_base_url},
    )


@router.post("/admin/settings/site")
async def site_save(
    request: Request,
    site_name: str = Form(...),
    public_base_url: str = Form(...),
    support_email: str = Form(""),
    primary_color: str = Form("#4f9eed"),
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    await settings_store.set(db, "site.name", site_name.strip()[:128] or env_settings.app_name,
                             user_id=admin.id)
    url = public_base_url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    await settings_store.set(db, "site.public_base_url", url, user_id=admin.id)
    await settings_store.set(db, "site.support_email", support_email.strip(), user_id=admin.id)
    await settings_store.set(db, "site.primary_color", primary_color.strip()[:24], user_id=admin.id)
    await db.commit()
    return RedirectResponse("/admin/settings/site?saved=1", status_code=303)
