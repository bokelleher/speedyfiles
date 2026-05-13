"""Admin-only webhook subscription management."""
from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.db import get_db
from app.models import Webhook
from app.templating import templates
from app.webhooks import EVENTS

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/admin/webhooks", response_class=HTMLResponse)
async def list_webhooks(
    request: Request,
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.scalars(select(Webhook).order_by(Webhook.created_at.desc()))).all()
    new_secret = request.query_params.get("secret")  # shown once after create
    return templates.TemplateResponse(
        request, "pages/admin_webhooks.html",
        {"user": admin, "hooks": rows, "events_all": EVENTS, "new_secret": new_secret},
    )


@router.post("/admin/webhooks")
async def create_webhook(
    request: Request,
    url: str = Form(...),
    events_csv: str = Form(...),
    description: str = Form(""),
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must start with http:// or https://")
    # Filter event names against allowlist
    requested = {e.strip() for e in events_csv.split(",") if e.strip()}
    valid = sorted(requested & set(EVENTS))
    if not valid:
        raise HTTPException(status_code=400, detail="select at least one valid event")
    secret = "whsec_" + secrets.token_urlsafe(32)
    db.add(Webhook(
        url=url.strip(),
        secret=secret,
        events=",".join(valid),
        description=description.strip()[:512] or None,
        is_active=1,
        created_by_user_id=admin.id,
    ))
    await db.commit()
    # show the secret once via redirect query (no persistence beyond DB)
    return RedirectResponse(f"/admin/webhooks?secret={secret}", status_code=303)


@router.post("/admin/webhooks/{hook_id}/toggle")
async def toggle_webhook(
    hook_id: int,
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    h = await db.get(Webhook, hook_id)
    if h is None:
        raise HTTPException(status_code=404)
    h.is_active = 0 if h.is_active else 1
    if h.is_active:
        h.failure_count = 0  # reset on re-enable
    await db.commit()
    return RedirectResponse("/admin/webhooks", status_code=303)


@router.post("/admin/webhooks/{hook_id}/delete")
async def delete_webhook(
    hook_id: int,
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    h = await db.get(Webhook, hook_id)
    if h is None:
        raise HTTPException(status_code=404)
    await db.delete(h)
    await db.commit()
    return RedirectResponse("/admin/webhooks", status_code=303)


@router.post("/admin/webhooks/{hook_id}/test")
async def test_webhook(
    hook_id: int,
    admin = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Send a synthetic 'webhook.test' event to verify the endpoint works."""
    from app.webhooks import fire_event
    # Temporarily widen this hook's event list to include the test event
    h = await db.get(Webhook, hook_id)
    if h is None:
        raise HTTPException(status_code=404)
    orig = h.events
    if "webhook.test" not in orig:
        h.events = orig + (",webhook.test" if orig else "webhook.test")
        await db.commit()
    try:
        await fire_event(db, "webhook.test", payload={
            "message": "Test event fired from the admin UI.",
            "fired_by": admin.email,
        })
    finally:
        # Restore original event list
        h = await db.get(Webhook, hook_id)
        if h:
            h.events = orig
            await db.commit()
    return RedirectResponse("/admin/webhooks", status_code=303)
