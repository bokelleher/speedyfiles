"""Internal user dashboard routes."""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_user
from app.config import settings
from app.db import get_db
from app.email import send_inbound_request, send_outbound_notification
from app.models import AccessLog, MagicLinkToken, Package, PackageFile, User
from app.storage import get_backend
from app.templating import templates
from app.utils import gen_id, gen_magic_token, hash_token, sanitize_filename, utcnow
from app.webhooks import fire_event

log = logging.getLogger(__name__)
router = APIRouter()


def _async_iter_uploadfile(uf: UploadFile, chunk: int = 1 << 20):
    async def gen():
        while True:
            data = await uf.read(chunk)
            if not data:
                break
            yield data
    return gen()


@router.get("/", response_class=HTMLResponse)
async def root_redirect(user: User | None = Depends(require_user)):
    return RedirectResponse("/dash", status_code=303)


@router.get("/dash", response_class=HTMLResponse)
async def dash(
    request: Request,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy.orm import selectinload
    q = (select(Package)
         .options(selectinload(Package.owner))
         .order_by(Package.created_at.desc()))
    if user.role != "admin":
        q = q.where(Package.owner_user_id == user.id)
    pkgs = (await db.scalars(q)).all()
    return templates.TemplateResponse(
        request, "pages/dash.html",
        {"user": user, "packages": pkgs, "now": utcnow()},
    )


@router.get("/dash/packages/new/outbound", response_class=HTMLResponse)
async def new_outbound_form(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse(
        request, "pages/package_new_outbound.html",
        {"user": user, "default_ttl_days": 7},
    )


async def _finalize_outbound(db: AsyncSession, pkg: Package, user: User,
                             request: Request) -> str:
    """Mint magic link, mark active, send notification. Returns raw token."""
    raw_token = gen_magic_token()
    db.add(MagicLinkToken(
        package_id=pkg.id, token_sha256=hash_token(raw_token),
        recipient_email=pkg.recipient_email, purpose="download",
        expires_at=pkg.expires_at,
    ))
    pkg.status = "active"
    file_count = await db.scalar(
        select(func.count()).select_from(PackageFile)
        .where(PackageFile.package_id == pkg.id, PackageFile.state == "complete")
    )
    await db.commit()

    link_url = f"{settings.public_base_url}/p/{raw_token}"
    try:
        await send_outbound_notification(
            db,
            to_email=pkg.recipient_email, to_name=pkg.recipient_name,
            sender_name=user.display_name, package_title=pkg.title,
            note=pkg.note, link_url=link_url,
            expires_at=pkg.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            file_count=file_count or 0,
        )
    except Exception:
        log.exception("failed to send outbound notification for pkg=%s", pkg.id)
    try:
        await fire_event(db, "package.finalized", package_id=pkg.id, payload={
            "title": pkg.title, "recipient_email": pkg.recipient_email,
            "owner_user_id": pkg.owner_user_id, "file_count": file_count or 0,
            "expires_at": pkg.expires_at.isoformat(),
        })
    except Exception:
        log.exception("webhook fire failed for pkg.finalized %s", pkg.id)
    return raw_token


@router.post("/dash/packages/new/outbound")
async def new_outbound_submit(
    request: Request,
    title: str = Form(...),
    recipient_email: str = Form(...),
    recipient_name: str = Form(...),
    ttl_days: int = Form(7),
    note: str = Form(""),
    files: list[UploadFile] | None = File(None),
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    """Two modes:
       - JS-driven (NEW): no `files` field → create empty package in 'draft' status,
         return JSON `{pkg_id}`. Client then POSTs each file to
         /dash/packages/{id}/upload (with progress) and finally /finalize.
       - Legacy: `files` provided → single-shot upload, mint+email immediately.
    """
    if ttl_days < 1 or ttl_days > 90:
        raise HTTPException(status_code=400, detail="ttl_days must be 1..90")

    inline_files = [f for f in (files or []) if f and f.filename]
    pkg_id = gen_id(16)
    expires = utcnow() + timedelta(days=ttl_days)
    backend = get_backend()
    await backend.init_package(pkg_id)

    pkg = Package(
        id=pkg_id, owner_user_id=user.id, direction="outbound",
        title=title.strip(), note=note.strip() or None,
        recipient_email=recipient_email.strip().lower(),
        recipient_name=recipient_name.strip(),
        storage_backend=backend.name, transport_mode="http",
        status="draft" if not inline_files else "active",
        expires_at=expires,
    )
    db.add(pkg)
    await db.flush()

    import time
    for uf in inline_files:
        file_id = gen_id(8)
        sanitized = sanitize_filename(uf.filename)
        t0 = time.monotonic()
        stored = await backend.put_file(
            pkg_id, file_id, sanitized, _async_iter_uploadfile(uf),
        )
        duration_ms = int((time.monotonic() - t0) * 1000)
        db.add(PackageFile(
            id=file_id, package_id=pkg_id,
            original_name=uf.filename, sanitized_name=sanitized,
            size_bytes=stored.size_bytes, sha256=stored.sha256,
            content_type=uf.content_type,
            storage_key=stored.storage_key, state="complete",
            uploaded_at=utcnow(), duration_ms=duration_ms,
        ))

    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="admin_create_pkg",
        ip=request.client.host if request.client else None,
        details_json=json.dumps({"direction": "outbound",
                                 "file_count": len(inline_files),
                                 "mode": "inline" if inline_files else "draft"}),
    ))
    await db.commit()

    if inline_files:
        await _finalize_outbound(db, pkg, user, request)
        return RedirectResponse(f"/dash/packages/{pkg_id}", status_code=303)
    from fastapi.responses import JSONResponse
    return JSONResponse({"pkg_id": pkg_id})


@router.post("/dash/packages/{pkg_id}/upload")
async def package_upload_one(
    pkg_id: str, request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    """Owner-only: append one file to an existing outbound package.
       Used by the JS-driven upload UI for per-file progress."""
    pkg = await db.get(Package, pkg_id)
    if not pkg:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    if pkg.direction != "outbound":
        raise HTTPException(status_code=400, detail="not an outbound package")
    if pkg.status not in ("draft", "active"):
        raise HTTPException(status_code=400, detail=f"package status {pkg.status!r}")
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename required")

    file_id = gen_id(8)
    sanitized = sanitize_filename(file.filename)
    backend = get_backend(pkg.storage_backend)

    async def _gen():
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            yield chunk

    import time
    t0 = time.monotonic()
    stored = await backend.put_file(pkg_id, file_id, sanitized, _gen())
    duration_ms = int((time.monotonic() - t0) * 1000)
    db.add(PackageFile(
        id=file_id, package_id=pkg_id,
        original_name=file.filename, sanitized_name=sanitized,
        size_bytes=stored.size_bytes, sha256=stored.sha256,
        content_type=file.content_type, storage_key=stored.storage_key,
        state="complete", uploaded_at=utcnow(), duration_ms=duration_ms,
    ))
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="admin_add_file",
        ip=request.client.host if request.client else None,
        details_json=json.dumps({"file_id": file_id, "size": stored.size_bytes,
                                 "original_name": file.filename,
                                 "duration_ms": duration_ms}),
    ))
    await db.commit()
    try:
        await fire_event(db, "package.file_uploaded", package_id=pkg_id, payload={
            "file_id": file_id, "size_bytes": stored.size_bytes,
            "original_name": file.filename, "duration_ms": duration_ms,
            "uploaded_by": "owner",
        })
    except Exception:
        log.exception("webhook fire failed for package.file_uploaded")
    return {"ok": True, "file_id": file_id, "size": stored.size_bytes,
            "sha256": stored.sha256, "original_name": file.filename,
            "duration_ms": duration_ms}


@router.post("/dash/packages/{pkg_id}/finalize")
async def package_finalize(
    pkg_id: str, request: Request,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    """Owner-only: mint magic link + send email for a draft outbound pkg.

    Content-negotiates the response:
      - Browser form post (Accept: text/html) → 303 to the package detail page.
      - Fetch from JS (Accept: application/json) → JSON {"ok": true, "redirect": "..."}.
    """
    pkg = await db.get(Package, pkg_id)
    if not pkg:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    if pkg.direction != "outbound":
        raise HTTPException(status_code=400, detail="not outbound")

    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept and "application/json" not in accept

    if pkg.status == "active":
        if wants_html:
            return RedirectResponse(f"/dash/packages/{pkg_id}", status_code=303)
        return {"ok": True, "already_active": True,
                "redirect": f"/dash/packages/{pkg_id}"}

    file_count = await db.scalar(
        select(func.count()).select_from(PackageFile)
        .where(PackageFile.package_id == pkg_id, PackageFile.state == "complete")
    )
    if not file_count:
        raise HTTPException(status_code=400, detail="no files uploaded yet")
    await _finalize_outbound(db, pkg, user, request)
    if wants_html:
        return RedirectResponse(f"/dash/packages/{pkg_id}", status_code=303)
    return {"ok": True, "redirect": f"/dash/packages/{pkg_id}"}


@router.get("/dash/packages/new/inbound", response_class=HTMLResponse)
async def new_inbound_form(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse(
        request, "pages/package_new_inbound.html",
        {"user": user, "default_ttl_days": 7},
    )


@router.post("/dash/packages/new/inbound")
async def new_inbound_submit(
    request: Request,
    title: str = Form(...),
    recipient_email: str = Form(...),
    recipient_name: str = Form(...),
    ttl_days: int = Form(7),
    note: str = Form(""),
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    if ttl_days < 1 or ttl_days > 90:
        raise HTTPException(status_code=400, detail="ttl_days must be 1..90")

    pkg_id = gen_id(16)
    expires = utcnow() + timedelta(days=ttl_days)
    backend = get_backend()
    await backend.init_package(pkg_id)

    pkg = Package(
        id=pkg_id, owner_user_id=user.id, direction="inbound",
        title=title.strip(), note=note.strip() or None,
        recipient_email=recipient_email.strip().lower(),
        recipient_name=recipient_name.strip(),
        storage_backend=backend.name, transport_mode="http",
        status="active", expires_at=expires,
    )
    db.add(pkg)

    raw_token = gen_magic_token()
    db.add(MagicLinkToken(
        package_id=pkg_id, token_sha256=hash_token(raw_token),
        recipient_email=pkg.recipient_email, purpose="upload",
        expires_at=expires,
    ))
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="admin_create_pkg",
        ip=request.client.host if request.client else None,
        details_json=json.dumps({"direction": "inbound"}),
    ))
    await db.commit()

    link_url = f"{settings.public_base_url}/p/{raw_token}"
    try:
        await send_inbound_request(
            db,
            to_email=pkg.recipient_email, to_name=pkg.recipient_name,
            sender_name=user.display_name, package_title=pkg.title,
            note=pkg.note, link_url=link_url,
            expires_at=expires.strftime("%Y-%m-%d %H:%M UTC"),
        )
    except Exception:
        log.exception("failed to send inbound request for pkg=%s", pkg_id)

    return RedirectResponse(f"/dash/packages/{pkg_id}", status_code=303)


@router.get("/dash/packages/{pkg_id}", response_class=HTMLResponse)
async def package_detail(
    request: Request, pkg_id: str,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    pkg = await db.get(Package, pkg_id)
    if not pkg:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    files = (await db.scalars(
        select(PackageFile).where(PackageFile.package_id == pkg_id)
        .order_by(PackageFile.created_at)
    )).all()
    tokens = (await db.scalars(
        select(MagicLinkToken).where(MagicLinkToken.package_id == pkg_id)
        .order_by(MagicLinkToken.created_at.desc())
    )).all()
    logs = (await db.scalars(
        select(AccessLog).where(AccessLog.package_id == pkg_id)
        .order_by(AccessLog.ts.desc()).limit(50)
    )).all()
    return templates.TemplateResponse(
        request, "pages/package_detail.html",
        {"user": user, "pkg": pkg, "files": files, "tokens": tokens,
         "logs": logs, "now": utcnow(), "base_url": settings.public_base_url},
    )


@router.post("/dash/packages/{pkg_id}/revoke")
async def package_revoke(
    request: Request, pkg_id: str,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    pkg = await db.get(Package, pkg_id)
    if not pkg:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    pkg.status = "revoked"
    now = utcnow()
    for tok in (await db.scalars(
        select(MagicLinkToken).where(MagicLinkToken.package_id == pkg_id,
                                     MagicLinkToken.revoked_at.is_(None))
    )).all():
        tok.revoked_at = now
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="admin_revoke",
        ip=request.client.host if request.client else None,
    ))
    await db.commit()
    try:
        await fire_event(db, "package.revoked", package_id=pkg_id, payload={
            "title": pkg.title, "recipient_email": pkg.recipient_email,
        })
    except Exception:
        log.exception("webhook fire failed for pkg.revoked")
    return RedirectResponse(f"/dash/packages/{pkg_id}", status_code=303)


@router.post("/dash/packages/{pkg_id}/delete")
async def package_delete(
    request: Request, pkg_id: str,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    """Owner-or-admin: permanently delete a package — DB rows + storage bytes.
       The audit-log entries for this package are preserved (package_id is
       nulled out before delete) so the trail of who-did-what remains."""
    from sqlalchemy import update
    pkg = await db.get(Package, pkg_id)
    if not pkg:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)

    # Collect a few details for the final audit-log row
    file_count = await db.scalar(
        select(func.count()).select_from(PackageFile).where(PackageFile.package_id == pkg_id)
    ) or 0
    total_bytes = await db.scalar(
        select(func.coalesce(func.sum(PackageFile.size_bytes), 0))
        .where(PackageFile.package_id == pkg_id)
    ) or 0

    # Audit row (BEFORE we strip the FK references, so this row also gets
    # NULL'd by the next statement — that's fine; details_json keeps the id).
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="admin_delete_pkg",
        ip=request.client.host if request.client else None,
        details_json=json.dumps({"pkg_id": pkg_id, "title": pkg.title,
                                 "direction": pkg.direction,
                                 "file_count": file_count,
                                 "total_bytes": int(total_bytes),
                                 "recipient_email": pkg.recipient_email}),
    ))

    # Null out package_id in audit log so the FK doesn't block the delete.
    # access_log.package_id was declared without ON DELETE behavior, and
    # PRAGMA foreign_keys is ON, so we have to do this manually.
    await db.execute(
        update(AccessLog).where(AccessLog.package_id == pkg_id).values(package_id=None)
    )

    # Delete files in storage first; if it fails we still want to NOT have
    # orphaned DB rows on success path, so we commit storage cleanup before
    # the DB delete. (If storage cleanup fails, the row stays and the user
    # can retry.)
    backend = get_backend(pkg.storage_backend)
    try:
        await backend.delete_package(pkg_id)
    except Exception:
        log.exception("storage delete_package failed for pkg=%s", pkg_id)
        # Don't abort the DB delete — leaving orphans on disk is worse than
        # leaving orphans in the DB. Continue and let admin sweep /srv/files.

    # Cascade-delete in DB (package_files, magic_link_tokens have ON DELETE CASCADE)
    await db.delete(pkg)
    await db.commit()
    log.info("deleted package pkg_id=%s files=%d bytes=%d by user_id=%s",
             pkg_id, file_count, total_bytes, user.id)
    try:
        await fire_event(db, "package.deleted", package_id=pkg_id, payload={
            "title": pkg.title, "file_count": file_count, "total_bytes": int(total_bytes),
        })
    except Exception:
        log.exception("webhook fire failed for pkg.deleted")
    return RedirectResponse("/dash", status_code=303)
