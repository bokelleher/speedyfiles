"""Public magic-link routes — no internal auth required.

Per requirements, all hits are audited; invalid/expired/revoked tokens 410.
"""
from __future__ import annotations

import json
import logging
import urllib.parse

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import AccessLog, MagicLinkToken, Package, PackageFile
from app.storage import get_backend
from app.storage.local import LocalStorage
from app.templating import templates
from app.utils import gen_id, hash_token, sanitize_filename, stream_zip_files, utcnow
from app.webhooks import fire_event

log = logging.getLogger(__name__)
router = APIRouter()


async def _resolve_token(db: AsyncSession, raw: str) -> tuple[MagicLinkToken, Package] | None:
    th = hash_token(raw)
    tok = await db.scalar(select(MagicLinkToken).where(MagicLinkToken.token_sha256 == th))
    if not tok:
        return None
    pkg = await db.get(Package, tok.package_id)
    if not pkg:
        return None
    return tok, pkg


async def _audit(
    db: AsyncSession, request: Request, *,
    action: str, token: MagicLinkToken | None = None, package_id: str | None = None,
    details: dict | None = None,
) -> None:
    db.add(AccessLog(
        ts=utcnow(),
        token_id=token.id if token else None,
        package_id=package_id or (token.package_id if token else None),
        action=action,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details_json=json.dumps(details) if details else None,
    ))


def _link_dead(tok: MagicLinkToken, pkg: Package) -> str | None:
    now = utcnow()
    if pkg.status == "revoked" or tok.revoked_at is not None:
        return "token_revoked"
    if pkg.status != "active":
        return "token_invalid"
    if tok.expires_at <= now or pkg.expires_at <= now:
        return "token_expired"
    return None


def _render_dead(request: Request, reason: str, status_code: int = 410) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "pages/expired.html", {"reason": reason}, status_code=status_code,
    )


@router.get("/p/{raw}", response_class=HTMLResponse)
async def public_landing(raw: str, request: Request, db: AsyncSession = Depends(get_db)):
    resolved = await _resolve_token(db, raw)
    if not resolved:
        await _audit(db, request, action="token_invalid")
        await db.commit()
        return _render_dead(request, "invalid")

    tok, pkg = resolved
    dead = _link_dead(tok, pkg)
    if dead:
        await _audit(db, request, action=dead, token=tok)
        await db.commit()
        return _render_dead(request, dead.removeprefix("token_"))

    tok.use_count += 1
    tok.last_used_at = utcnow()
    await _audit(db, request, action="token_view", token=tok)
    await db.commit()

    if tok.purpose == "download":
        files = (await db.scalars(
            select(PackageFile).where(
                PackageFile.package_id == pkg.id,
                PackageFile.state == "complete",
            ).order_by(PackageFile.created_at)
        )).all()
        return templates.TemplateResponse(
            request, "pages/public_download.html",
            {"pkg": pkg, "files": files, "token": raw},
        )
    files = (await db.scalars(
        select(PackageFile).where(PackageFile.package_id == pkg.id)
        .order_by(PackageFile.created_at)
    )).all()
    return templates.TemplateResponse(
        request, "pages/public_upload.html",
        {"pkg": pkg, "files": files, "token": raw},
    )


@router.get("/p/{raw}/zip")
async def public_download_zip(
    raw: str, request: Request, db: AsyncSession = Depends(get_db),
):
    """Bundle all completed files in a download-purpose package into a
    single streamed ZIP. Local-storage only at v1."""
    resolved = await _resolve_token(db, raw)
    if not resolved:
        await _audit(db, request, action="token_invalid")
        await db.commit()
        return _render_dead(request, "invalid")
    tok, pkg = resolved
    dead = _link_dead(tok, pkg)
    if dead or tok.purpose != "download":
        await _audit(db, request, action=dead or "token_invalid", token=tok)
        await db.commit()
        return _render_dead(request, (dead or "token_invalid").removeprefix("token_"))

    if pkg.storage_backend != "local":
        raise HTTPException(status_code=400,
                            detail="bulk zip download is only available for local-storage packages")

    files = (await db.scalars(
        select(PackageFile).where(
            PackageFile.package_id == pkg.id,
            PackageFile.state == "complete",
        ).order_by(PackageFile.created_at)
    )).all()
    if not files:
        raise HTTPException(status_code=404, detail="no files to download")

    # Resolve disk paths via the backend (with its safety guard against
    # storage-key traversal).
    backend = LocalStorage()
    members: list[tuple[str, str]] = []
    total_bytes = 0
    seen_names: set[str] = set()
    for pf in files:
        # Disambiguate duplicate filenames inside the zip
        arc = pf.original_name
        n = 2
        while arc in seen_names:
            base, _, ext = pf.original_name.rpartition(".")
            arc = f"{base} ({n}).{ext}" if ext else f"{pf.original_name} ({n})"
            n += 1
        seen_names.add(arc)
        ticket = await backend.get_download_ticket(pkg.id, pf.id, pf.storage_key, pf.original_name)
        if not ticket.stream_path:
            continue
        members.append((arc, ticket.stream_path))
        total_bytes += pf.size_bytes or 0

    # Audit + webhook fire
    await _audit(db, request, action="file_download_zip", token=tok,
                 details={"file_count": len(members), "total_bytes": total_bytes})
    await db.commit()
    try:
        await fire_event(db, "package.downloaded", package_id=pkg.id, payload={
            "kind": "zip", "file_count": len(members), "total_bytes": total_bytes,
            "ip": request.client.host if request.client else None,
        })
    except Exception:
        log.exception("webhook fire failed for pkg.downloaded (zip)")

    # Build a sensible filename. Sanitize the package title for filesystem safety.
    safe_title = sanitize_filename(pkg.title or "package").rstrip(".") or "package"
    zip_name = f"{safe_title}.zip"
    quoted = urllib.parse.quote(zip_name)
    return StreamingResponse(
        stream_zip_files(members),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quoted}"},
    )


@router.get("/p/{raw}/file/{file_id}")
async def public_download(
    raw: str, file_id: str, request: Request, db: AsyncSession = Depends(get_db),
):
    resolved = await _resolve_token(db, raw)
    if not resolved:
        await _audit(db, request, action="token_invalid")
        await db.commit()
        return _render_dead(request, "invalid")
    tok, pkg = resolved
    dead = _link_dead(tok, pkg)
    if dead or tok.purpose != "download":
        await _audit(db, request, action=dead or "token_invalid", token=tok)
        await db.commit()
        return _render_dead(request, (dead or "token_invalid").removeprefix("token_"))

    pf = await db.get(PackageFile, file_id)
    if not pf or pf.package_id != pkg.id or pf.state != "complete":
        raise HTTPException(status_code=404)

    backend = get_backend(pkg.storage_backend)
    ticket = await backend.get_download_ticket(
        pkg.id, pf.id, pf.storage_key, pf.original_name,
    )
    await _audit(db, request, action="file_download", token=tok,
                 details={"file_id": pf.id, "size": pf.size_bytes})
    await db.commit()
    try:
        await fire_event(db, "package.downloaded", package_id=pkg.id, payload={
            "file_id": pf.id, "original_name": pf.original_name,
            "size_bytes": pf.size_bytes, "ip": request.client.host if request.client else None,
        })
    except Exception:
        log.exception("webhook fire failed for pkg.downloaded")

    if ticket.kind == "http_redirect" and ticket.url:
        return RedirectResponse(ticket.url, status_code=302)
    if ticket.kind == "http_stream" and ticket.stream_path:
        filename_quoted = urllib.parse.quote(pf.original_name)
        return FileResponse(
            ticket.stream_path, media_type=pf.content_type or "application/octet-stream",
            filename=pf.original_name,
            headers={
                "Content-Disposition": (
                    f"attachment; filename*=UTF-8''{filename_quoted}"
                ),
            },
        )
    raise HTTPException(status_code=500, detail="unhandled ticket kind")


@router.post("/p/{raw}/upload")
async def public_upload(
    raw: str, request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    resolved = await _resolve_token(db, raw)
    if not resolved:
        await _audit(db, request, action="token_invalid")
        await db.commit()
        raise HTTPException(status_code=410, detail="invalid")
    tok, pkg = resolved
    dead = _link_dead(tok, pkg)
    if dead or tok.purpose != "upload":
        await _audit(db, request, action=dead or "token_invalid", token=tok)
        await db.commit()
        raise HTTPException(status_code=410, detail=dead or "invalid")

    if not file.filename:
        raise HTTPException(status_code=400, detail="filename required")

    file_id = gen_id(8)
    sanitized = sanitize_filename(file.filename)

    await _audit(db, request, action="file_upload_start", token=tok,
                 details={"file_id": file_id, "filename": file.filename})
    await db.commit()

    backend = get_backend(pkg.storage_backend)
    async def _gen():
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            yield chunk

    import time
    t0 = time.monotonic()
    stored = await backend.put_file(pkg.id, file_id, sanitized, _gen())
    duration_ms = int((time.monotonic() - t0) * 1000)

    db.add(PackageFile(
        id=file_id, package_id=pkg.id,
        original_name=file.filename, sanitized_name=sanitized,
        size_bytes=stored.size_bytes, sha256=stored.sha256,
        content_type=file.content_type, storage_key=stored.storage_key,
        state="complete", uploaded_at=utcnow(), duration_ms=duration_ms,
    ))
    await _audit(db, request, action="file_upload_complete", token=tok,
                 details={"file_id": file_id, "size": stored.size_bytes,
                          "duration_ms": duration_ms})
    await db.commit()
    try:
        await fire_event(db, "package.file_uploaded", package_id=pkg.id, payload={
            "file_id": file_id, "original_name": file.filename,
            "size_bytes": stored.size_bytes, "duration_ms": duration_ms,
            "uploaded_by": "recipient",
        })
    except Exception:
        log.exception("webhook fire failed for inbound file_uploaded")

    return {"ok": True, "file_id": file_id, "size": stored.size_bytes,
            "sha256": stored.sha256, "duration_ms": duration_ms}
