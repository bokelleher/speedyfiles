"""SpeedyFiles REST API v1.

Mounted as a FastAPI sub-app at /api/v1, giving us:
  - /api/v1/openapi.json    (machine-readable spec)
  - /api/v1/docs            (Swagger UI)
  - /api/v1/redoc           (ReDoc)

Authentication: Bearer tokens issued via the web UI. Send as
  Authorization: Bearer <token>
The raw token is shown to the user exactly once at creation time.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    UploadFile,
)
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_db
from app.email import send_outbound_notification
from app.models import AccessLog, ApiToken, MagicLinkToken, Package, PackageFile, User
from app.storage import get_backend
from app.utils import gen_id, gen_magic_token, hash_token, sanitize_filename, utcnow
from app.webhooks import fire_event

log = logging.getLogger(__name__)

# ============================================================
# auth
# ============================================================

async def require_api_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate Bearer token; return User. 401 on missing/invalid/expired/revoked."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401, detail="missing bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="speedyfiles"'},
        )
    raw = authorization.split(" ", 1)[1].strip()
    if not raw:
        raise HTTPException(status_code=401, detail="empty bearer token")
    th = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    tok = await db.scalar(select(ApiToken).where(ApiToken.token_sha256 == th))
    if tok is None:
        raise HTTPException(status_code=401, detail="invalid token")
    if tok.revoked_at is not None:
        raise HTTPException(status_code=401, detail="token revoked")
    if tok.expires_at is not None and tok.expires_at <= utcnow():
        raise HTTPException(status_code=401, detail="token expired")
    user = await db.get(User, tok.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="account disabled")
    tok.last_used_at = utcnow()
    await db.commit()
    request.state.api_user = user
    request.state.api_token_id = tok.id
    return user


async def require_api_admin(user: User = Depends(require_api_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


# ============================================================
# pydantic schemas
# ============================================================

class TokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Human-friendly label for this token")
    expires_in_days: int | None = Field(None, ge=1, le=3650, description="Optional TTL; omit for non-expiring")


class TokenInfo(BaseModel):
    id: int
    name: str
    prefix: str
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class TokenCreated(TokenInfo):
    token: str = Field(..., description="The raw bearer token. Shown ONCE at creation. Store it now.")


class MeOut(BaseModel):
    id: int
    email: str   # trusted from DB; no need to revalidate
    display_name: str
    role: Literal["admin", "regular"]


class PackageCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    recipient_email: EmailStr
    recipient_name: str = Field(..., min_length=1, max_length=255)
    direction: Literal["outbound", "inbound"] = "outbound"
    ttl_days: int = Field(7, ge=1, le=90)
    note: str | None = Field(None, max_length=4000)


class PackageFileOut(BaseModel):
    id: str
    original_name: str
    size_bytes: int | None
    sha256: str | None
    content_type: str | None
    state: str
    duration_ms: int | None = None
    uploaded_at: datetime | None
    created_at: datetime


class PackageOut(BaseModel):
    id: str
    owner_user_id: int
    direction: str
    title: str
    note: str | None
    recipient_email: str
    recipient_name: str
    storage_backend: str
    transport_mode: str
    status: str
    expires_at: datetime
    created_at: datetime
    files: list[PackageFileOut] = []


class PackageList(BaseModel):
    total: int
    items: list[PackageOut]


class FinalizeOut(BaseModel):
    ok: bool
    redirect: str | None = None
    magic_link: str | None = Field(None, description="The full magic-link URL emailed to the recipient. Returned ONLY when called via API.")


# ============================================================
# /me
# ============================================================

me_router = APIRouter(tags=["me"])


@me_router.get("/me", response_model=MeOut, summary="Current authenticated user")
async def whoami(user: User = Depends(require_api_user)):
    return MeOut(id=user.id, email=user.email, display_name=user.display_name, role=user.role)


@me_router.get("/me/tokens", response_model=list[TokenInfo], summary="List your API tokens")
async def list_tokens(user: User = Depends(require_api_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    )).all()
    return [TokenInfo.model_validate(r, from_attributes=True) for r in rows]


@me_router.post("/me/tokens", response_model=TokenCreated, status_code=201,
                summary="Create a new API token (returns raw token ONCE)")
async def create_token(
    body: TokenCreate,
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
):
    raw = "sf_" + secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    row = ApiToken(
        user_id=user.id,
        token_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        name=body.name.strip(),
        prefix=raw[:11],  # "sf_" + first 8 chars of secret
        expires_at=expires,
    )
    db.add(row)
    await db.flush()
    await db.commit()
    return TokenCreated(
        id=row.id, name=row.name, prefix=row.prefix,
        expires_at=row.expires_at, last_used_at=None, revoked_at=None,
        created_at=row.created_at, token=raw,
    )


@me_router.delete("/me/tokens/{token_id}", status_code=204, summary="Revoke an API token")
async def revoke_token(
    token_id: int = Path(..., ge=1),
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(ApiToken, token_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404)
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        await db.commit()
    return


# ============================================================
# /packages
# ============================================================

pkg_router = APIRouter(tags=["packages"])


def _to_pkg_out(pkg: Package, files: list[PackageFile]) -> PackageOut:
    return PackageOut(
        id=pkg.id, owner_user_id=pkg.owner_user_id, direction=pkg.direction,
        title=pkg.title, note=pkg.note,
        recipient_email=pkg.recipient_email, recipient_name=pkg.recipient_name,
        storage_backend=pkg.storage_backend, transport_mode=pkg.transport_mode,
        status=pkg.status, expires_at=pkg.expires_at, created_at=pkg.created_at,
        files=[PackageFileOut.model_validate(f, from_attributes=True) for f in files],
    )


@pkg_router.get("/packages", response_model=PackageList, summary="List packages")
async def list_packages(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(Package).order_by(Package.created_at.desc())
    cq = select(func.count()).select_from(Package)
    if user.role != "admin":
        q = q.where(Package.owner_user_id == user.id)
        cq = cq.where(Package.owner_user_id == user.id)
    total = await db.scalar(cq) or 0
    pkgs = (await db.scalars(q.limit(limit).offset(offset))).all()
    out: list[PackageOut] = []
    for p in pkgs:
        files = (await db.scalars(
            select(PackageFile).where(PackageFile.package_id == p.id)
            .order_by(PackageFile.created_at)
        )).all()
        out.append(_to_pkg_out(p, files))
    return PackageList(total=total, items=out)


@pkg_router.post("/packages", response_model=PackageOut, status_code=201,
                 summary="Create a new package (draft, no files yet)")
async def create_package(
    body: PackageCreate,
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    pkg_id = gen_id(16)
    expires = utcnow() + timedelta(days=body.ttl_days)
    backend = get_backend()
    await backend.init_package(pkg_id)

    pkg = Package(
        id=pkg_id, owner_user_id=user.id, direction=body.direction,
        title=body.title.strip(),
        note=(body.note or "").strip() or None,
        recipient_email=str(body.recipient_email).lower(),
        recipient_name=body.recipient_name.strip(),
        storage_backend=backend.name, transport_mode="http",
        status="draft" if body.direction == "outbound" else "active",
        expires_at=expires,
    )
    db.add(pkg)
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="api_create_pkg",
        ip=request.client.host if request and request.client else None,
        details_json=json.dumps({"direction": body.direction, "via": "api"}),
    ))

    # Inbound packages get a magic link minted immediately so the recipient
    # can upload. Outbound packages wait for /finalize after file uploads.
    if body.direction == "inbound":
        raw_token = gen_magic_token()
        db.add(MagicLinkToken(
            package_id=pkg_id, token_sha256=hash_token(raw_token),
            recipient_email=pkg.recipient_email, purpose="upload",
            expires_at=expires,
        ))
    await db.commit()
    return _to_pkg_out(pkg, [])


@pkg_router.get("/packages/{pkg_id}", response_model=PackageOut, summary="Get a package by id")
async def get_package(
    pkg_id: str,
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
):
    pkg = await db.get(Package, pkg_id)
    if pkg is None:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    files = (await db.scalars(
        select(PackageFile).where(PackageFile.package_id == pkg_id)
        .order_by(PackageFile.created_at)
    )).all()
    return _to_pkg_out(pkg, files)


@pkg_router.post("/packages/{pkg_id}/files", response_model=PackageFileOut, status_code=201,
                 summary="Upload a file to an existing package")
async def upload_file(
    pkg_id: str,
    file: UploadFile = File(..., description="The file to upload (multipart/form-data)"),
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    pkg = await db.get(Package, pkg_id)
    if pkg is None:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    if pkg.direction != "outbound":
        raise HTTPException(status_code=400, detail="files can only be uploaded to outbound packages via this endpoint")
    if pkg.status not in ("draft", "active"):
        raise HTTPException(status_code=400, detail=f"package status is {pkg.status!r}")
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
    t0 = time.monotonic()
    stored = await backend.put_file(pkg_id, file_id, sanitized, _gen())
    duration_ms = int((time.monotonic() - t0) * 1000)
    pf = PackageFile(
        id=file_id, package_id=pkg_id,
        original_name=file.filename, sanitized_name=sanitized,
        size_bytes=stored.size_bytes, sha256=stored.sha256,
        content_type=file.content_type, storage_key=stored.storage_key,
        state="complete", uploaded_at=utcnow(), duration_ms=duration_ms,
    )
    db.add(pf)
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="api_add_file",
        ip=request.client.host if request and request.client else None,
        details_json=json.dumps({"file_id": file_id, "size": stored.size_bytes,
                                 "duration_ms": duration_ms}),
    ))
    await db.commit()
    try:
        await fire_event(db, "package.file_uploaded", package_id=pkg_id, payload={
            "file_id": file_id, "size_bytes": stored.size_bytes,
            "original_name": file.filename, "duration_ms": duration_ms,
            "uploaded_by": "api",
        })
    except Exception:
        log.exception("webhook fire failed: api package.file_uploaded")
    return PackageFileOut.model_validate(pf, from_attributes=True)


@pkg_router.post("/packages/{pkg_id}/finalize", response_model=FinalizeOut,
                 summary="Mint magic link + send notification email (outbound only)")
async def finalize_package(
    pkg_id: str,
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
):
    pkg = await db.get(Package, pkg_id)
    if pkg is None:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    if pkg.direction != "outbound":
        raise HTTPException(status_code=400, detail="not an outbound package")
    if pkg.status == "active":
        return FinalizeOut(ok=True, redirect=f"/dash/packages/{pkg_id}")
    file_count = await db.scalar(
        select(func.count()).select_from(PackageFile)
        .where(PackageFile.package_id == pkg_id, PackageFile.state == "complete")
    )
    if not file_count:
        raise HTTPException(status_code=400, detail="package has no completed files yet")

    raw_token = gen_magic_token()
    db.add(MagicLinkToken(
        package_id=pkg.id, token_sha256=hash_token(raw_token),
        recipient_email=pkg.recipient_email, purpose="download",
        expires_at=pkg.expires_at,
    ))
    pkg.status = "active"
    await db.commit()

    link_url = f"{settings.public_base_url}/p/{raw_token}"
    try:
        await send_outbound_notification(
            db,
            to_email=pkg.recipient_email, to_name=pkg.recipient_name,
            sender_name=user.display_name, package_title=pkg.title,
            note=pkg.note, link_url=link_url,
            expires_at=pkg.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            file_count=file_count,
        )
    except Exception:
        log.exception("api finalize: email send failed for pkg=%s", pkg_id)
    try:
        await fire_event(db, "package.finalized", package_id=pkg_id, payload={
            "title": pkg.title, "recipient_email": pkg.recipient_email,
            "owner_user_id": pkg.owner_user_id, "file_count": file_count,
            "expires_at": pkg.expires_at.isoformat(),
        })
    except Exception:
        log.exception("webhook fire failed: api package.finalized")
    return FinalizeOut(ok=True, redirect=f"/dash/packages/{pkg_id}",
                       magic_link=link_url)


@pkg_router.post("/packages/{pkg_id}/revoke", response_model=PackageOut,
                 summary="Revoke a package's magic links")
async def revoke_package(
    pkg_id: str,
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    pkg = await db.get(Package, pkg_id)
    if pkg is None:
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
        user_id=user.id, package_id=pkg_id, action="api_revoke",
        ip=request.client.host if request and request.client else None,
    ))
    await db.commit()
    try:
        await fire_event(db, "package.revoked", package_id=pkg_id, payload={
            "title": pkg.title, "recipient_email": pkg.recipient_email,
        })
    except Exception:
        log.exception("webhook fire failed: api package.revoked")
    files = (await db.scalars(
        select(PackageFile).where(PackageFile.package_id == pkg_id)
        .order_by(PackageFile.created_at)
    )).all()
    return _to_pkg_out(pkg, files)


@pkg_router.delete("/packages/{pkg_id}", status_code=204,
                   summary="Permanently delete a package + its files")
async def delete_package(
    pkg_id: str,
    user: User = Depends(require_api_user),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    from sqlalchemy import update
    pkg = await db.get(Package, pkg_id)
    if pkg is None:
        raise HTTPException(status_code=404)
    if user.role != "admin" and pkg.owner_user_id != user.id:
        raise HTTPException(status_code=403)
    file_count = await db.scalar(
        select(func.count()).select_from(PackageFile).where(PackageFile.package_id == pkg_id)
    ) or 0
    total_bytes = await db.scalar(
        select(func.coalesce(func.sum(PackageFile.size_bytes), 0))
        .where(PackageFile.package_id == pkg_id)
    ) or 0
    db.add(AccessLog(
        user_id=user.id, package_id=pkg_id, action="api_delete_pkg",
        ip=request.client.host if request and request.client else None,
        details_json=json.dumps({"pkg_id": pkg_id, "title": pkg.title,
                                 "file_count": file_count,
                                 "total_bytes": int(total_bytes)}),
    ))
    await db.execute(
        update(AccessLog).where(AccessLog.package_id == pkg_id).values(package_id=None)
    )
    backend = get_backend(pkg.storage_backend)
    try:
        await backend.delete_package(pkg_id)
    except Exception:
        log.exception("api delete: storage cleanup failed for pkg=%s", pkg_id)
    pkg_title, pkg_recipient = pkg.title, pkg.recipient_email
    await db.delete(pkg)
    await db.commit()
    try:
        await fire_event(db, "package.deleted", package_id=pkg_id, payload={
            "title": pkg_title, "recipient_email": pkg_recipient,
            "file_count": file_count, "total_bytes": int(total_bytes),
        })
    except Exception:
        log.exception("webhook fire failed: api package.deleted")
    return


# ============================================================
# build the API sub-app
# ============================================================

def build_api_app() -> FastAPI:
    api_app = FastAPI(
        title="SpeedyFiles API",
        version="v1",
        description=(
            "Programmatic access to packages, files, and magic links.\n\n"
            "## Authentication\n"
            "Pass your token in the `Authorization` header:\n\n"
            "    Authorization: Bearer sf_xxxxxxxxxxxxxxxxxx\n\n"
            "Create a token via the web UI under **Account → API tokens**, or "
            "via the `POST /me/tokens` endpoint (web session required).\n\n"
            "Tokens inherit the role of the user that created them. "
            "Admin tokens can see/modify all packages; regular tokens are scoped "
            "to packages owned by that user.\n\n"
            "## Errors\n"
            "Standard HTTP status codes. Errors come back as `{\"detail\": \"...\"}`."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    api_app.include_router(me_router)
    api_app.include_router(pkg_router)

    @api_app.get("/health", tags=["health"], summary="Health check")
    async def api_health():
        return {"status": "ok"}

    return api_app
