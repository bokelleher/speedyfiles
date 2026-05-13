"""Login / logout / self-service account routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password, make_session_cookie, require_user, verify_password
from app.config import settings
from app.db import get_db
from app.models import AccessLog, User
from app.templating import templates
from app.utils import utcnow

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(request, "pages/login.html", {"error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(User).where(User.email == email, User.is_active == 1))
    ok = bool(user) and verify_password(user.password_hash, password)
    db.add(AccessLog(
        ts=utcnow(),
        user_id=user.id if user else None,
        action="login_success" if ok else "login_fail",
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details_json=None,
    ))
    await db.commit()

    if not ok:
        return templates.TemplateResponse(
            request, "pages/login.html", {"error": "invalid email or password"},
            status_code=401,
        )

    user.last_login_at = utcnow()
    await db.commit()

    cookie_value, _csrf = make_session_cookie(user.id)
    resp = RedirectResponse("/dash", status_code=303)
    resp.set_cookie(
        settings.session_cookie_name,
        cookie_value,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        secure=not settings.debug,
        samesite="lax",
        path="/",
    )
    return resp


@router.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(settings.session_cookie_name, path="/")
    return resp


# --- Self-service account ---

@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse(
        request, "pages/account.html",
        {"user": user, "message": None, "error": None},
    )


@router.post("/account/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    error: str | None = None
    if not verify_password(user.password_hash, current_password):
        error = "Current password is incorrect."
    elif len(new_password) < 10:
        error = "New password must be at least 10 characters."
    elif new_password != confirm_password:
        error = "New password and confirmation do not match."
    elif new_password == current_password:
        error = "New password must differ from current password."

    if error:
        db.add(AccessLog(
            user_id=user.id, action="self_pw_change_fail",
            ip=request.client.host if request.client else None,
            details_json=None,
        ))
        await db.commit()
        return templates.TemplateResponse(
            request, "pages/account.html",
            {"user": user, "message": None, "error": error},
            status_code=400,
        )

    user.password_hash = hash_password(new_password)
    db.add(AccessLog(
        user_id=user.id, action="self_pw_change",
        ip=request.client.host if request.client else None,
    ))
    await db.commit()
    return templates.TemplateResponse(
        request, "pages/account.html",
        {"user": user, "message": "Password updated.", "error": None},
    )


# --- API tokens (self-service) ---

import hashlib as _hashlib
import secrets as _secrets
from datetime import timedelta

from app.models import ApiToken


@router.get("/account/tokens", response_class=HTMLResponse)
async def list_tokens(
    request: Request,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id)
        .order_by(ApiToken.created_at.desc())
    )).all()
    new_token = request.query_params.get("new")  # raw token shown once
    return templates.TemplateResponse(
        request, "pages/account_tokens.html",
        {"user": user, "tokens": rows, "new_token": new_token},
    )


@router.post("/account/tokens")
async def create_token(
    request: Request,
    name: str = Form(...),
    expires_in_days: str = Form(""),
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    raw = "sf_" + _secrets.token_urlsafe(32)
    ttl = None
    if expires_in_days.strip():
        try:
            ttl = int(expires_in_days)
            if ttl < 1 or ttl > 3650:
                ttl = None
        except ValueError:
            ttl = None
    expires = utcnow() + timedelta(days=ttl) if ttl else None
    db.add(ApiToken(
        user_id=user.id,
        token_sha256=_hashlib.sha256(raw.encode()).hexdigest(),
        name=name.strip()[:128] or "token",
        prefix=raw[:11],
        expires_at=expires,
    ))
    await db.commit()
    return RedirectResponse(f"/account/tokens?new={raw}", status_code=303)


@router.post("/account/tokens/{tok_id}/revoke")
async def revoke_token(
    tok_id: int,
    user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(ApiToken, tok_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404)
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        await db.commit()
    return RedirectResponse("/account/tokens", status_code=303)


# --- Password reset (forgot-password flow) ---

from app.config import settings as app_settings
from app.email import send_email
from app.models import PasswordResetToken


@router.get("/forgot", response_class=HTMLResponse)
async def forgot_form(request: Request):
    return templates.TemplateResponse(
        request, "pages/forgot.html",
        {"message": None, "error": None, "submitted": False},
    )


@router.post("/forgot")
async def forgot_submit(
    request: Request,
    email: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Always returns success — never leak whether an email exists.
    Internally we mint a reset token and email it if the user is found."""
    email = email.strip().lower()
    user = await db.scalar(select(User).where(User.email == email, User.is_active == 1))
    if user:
        raw = _secrets.token_urlsafe(32)
        from datetime import timedelta as _td
        db.add(PasswordResetToken(
            user_id=user.id,
            token_sha256=_hashlib.sha256(raw.encode()).hexdigest(),
            expires_at=utcnow() + _td(hours=2),
        ))
        await db.commit()
        reset_url = f"{app_settings.public_base_url}/reset/{raw}"
        try:
            await send_email(
                db,
                to_addr=user.email,
                subject=f"{app_settings.app_name} — password reset",
                text_body=(
                    f"Hi {user.display_name},\n\n"
                    f"Someone (hopefully you) requested a password reset for your\n"
                    f"{app_settings.app_name} account.\n\n"
                    f"Reset link (expires in 2 hours):\n{reset_url}\n\n"
                    f"If you didn't ask for this, you can safely ignore this email.\n"
                ),
                html_body=(
                    f"<p>Hi {user.display_name},</p>"
                    f"<p>Someone (hopefully you) requested a password reset for your "
                    f"<b>{app_settings.app_name}</b> account.</p>"
                    f"<p><a href='{reset_url}' style='background:#4f9eed;color:#fff;"
                    f"padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600'>"
                    f"Reset password</a></p>"
                    f"<p style='font-size:12px;color:#888'>Link expires in 2 hours. "
                    f"If the button doesn't work, paste this URL: <code>{reset_url}</code></p>"
                    f"<p style='font-size:11px;color:#aaa'>If you didn't ask for this, you can safely ignore this email.</p>"
                ),
            )
        except Exception:
            log = __import__('logging').getLogger(__name__)
            log.exception("password reset email send failed")
        db.add(AccessLog(
            user_id=user.id, action="password_reset_request",
            ip=request.client.host if request.client else None,
        ))
        await db.commit()
    return templates.TemplateResponse(
        request, "pages/forgot.html",
        {"message": "If that email is registered, a reset link has been sent. "
                    "Check your inbox (and spam folder) for an email from "
                    f"{app_settings.app_name}.",
         "error": None, "submitted": True},
    )


@router.get("/reset/{raw}", response_class=HTMLResponse)
async def reset_form(raw: str, request: Request, db: AsyncSession = Depends(get_db)):
    th = _hashlib.sha256(raw.encode()).hexdigest()
    tok = await db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_sha256 == th))
    if not tok or tok.used_at or tok.expires_at <= utcnow():
        return templates.TemplateResponse(
            request, "pages/reset.html",
            {"valid": False, "message": None, "raw": ""}, status_code=410,
        )
    return templates.TemplateResponse(
        request, "pages/reset.html",
        {"valid": True, "message": None, "raw": raw},
    )


@router.post("/reset/{raw}")
async def reset_submit(
    raw: str, request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    th = _hashlib.sha256(raw.encode()).hexdigest()
    tok = await db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_sha256 == th))
    if not tok or tok.used_at or tok.expires_at <= utcnow():
        return templates.TemplateResponse(
            request, "pages/reset.html",
            {"valid": False, "message": None, "raw": ""}, status_code=410,
        )
    if len(new_password) < 10:
        return templates.TemplateResponse(
            request, "pages/reset.html",
            {"valid": True, "message": "Password must be at least 10 characters.",
             "raw": raw}, status_code=400,
        )
    if new_password != confirm_password:
        return templates.TemplateResponse(
            request, "pages/reset.html",
            {"valid": True, "message": "Passwords do not match.", "raw": raw},
            status_code=400,
        )
    user = await db.get(User, tok.user_id)
    if not user:
        raise HTTPException(status_code=404)
    user.password_hash = hash_password(new_password)
    tok.used_at = utcnow()
    db.add(AccessLog(
        user_id=user.id, action="password_reset_complete",
        ip=request.client.host if request.client else None,
    ))
    await db.commit()
    return RedirectResponse("/login?reset=1", status_code=303)
