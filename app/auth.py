"""Password hashing, session cookies, FastAPI auth dependencies."""
from __future__ import annotations

import json
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, TimestampSigner
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_db
from app.models import User

ph = PasswordHasher()
_signer = TimestampSigner(settings.session_secret)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


def make_session_cookie(user_id: int) -> tuple[str, str]:
    """Returns (cookie_value, csrf_token)."""
    csrf = secrets.token_urlsafe(24)
    payload = json.dumps({"u": user_id, "c": csrf}, separators=(",", ":"))
    signed = _signer.sign(payload.encode("utf-8")).decode("utf-8")
    return signed, csrf


def read_session_cookie(value: str) -> dict | None:
    try:
        raw = _signer.unsign(value, max_age=settings.session_max_age_seconds)
        return json.loads(raw.decode("utf-8"))
    except (BadSignature, ValueError):
        return None


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Returns the User or None. Use require_user for endpoints needing auth."""
    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        return None
    data = read_session_cookie(cookie)
    if not data:
        return None
    user_id = data.get("u")
    if not isinstance(user_id, int):
        return None
    user = await db.scalar(select(User).where(User.id == user_id, User.is_active == 1))
    if user:
        # Stash csrf for the middleware/template to read
        request.state.csrf_token = data.get("c")
    return user


async def require_user(user: User | None = Depends(get_current_user)) -> User:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")
    return user


async def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    return user
