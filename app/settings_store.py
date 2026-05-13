"""Runtime-editable settings store, backed by the `app_settings` table.

- `get(key, default)`: returns the deserialized value or `default`.
- `set(key, value, secret=False, user_id=None)`: upserts; encrypts if `secret=True`.
- `get_section(prefix)`: returns dict of all keys under a prefix (prefix stripped).
- `set_section(prefix, dict, secrets={...})`: bulk upsert.

Secret values are encrypted at rest with Fernet, using a key derived
deterministically from `settings.session_secret` so the same .env file
roundtrips across restarts (no extra secret to manage).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as env_settings
from app.models import AppSetting
from app.utils import utcnow

log = logging.getLogger(__name__)


def _fernet() -> Fernet:
    """Derive a stable 32-byte key from session_secret for encrypting secrets."""
    digest = hashlib.sha256(b"app_settings|" + env_settings.session_secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def _decrypt(cipher: str) -> str:
    try:
        return _fernet().decrypt(cipher.encode("ascii")).decode("utf-8")
    except InvalidToken:
        log.warning("settings_store: failed to decrypt a value (session_secret changed?)")
        return ""


async def get(db: AsyncSession, key: str, default: Any = None) -> Any:
    row = await db.get(AppSetting, key)
    if row is None or row.value is None:
        return default
    raw = row.value
    if row.is_secret:
        raw = _decrypt(raw)
    try:
        return json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return raw  # legacy / non-JSON values


async def set(
    db: AsyncSession, key: str, value: Any, *,
    secret: bool = False, user_id: int | None = None,
) -> None:
    raw = json.dumps(value)
    if secret:
        raw = _encrypt(raw)
    row = await db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key, value=raw, is_secret=1 if secret else 0,
                         updated_at=utcnow(), updated_by=user_id)
        db.add(row)
    else:
        row.value = raw
        row.is_secret = 1 if secret else 0
        row.updated_at = utcnow()
        row.updated_by = user_id


async def get_section(db: AsyncSession, prefix: str) -> dict[str, Any]:
    """All settings whose key starts with `prefix + '.'`; the prefix is stripped."""
    pfx = prefix + "."
    out: dict[str, Any] = {}
    rows = (await db.scalars(select(AppSetting).where(AppSetting.key.like(pfx + "%")))).all()
    for r in rows:
        raw = r.value
        if raw is None:
            continue
        if r.is_secret:
            raw = _decrypt(raw)
        try:
            v = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            v = raw
        out[r.key[len(pfx):]] = v
    return out


async def set_section(
    db: AsyncSession, prefix: str, values: dict[str, Any],
    *, secrets: set[str] | None = None, user_id: int | None = None,
) -> None:
    secrets = secrets or set()
    for k, v in values.items():
        await set(db, f"{prefix}.{k}", v, secret=(k in secrets), user_id=user_id)


async def delete(db: AsyncSession, key: str) -> None:
    row = await db.get(AppSetting, key)
    if row is not None:
        await db.delete(row)
