"""Pytest fixtures for SpeedyFiles."""
from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from collections.abc import AsyncIterator

# Set required env vars BEFORE importing the app
os.environ.setdefault("SESSION_SECRET", "test-secret-for-pytest-must-be-long-enough")
# Use a temp file DB rather than :memory: — aiosqlite memory DBs aren't shared
# across connections, which breaks tests that span fixture + ASGI client.
_test_db_path = tempfile.mkdtemp(prefix="speedyfiles-test-db-") + "/app.db"
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_test_db_path}")
os.environ.setdefault("PUBLIC_BASE_URL", "http://test.local")
os.environ.setdefault("STORAGE_BACKEND", "local")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture(scope="session")
def tmp_storage_root(tmp_path_factory) -> str:
    """A clean filesystem root for the local storage backend."""
    root = tmp_path_factory.mktemp("speedyfiles-storage")
    os.environ["LOCAL_STORAGE_ROOT"] = str(root)
    return str(root)


@pytest_asyncio.fixture(scope="session")
async def _schema_init(tmp_storage_root):
    """Session-scoped: create the schema once. Avoids stale-pool issues that
    would otherwise arise from dropping/recreating tables every test."""
    from app.db import engine, init_pragmas
    from app.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await init_pragmas()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def app(_schema_init, capsys):
    """FastAPI app instance; truncates user-data tables before each test for isolation.

    Always seeds a placeholder user so the setup-required middleware doesn't
    redirect requests to /setup during tests. Per-test admin fixtures create
    additional users as needed.
    """
    from app.auth import hash_password
    from app.db import AsyncSessionLocal, engine
    from app.models import (
        AccessLog,
        ApiToken,
        AppSetting,
        MagicLinkToken,
        Package,
        PackageFile,
        PasswordResetToken,
        User,
        Webhook,
    )
    async with engine.begin() as conn:
        for tbl in (AccessLog, MagicLinkToken, PackageFile, Package,
                    ApiToken, AppSetting, Webhook, PasswordResetToken, User):
            await conn.execute(tbl.__table__.delete())
    async with AsyncSessionLocal() as s:
        s.add(User(email="placeholder@test.local", display_name="placeholder",
                   password_hash=hash_password("placeholder-pw-not-used"),
                   role="regular", is_active=0))
        await s.commit()
    from app.main import app as fastapi_app
    yield fastapi_app


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test.local") as c:
        yield c


@pytest_asyncio.fixture
async def db_session(app) -> AsyncIterator[AsyncSession]:
    """Depends on `app` so tables are created before the session is used."""
    from app.db import AsyncSessionLocal
    async with AsyncSessionLocal() as s:
        yield s


@pytest_asyncio.fixture
async def admin_user(db_session):
    """Create an admin user; return (user, password)."""
    from app.auth import hash_password
    from app.models import User
    pw = "test-admin-password-strong"
    u = User(
        email="admin@test.local",
        display_name="Admin",
        password_hash=hash_password(pw),
        role="admin",
        is_active=1,
    )
    db_session.add(u)
    await db_session.commit()
    await db_session.refresh(u)
    return u, pw


@pytest_asyncio.fixture
async def admin_api_token(db_session, admin_user):
    """Create an API token for the admin user; return the raw bearer."""
    from app.models import ApiToken
    user, _ = admin_user
    raw = "sf_test_" + secrets.token_urlsafe(24)
    db_session.add(ApiToken(
        user_id=user.id,
        token_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        name="pytest",
        prefix=raw[:11],
    ))
    await db_session.commit()
    return raw
