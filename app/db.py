"""Database engine + session helpers."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
    connect_args={"timeout": 30},
)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as s:
        try:
            yield s
            await s.commit()
        except Exception:
            await s.rollback()
            raise


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with AsyncSessionLocal() as s:
        try:
            yield s
        finally:
            await s.close()


async def init_pragmas() -> None:
    """Set SQLite WAL + foreign-key enforcement, run lightweight migrations."""
    from sqlalchemy import text
    from app.models import Base
    async with engine.begin() as conn:
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text("PRAGMA foreign_keys=ON"))
        await conn.execute(text("PRAGMA synchronous=NORMAL"))
        # Create any missing tables (idempotent — won't drop existing data).
        await conn.run_sync(Base.metadata.create_all)
        # Idempotent column additions (so the app can self-heal an old schema).
        for table, col, decl in (
            ("package_files", "duration_ms", "INTEGER"),
        ):
            rows = (await conn.execute(text(f"PRAGMA table_info({table})"))).all()
            if not any(r[1] == col for r in rows):
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {decl}"))
