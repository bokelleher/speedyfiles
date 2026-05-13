"""Admin CLI: create the first user, reset passwords, etc.

Usage:
  python -m app.cli create-user --email a@b.com --name 'Bo' --role admin --password '...'
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from app.auth import hash_password
from app.db import AsyncSessionLocal, init_pragmas, engine
from app.models import Base, User
from app.utils import utcnow


async def _create_user(email: str, name: str, role: str, password: str) -> None:
    await init_pragmas()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        existing = await db.scalar(select(User).where(User.email == email))
        if existing:
            print(f"user {email!r} already exists (id={existing.id})", file=sys.stderr)
            sys.exit(2)
        u = User(
            email=email.lower(),
            display_name=name,
            password_hash=hash_password(password),
            role=role,
            is_active=1,
            created_at=utcnow(),
        )
        db.add(u)
        await db.commit()
        await db.refresh(u)
        print(f"created user id={u.id} email={u.email} role={u.role}")


async def _init_db() -> None:
    await init_pragmas()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("schema created (idempotent).")


def main() -> None:
    p = argparse.ArgumentParser(prog="files-cli")
    sub = p.add_subparsers(dest="cmd", required=True)

    cu = sub.add_parser("create-user")
    cu.add_argument("--email", required=True)
    cu.add_argument("--name", required=True)
    cu.add_argument("--role", choices=["admin", "regular"], default="regular")
    cu.add_argument("--password", required=True)

    sub.add_parser("init-db")

    args = p.parse_args()
    if args.cmd == "create-user":
        asyncio.run(_create_user(args.email, args.name, args.role, args.password))
    elif args.cmd == "init-db":
        asyncio.run(_init_db())


if __name__ == "__main__":
    main()
