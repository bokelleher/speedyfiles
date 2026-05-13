"""Storage backend factory."""
from __future__ import annotations

from app.config import settings
from app.storage.base import StorageBackend
from app.storage.local import LocalStorage
from app.storage.s3 import S3Storage


def get_backend(name: str | None = None) -> StorageBackend:
    name = name or settings.storage_backend
    if name == "local":
        return LocalStorage()
    if name == "s3":
        return S3Storage()
    raise ValueError(f"unknown storage backend: {name!r}")
