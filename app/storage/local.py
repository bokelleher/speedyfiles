"""Local-filesystem storage backend rooted at /srv/files/."""
from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path

import aiofiles
import aiofiles.os

from app.config import settings
from app.storage.base import StorageBackend, StoredFile, TransferTicket
from app.utils import gen_id

log = logging.getLogger(__name__)


class LocalStorage(StorageBackend):
    name = "local"

    def __init__(self, root: Path | None = None):
        self.root = root or settings.local_storage_root
        self.packages_root = self.root / "packages"
        self.tmp_root = self.root / "tmp"

    def _pkg_dir(self, package_id: str) -> Path:
        # Defensive: never let a package_id traverse out.
        if "/" in package_id or ".." in package_id:
            raise ValueError("invalid package_id")
        return self.packages_root / package_id

    def _final_path(self, package_id: str, file_id: str, sanitized_name: str) -> Path:
        if "/" in file_id or ".." in file_id:
            raise ValueError("invalid file_id")
        return self._pkg_dir(package_id) / f"{file_id}--{sanitized_name}"

    async def init_package(self, package_id: str) -> None:
        d = self._pkg_dir(package_id)
        await aiofiles.os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o0700)
        await aiofiles.os.makedirs(self.tmp_root, exist_ok=True)

    async def put_file(
        self,
        package_id: str,
        file_id: str,
        sanitized_name: str,
        stream: AsyncIterator[bytes],
    ) -> StoredFile:
        await self.init_package(package_id)
        final = self._final_path(package_id, file_id, sanitized_name)
        tmp = self.tmp_root / f"{file_id}-{gen_id(4)}.part"
        h = hashlib.sha256()
        size = 0
        try:
            async with aiofiles.open(tmp, "wb") as f:
                async for chunk in stream:
                    if not chunk:
                        continue
                    h.update(chunk)
                    size += len(chunk)
                    await f.write(chunk)
                await f.flush()
                try:
                    os.fsync(f.fileno())  # type: ignore[attr-defined]
                except (OSError, AttributeError):
                    pass
            os.chmod(tmp, 0o0640)
            os.rename(tmp, final)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass
        rel_key = f"packages/{package_id}/{final.name}"
        return StoredFile(storage_key=rel_key, size_bytes=size, sha256=h.hexdigest())

    async def get_download_ticket(
        self,
        package_id: str,
        file_id: str,
        storage_key: str,
        original_name: str,
    ) -> TransferTicket:
        abs_path = (self.root / storage_key).resolve()
        # Guardrail: must remain inside root
        if not str(abs_path).startswith(str(self.root.resolve())):
            raise ValueError("storage key escaped root")
        return TransferTicket(kind="http_stream", stream_path=str(abs_path))

    async def delete_package(self, package_id: str) -> None:
        d = self._pkg_dir(package_id)
        if not d.exists():
            return
        for child in d.iterdir():
            try:
                child.unlink()
            except FileNotFoundError:
                pass
        try:
            d.rmdir()
        except OSError as e:
            log.warning("could not remove package dir %s: %s", d, e)
