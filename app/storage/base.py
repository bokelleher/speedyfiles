"""Storage backend Protocol and the TransferTicket envelope.

The seam for a future UDP sidecar lives here: a TransferTicket's `kind`
can become 'udp_sidecar' without touching the routes layer.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol


@dataclass
class StoredFile:
    storage_key: str
    size_bytes: int
    sha256: str | None = None


@dataclass
class TransferTicket:
    kind: Literal["http_stream", "http_redirect", "udp_sidecar"]
    url: str | None = None
    stream_path: str | None = None          # absolute path for LocalStorage to stream from
    expires_at: datetime | None = None
    extra: dict = field(default_factory=dict)


class StorageBackend(Protocol):
    name: str

    async def init_package(self, package_id: str) -> None: ...

    async def put_file(
        self,
        package_id: str,
        file_id: str,
        sanitized_name: str,
        stream: AsyncIterator[bytes],
    ) -> StoredFile: ...

    async def get_download_ticket(
        self,
        package_id: str,
        file_id: str,
        storage_key: str,
        original_name: str,
    ) -> TransferTicket: ...

    async def delete_package(self, package_id: str) -> None: ...
