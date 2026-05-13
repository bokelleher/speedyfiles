"""S3 storage backend using aioboto3 + presigned URLs."""
from __future__ import annotations

import hashlib
import logging
from collections.abc import AsyncIterator

import aioboto3

from app.config import settings
from app.storage.base import StorageBackend, StoredFile, TransferTicket

log = logging.getLogger(__name__)

_PRESIGN_TTL = 900  # 15 minutes


class S3Storage(StorageBackend):
    name = "s3"

    def __init__(self, bucket: str | None = None, region: str | None = None,
                 prefix: str | None = None):
        self.bucket = bucket or settings.s3_bucket
        if not self.bucket:
            raise RuntimeError("S3 storage requires settings.s3_bucket")
        self.region = region or settings.s3_region
        self.prefix = prefix or settings.s3_prefix
        self._session = aioboto3.Session()

    def _key(self, package_id: str, file_id: str, sanitized_name: str) -> str:
        return f"{self.prefix}/{package_id}/{file_id}--{sanitized_name}"

    async def init_package(self, package_id: str) -> None:
        # S3 has no notion of directories; nothing to do.
        return

    async def put_file(
        self,
        package_id: str,
        file_id: str,
        sanitized_name: str,
        stream: AsyncIterator[bytes],
    ) -> StoredFile:
        # For v1 we buffer through us — a future improvement is to issue presigned
        # PUTs and let the client upload directly. That belongs in get_upload_ticket
        # once the routes call it.
        key = self._key(package_id, file_id, sanitized_name)
        h = hashlib.sha256()
        size = 0

        async with self._session.client("s3", region_name=self.region) as s3:
            # Create multipart upload for larger files
            mpu = await s3.create_multipart_upload(Bucket=self.bucket, Key=key)
            upload_id = mpu["UploadId"]
            parts: list[dict] = []
            part_num = 1
            buf = bytearray()
            MIN_PART = 5 * 1024 * 1024  # 5 MiB
            try:
                async for chunk in stream:
                    if not chunk:
                        continue
                    h.update(chunk)
                    size += len(chunk)
                    buf.extend(chunk)
                    if len(buf) >= MIN_PART:
                        resp = await s3.upload_part(
                            Bucket=self.bucket, Key=key, PartNumber=part_num,
                            UploadId=upload_id, Body=bytes(buf),
                        )
                        parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                        part_num += 1
                        buf.clear()
                if buf or not parts:
                    resp = await s3.upload_part(
                        Bucket=self.bucket, Key=key, PartNumber=part_num,
                        UploadId=upload_id, Body=bytes(buf),
                    )
                    parts.append({"ETag": resp["ETag"], "PartNumber": part_num})
                await s3.complete_multipart_upload(
                    Bucket=self.bucket, Key=key, UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                )
            except Exception:
                await s3.abort_multipart_upload(
                    Bucket=self.bucket, Key=key, UploadId=upload_id,
                )
                raise

        return StoredFile(storage_key=key, size_bytes=size, sha256=h.hexdigest())

    async def get_download_ticket(
        self,
        package_id: str,
        file_id: str,
        storage_key: str,
        original_name: str,
    ) -> TransferTicket:
        async with self._session.client("s3", region_name=self.region) as s3:
            url = await s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.bucket,
                    "Key": storage_key,
                    "ResponseContentDisposition": f'attachment; filename="{original_name}"',
                },
                ExpiresIn=_PRESIGN_TTL,
            )
        return TransferTicket(kind="http_redirect", url=url)

    async def delete_package(self, package_id: str) -> None:
        prefix = f"{self.prefix}/{package_id}/"
        async with self._session.client("s3", region_name=self.region) as s3:
            paginator = s3.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objs:
                    await s3.delete_objects(Bucket=self.bucket, Delete={"Objects": objs})
