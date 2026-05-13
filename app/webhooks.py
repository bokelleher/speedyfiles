"""Outbound webhook delivery.

Best-effort synchronous HTTP POSTs to subscribed URLs on relevant events.
HMAC-SHA256 signed via the per-subscription secret.

Failure handling: record last status + bump failure_count. Auto-disable
after N consecutive failures so a broken endpoint can't slow every event.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Webhook
from app.utils import utcnow

log = logging.getLogger(__name__)

# All defined event names. The admin UI lets users subscribe to any subset.
EVENTS = (
    "package.created",
    "package.finalized",
    "package.file_uploaded",
    "package.downloaded",
    "package.revoked",
    "package.deleted",
    "package.expired",
)

_MAX_CONSECUTIVE_FAILURES = 10
_TIMEOUT_SECONDS = 8


def _sign(secret: str, body_bytes: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


async def fire_event(
    db: AsyncSession, event: str, *,
    package_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    """Find every active webhook subscribed to `event` and POST to it.

    Best effort; we don't block on success. Failures are logged and the
    subscription's failure_count is bumped — past the threshold the
    subscription auto-disables.
    """
    payload = payload or {}
    payload.update({
        "event": event,
        "timestamp": utcnow().isoformat() + "Z",
        "package_id": package_id,
    })
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # Cheap LIKE filter — events column is comma-separated text. We refine
    # in Python afterwards.
    rows = (await db.scalars(
        select(Webhook).where(
            Webhook.is_active == 1,
            Webhook.events.like(f"%{event}%"),
        )
    )).all()
    matching = [w for w in rows if event in [e.strip() for e in w.events.split(",")]]
    if not matching:
        return

    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=False) as client:
        for hook in matching:
            sig = _sign(hook.secret, body)
            try:
                r = await client.post(hook.url, content=body, headers={
                    "Content-Type": "application/json",
                    "User-Agent": "SpeedyFiles-Webhook/1.0",
                    "X-SpeedyFiles-Event": event,
                    "X-SpeedyFiles-Signature": f"sha256={sig}",
                    "X-SpeedyFiles-Hook-Id": str(hook.id),
                })
                hook.last_fired_at = utcnow()
                hook.last_status = r.status_code
                if 200 <= r.status_code < 300:
                    hook.failure_count = 0
                else:
                    hook.failure_count += 1
                    log.warning("webhook %s -> %s status=%s", hook.id, hook.url, r.status_code)
            except Exception as e:  # noqa: BLE001
                hook.last_fired_at = utcnow()
                hook.last_status = None
                hook.failure_count += 1
                log.warning("webhook %s -> %s error=%s", hook.id, hook.url, e)

            if hook.failure_count >= _MAX_CONSECUTIVE_FAILURES:
                hook.is_active = 0
                log.warning("webhook %s auto-disabled after %d consecutive failures",
                            hook.id, hook.failure_count)
    await db.commit()
