"""Webhook signing + dispatch (without making real HTTP calls)."""
import hashlib
import hmac
import json

import pytest

from app.models import Webhook
from app.webhooks import EVENTS, _sign


def test_signature_format():
    sig = _sign("secret", b'{"event":"package.finalized"}')
    assert len(sig) == 64  # sha256 hex
    expected = hmac.new(b"secret", b'{"event":"package.finalized"}',
                       hashlib.sha256).hexdigest()
    assert sig == expected


def test_events_set_is_immutable():
    """EVENTS is the canonical event registry."""
    assert isinstance(EVENTS, tuple)
    assert "package.finalized" in EVENTS
    assert "package.downloaded" in EVENTS
    assert "package.file_uploaded" in EVENTS


async def test_fire_event_no_subscribers(db_session):
    """Firing with no matching subscriptions should be a quiet no-op."""
    from app.webhooks import fire_event
    await fire_event(db_session, "package.finalized",
                     package_id="x", payload={"title": "test"})
    # No exception = pass


async def test_fire_event_subscriber_no_match(db_session):
    """Subscribers to other events should not be fired."""
    from app.webhooks import fire_event
    db_session.add(Webhook(
        url="http://localhost:1/nope",
        secret="x", events="package.deleted",
        is_active=1, failure_count=0,
    ))
    await db_session.commit()
    await fire_event(db_session, "package.finalized",
                     package_id="x", payload={})
    # Subscription wasn't fired (the event doesn't match) — verify by
    # checking the row stayed pristine
    rows = (await db_session.execute(
        Webhook.__table__.select()
    )).fetchall()
    assert len(rows) == 1
    # last_fired_at should be None since no event matched
    assert rows[0].last_fired_at is None
