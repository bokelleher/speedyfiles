"""Magic-link expiry / revocation / invalid-token behavior."""
import hashlib
import secrets
from datetime import timedelta

import pytest

from app.models import MagicLinkToken, Package
from app.utils import utcnow


@pytest.fixture
async def outbound_pkg_with_token(db_session, admin_user, tmp_storage_root):
    """An active outbound package with a known-plaintext magic token."""
    from app.storage import get_backend
    from app.models import PackageFile
    user, _ = admin_user
    pkg_id = "test_pkg_" + secrets.token_urlsafe(6)
    pkg = Package(
        id=pkg_id, owner_user_id=user.id, direction="outbound",
        title="Magic-link test", recipient_email="r@example.com",
        recipient_name="R", storage_backend="local", transport_mode="http",
        status="active", expires_at=utcnow() + timedelta(days=1),
    )
    db_session.add(pkg)
    await db_session.flush()
    # Need at least one file for the page to render
    backend = get_backend()
    await backend.init_package(pkg_id)
    # Use a fake file row — we don't actually need bytes on disk for landing-page test
    db_session.add(PackageFile(
        id="f1", package_id=pkg_id, original_name="x.txt", sanitized_name="x.txt",
        size_bytes=100, sha256="abc", storage_key=f"packages/{pkg_id}/f1--x.txt",
        state="complete", uploaded_at=utcnow(),
    ))
    raw = secrets.token_urlsafe(32)
    db_session.add(MagicLinkToken(
        package_id=pkg_id, token_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        recipient_email="r@example.com", purpose="download",
        expires_at=pkg.expires_at,
    ))
    await db_session.commit()
    return pkg, raw


async def test_landing_renders_files(client, outbound_pkg_with_token):
    pkg, raw = outbound_pkg_with_token
    r = await client.get(f"/p/{raw}")
    assert r.status_code == 200
    assert pkg.title in r.text
    assert "x.txt" in r.text


async def test_invalid_token_returns_410(client):
    r = await client.get("/p/totally_bogus_token_12345")
    assert r.status_code == 410


async def test_expired_token_returns_410(db_session, client, outbound_pkg_with_token):
    pkg, raw = outbound_pkg_with_token
    # Push the package's expiry into the past
    pkg.expires_at = utcnow() - timedelta(hours=1)
    db_session.add(pkg)
    await db_session.commit()
    r = await client.get(f"/p/{raw}")
    assert r.status_code == 410


async def test_revoked_token_returns_410(db_session, client, outbound_pkg_with_token):
    pkg, raw = outbound_pkg_with_token
    pkg.status = "revoked"
    db_session.add(pkg)
    await db_session.commit()
    r = await client.get(f"/p/{raw}")
    assert r.status_code == 410
