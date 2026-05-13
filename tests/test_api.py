"""REST API: token auth + package lifecycle."""
import io


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_me_unauthenticated(client):
    r = await client.get("/api/v1/me")
    assert r.status_code == 401


async def test_me_with_token(client, admin_user, admin_api_token):
    user, _ = admin_user
    r = await client.get("/api/v1/me", headers=_auth(admin_api_token))
    if r.status_code != 200:
        print(f"DEBUG body: {r.text[:500]}")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["email"] == user.email
    assert j["role"] == "admin"


async def test_me_bad_token(client):
    r = await client.get("/api/v1/me", headers=_auth("sf_bogus_xxx"))
    assert r.status_code == 401


async def test_package_create_and_get(client, admin_api_token):
    r = await client.post("/api/v1/packages", headers=_auth(admin_api_token), json={
        "title": "API smoke",
        "recipient_email": "smoke@example.com",
        "recipient_name": "Smoke",
        "direction": "outbound",
        "ttl_days": 1,
    })
    assert r.status_code == 201
    pkg = r.json()
    assert pkg["status"] == "draft"  # no files yet → draft
    assert pkg["direction"] == "outbound"

    r2 = await client.get(f"/api/v1/packages/{pkg['id']}",
                          headers=_auth(admin_api_token))
    assert r2.status_code == 200
    assert r2.json()["id"] == pkg["id"]


async def test_package_create_email_validation(client, admin_api_token):
    r = await client.post("/api/v1/packages", headers=_auth(admin_api_token), json={
        "title": "bad email",
        "recipient_email": "not-an-email",
        "recipient_name": "X",
        "direction": "outbound",
        "ttl_days": 1,
    })
    assert r.status_code == 422


async def test_upload_finalize_flow(client, admin_api_token, tmp_storage_root):
    # 1. Create
    r = await client.post("/api/v1/packages", headers=_auth(admin_api_token), json={
        "title": "Upload test",
        "recipient_email": "recipient@example.com",
        "recipient_name": "Recipient",
        "direction": "outbound",
        "ttl_days": 1,
    })
    pkg_id = r.json()["id"]

    # 2. Upload a file
    content = b"hello from pytest " * 50
    r = await client.post(
        f"/api/v1/packages/{pkg_id}/files",
        headers=_auth(admin_api_token),
        files={"file": ("hello.txt", io.BytesIO(content), "text/plain")},
    )
    assert r.status_code == 201
    fr = r.json()
    assert fr["size_bytes"] == len(content)
    assert fr["original_name"] == "hello.txt"
    assert fr.get("duration_ms") is not None

    # 3. Finalize (will fail to actually send email — no SMTP — but should still mint link)
    r = await client.post(f"/api/v1/packages/{pkg_id}/finalize",
                          headers=_auth(admin_api_token))
    # 200 even if SMTP send failed (best-effort)
    assert r.status_code == 200
    fin = r.json()
    assert fin["ok"] is True
    assert fin["magic_link"] and "/p/" in fin["magic_link"]


async def test_list_packages_pagination(client, admin_api_token):
    # Create a few packages
    for i in range(3):
        await client.post("/api/v1/packages", headers=_auth(admin_api_token), json={
            "title": f"Pkg {i}",
            "recipient_email": f"r{i}@example.com",
            "recipient_name": f"R{i}",
            "direction": "outbound", "ttl_days": 1,
        })
    r = await client.get("/api/v1/packages?limit=2", headers=_auth(admin_api_token))
    assert r.status_code == 200
    j = r.json()
    assert j["total"] >= 3
    assert len(j["items"]) == 2


async def test_revoke_then_delete(client, admin_api_token):
    r = await client.post("/api/v1/packages", headers=_auth(admin_api_token), json={
        "title": "Rev/Del",
        "recipient_email": "x@example.com",
        "recipient_name": "X",
        "direction": "outbound",
        "ttl_days": 1,
    })
    pkg_id = r.json()["id"]
    r = await client.post(f"/api/v1/packages/{pkg_id}/revoke",
                          headers=_auth(admin_api_token))
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"
    r = await client.delete(f"/api/v1/packages/{pkg_id}",
                            headers=_auth(admin_api_token))
    assert r.status_code == 204
    r = await client.get(f"/api/v1/packages/{pkg_id}",
                         headers=_auth(admin_api_token))
    assert r.status_code == 404


