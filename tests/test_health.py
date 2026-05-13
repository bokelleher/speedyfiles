"""Smoke tests — health endpoints, basic routing."""

async def test_healthz(client):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"


async def test_api_health(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_openapi_spec(client):
    r = await client.get("/api/v1/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["info"]["title"] == "SpeedyFiles API"
    assert "/packages" in spec["paths"]
    assert "/me" in spec["paths"]


async def test_swagger_ui(client):
    r = await client.get("/api/v1/docs")
    assert r.status_code == 200
    assert "swagger" in r.text.lower()
