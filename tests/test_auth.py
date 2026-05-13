"""Login, sessions, password change."""
import re


async def test_login_redirects_when_unauth(client):
    r = await client.get("/dash", follow_redirects=False)
    assert r.status_code in (303, 401)


async def test_login_success(client, admin_user):
    user, pw = admin_user
    r = await client.post("/login", data={"email": user.email, "password": pw},
                          follow_redirects=False)
    assert r.status_code == 303
    assert "files_session" in r.headers.get("set-cookie", "") or \
           "speedyfiles_session" in r.headers.get("set-cookie", "")


async def test_login_wrong_password(client, admin_user):
    user, _ = admin_user
    r = await client.post("/login",
                          data={"email": user.email, "password": "wrong"},
                          follow_redirects=False)
    assert r.status_code == 401


async def test_login_unknown_email(client):
    r = await client.post("/login",
                          data={"email": "ghost@test.local", "password": "x"},
                          follow_redirects=False)
    assert r.status_code == 401


async def test_forgot_returns_always_ok(client):
    """Forgot-password should never leak whether an email exists."""
    r = await client.post("/forgot", data={"email": "anyone@test.local"})
    assert r.status_code == 200
    assert "reset link has been sent" in r.text.lower() or "if that email" in r.text.lower()


async def test_change_password_requires_session(client):
    r = await client.post("/account/password",
                          data={"current_password": "x", "new_password": "y", "confirm_password": "y"},
                          follow_redirects=False)
    # CSRF middleware or session middleware will reject
    assert r.status_code in (303, 401, 403)
