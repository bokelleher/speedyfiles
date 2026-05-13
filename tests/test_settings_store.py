"""Settings store with Fernet encryption."""

from app import settings_store


async def test_set_get_roundtrip(db_session):
    await settings_store.set(db_session, "test.key", "hello")
    await db_session.commit()
    v = await settings_store.get(db_session, "test.key")
    assert v == "hello"


async def test_secret_encrypted_at_rest(db_session):
    from app.models import AppSetting
    await settings_store.set(db_session, "test.secret", "p@ssw0rd",
                             secret=True)
    await db_session.commit()
    # Inspect the raw row — should NOT be the plaintext
    row = await db_session.get(AppSetting, "test.secret")
    assert row.value != "p@ssw0rd"
    assert row.value != '"p@ssw0rd"'  # not just JSON-wrapped either
    assert row.is_secret == 1
    # But reading back via settings_store decrypts transparently
    v = await settings_store.get(db_session, "test.secret")
    assert v == "p@ssw0rd"


async def test_get_section(db_session):
    await settings_store.set(db_session, "mail.host", "smtp.example.com")
    await settings_store.set(db_session, "mail.port", 587)
    await settings_store.set(db_session, "mail.password", "shh", secret=True)
    await db_session.commit()
    s = await settings_store.get_section(db_session, "mail")
    assert s["host"] == "smtp.example.com"
    assert s["port"] == 587
    assert s["password"] == "shh"


async def test_default_when_missing(db_session):
    v = await settings_store.get(db_session, "nonexistent.key", default="fallback")
    assert v == "fallback"


async def test_types_roundtrip(db_session):
    await settings_store.set(db_session, "x.int", 42)
    await settings_store.set(db_session, "x.bool", True)
    await settings_store.set(db_session, "x.list", [1, 2, 3])
    await settings_store.set(db_session, "x.dict", {"a": 1, "b": "two"})
    await db_session.commit()
    assert await settings_store.get(db_session, "x.int") == 42
    assert await settings_store.get(db_session, "x.bool") is True
    assert await settings_store.get(db_session, "x.list") == [1, 2, 3]
    assert await settings_store.get(db_session, "x.dict") == {"a": 1, "b": "two"}
