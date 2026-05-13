# Contributing to SpeedyFiles

Thanks for your interest! SpeedyFiles is small, focused, and intends to stay that way — but PRs and issues are very welcome.

## Quickstart for development

```bash
git clone https://github.com/speedyfiles/speedyfiles
cd speedyfiles
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
sed -i "s|change-me|$(openssl rand -hex 32)|" .env
python -m app.cli init-db
python -m app.cli create-user --email you@example.com --name 'Dev' --role admin --password 'devpass123'
uvicorn app.main:app --reload --port 5300
```

Visit <http://localhost:5300>.

## Tests

```bash
pytest -v                    # all tests
pytest tests/test_api.py     # one file
pytest -k "magic_link"       # filter by name
pytest --cov=app             # coverage report
```

## Lint + type-check

```bash
ruff check .                 # style + bugs
ruff format .                # auto-format (replaces black/isort)
mypy app/                    # type check
```

PR CI runs all three on every push.

## Project structure

```
app/
├── main.py                  FastAPI app entry, lifespan, middleware mount
├── config.py                pydantic-settings — env-driven config
├── db.py                    async engine + session + idempotent migrations
├── models.py                SQLAlchemy ORM
├── auth.py                  argon2 + session cookies + user dependencies
├── csrf.py                  double-submit-via-querystring CSRF middleware
├── email.py                 SMTP sender (reads from settings_store + env)
├── settings_store.py        DB-backed runtime config with Fernet encryption
├── webhooks.py              outbound HMAC-signed POSTs on events
├── utils.py                 small helpers (gen_id, sanitize, fmt_bytes…)
├── templating.py            Jinja2 env + filters
├── storage/
│   ├── base.py              StorageBackend Protocol + TransferTicket
│   ├── local.py             /srv/files filesystem backend
│   └── s3.py                S3-compatible backend (aioboto3)
├── routes/
│   ├── auth.py              login, logout, password change, forgot, reset
│   ├── dash.py              internal-user dashboard, package CRUD
│   ├── public.py            /p/<token>/* magic-link endpoints
│   ├── admin.py             user management
│   ├── admin_settings.py    /admin/settings/mail
│   ├── admin_webhooks.py    /admin/webhooks
│   ├── admin_audit.py       /admin/audit
│   └── api.py               /api/v1/* REST API sub-app
└── templates/               Jinja2 HTML
```

## Code style

- Python 3.12+. Use modern union syntax (`int | None`), `Mapped[]`, etc.
- Async by default. Any new route/handler should be `async def`.
- No `print()` — use `logging`.
- Type-hint public function signatures.
- Keep files under ~500 lines; split before they grow further.

## Adding a route

1. Add the handler to an appropriate router in `app/routes/`.
2. Add the audit-log entry inside the handler if it changes state.
3. Fire a webhook (`app.webhooks.fire_event(...)`) if it's a state-change relevant to event subscribers.
4. Write a pytest in `tests/test_<area>.py` exercising the route.

## Adding a setting

1. If env-driven, add to `app/config.py` (Settings) + `.env.example`.
2. If runtime-editable, add UI under `app/routes/admin_settings.py` and a template at `app/templates/pages/admin_settings_<area>.html`.
3. Persist via `settings_store.set(db, "section.key", value, secret=True_if_credential)`.
4. Read via `settings_store.get_section(db, "section")`.

## Commit conventions

We don't enforce conventional-commits, but a useful prefix helps:

- `feat: add OIDC login`
- `fix: handle empty filename in upload`
- `docs: clarify S3 setup`
- `chore: bump pinned cryptography`
- `refactor: extract _finalize_outbound`
- `test: cover delete-package edge cases`

## Releasing

Maintainers only. Tag `vX.Y.Z`, push tag — Actions builds + pushes Docker image, builds docs, attaches changelog.

## Code of conduct

Be kind. We don't have a long CoC document yet; the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) applies as a default.
