# SpeedyFiles

> Self-hosted file transfer that doesn't suck.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker pulls](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://github.com/bokelleher/speedyfiles/pkgs/container/speedyfiles)

Send and receive multi-gigabyte packages with **expiring magic links**, **per-recipient isolation**, **signed-email notifications**, and a **clean admin UI**. Your customers, your storage, your rules.

🌐 **Website**: <https://speedyfiles.app>
📖 **Docs**: <https://speedyfiles.app/docs/>
⚙️ **API**: <https://speedyfiles.app/api/>

---

## Why?

Sending big files to customers is harder than it should be:

- **Dropbox / Google Drive** expose your whole shared drive; over-share-by-accident is one click away.
- **WeTransfer** is great but per-seat fees, no audit trail, and your customers' files live on their servers.
- **FTP/SFTP** works but the UX is medieval and credentials get reused forever.
- **Email attachments** cap out at 25 MB.

SpeedyFiles is the self-hosted middle path: as easy as WeTransfer to use, but **the files live on your storage**, **the audit trail is yours**, and **you pay $0 per seat**.

## Features

- 📤 **Outbound packages** — upload files, set TTL, send magic link to recipient.
- 📥 **Inbound requests** — invite a customer to upload to a private page.
- 🔐 **Per-recipient isolation** — magic-link tokens scoped to a single package; SHA-256 hashed in DB.
- 📊 **Live transfer stats** — per-file progress bars + speed + persisted `Transferred 47.7 MB in 509 ms (93.7 MB/s)` data.
- 📧 **BYO-SMTP** — any mail server: Gmail, Postmark, SES, your own. Configure in the UI.
- 💾 **Local or S3 storage** — toggle globally or per-package.
- 📜 **Full audit log** — every login, magic-link hit, file download, upload, revocation.
- ⚙️ **REST API** — token-authenticated, OpenAPI 3 documented, Swagger UI bundled at `/api/v1/docs`.
- 🪝 **Webhooks** — HMAC-signed HTTP POSTs to your URLs on every event.
- 👥 **Multi-user with roles** — admin + regular; admin sees everything.
- 🔑 **Password reset by email** — forgot-password flow built in.
- 🚀 **5-minute install** — Docker compose + first-run wizard; no config files needed.

## Quick start

```bash
curl -O https://speedyfiles.app/quickstart/docker-compose.yml
echo "SESSION_SECRET=$(openssl rand -hex 32)" > .env
docker compose up -d
open http://localhost:5300/setup
```

That's it. The first-run wizard collects your admin email, site name, and (optional) SMTP settings — you're sending files in 5 minutes.

For production deployments with TLS, a real domain, and proper email deliverability, see the [full install guide](https://speedyfiles.app/docs/install.html).

## Stack

- **Backend**: Python 3.12 + FastAPI + SQLAlchemy 2 (async) + SQLite (default) or any SQLAlchemy-supported DB
- **Frontend**: server-rendered Jinja2 + HTMX + vanilla JS (no Node/npm build step at runtime)
- **Storage**: local filesystem or S3-compatible (AWS S3, MinIO, R2, B2, Wasabi, Spaces…)
- **Mail**: stdlib `smtplib` → any SMTP server (no vendor lock-in)
- **Auth**: argon2id passwords + signed-cookie sessions + double-submit CSRF + Bearer-token API
- **Security**: HMAC-signed webhooks, Fernet-encrypted secrets at rest, audit log per action

## Architecture

```
                  ┌──────────────────────────────────────┐
                  │     Recipient                        │
                  │  ┌──────────────┐                    │
                  │  │ Magic link in│                    │
                  │  │ their email  │                    │
                  │  └──────┬───────┘                    │
                  │         │                            │
                  └─────────┼────────────────────────────┘
                            │ HTTPS
                            ▼
              ┌────────────────────────────┐
              │  nginx (TLS termination)   │
              └─────────────┬──────────────┘
                            │ proxy_pass
                            ▼
              ┌────────────────────────────┐
              │  SpeedyFiles (FastAPI)     │
              │  - Web UI (/dash, /p/...)  │
              │  - REST API (/api/v1/*)    │
              │  - Background webhooks     │
              └──┬───────────┬─────────────┘
                 │           │
                 │ SQLite    │ Local FS or S3
                 ▼           ▼
              ┌──────┐   ┌──────────┐
              │ DB   │   │ /srv/    │
              │      │   │  files/  │
              └──────┘   └──────────┘
```

## REST API

Every instance auto-publishes its OpenAPI 3 spec + Swagger UI:

- `GET /api/v1/openapi.json` — machine-readable spec
- `GET /api/v1/docs` — try-it-in-browser Swagger UI
- `GET /api/v1/redoc` — clean reference style

Example: create a package, upload a file, send the notification — entirely from a script:

```bash
TOKEN="sf_..."  # create in the web UI under Account → API tokens
HOST="https://files.example.com"

PKG=$(curl -s -X POST $HOST/api/v1/packages \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title":"Q4 financials","recipient_email":"cfo@acme.com",
       "recipient_name":"Acme CFO","direction":"outbound","ttl_days":14}' | jq -r .id)

curl -X POST $HOST/api/v1/packages/$PKG/files \
  -H "Authorization: Bearer $TOKEN" -F "file=@./Q4-report.pdf"

curl -X POST $HOST/api/v1/packages/$PKG/finalize \
  -H "Authorization: Bearer $TOKEN"
# → response includes the magic link emailed to the recipient
```

## Webhooks

Subscribe to `package.created`, `package.finalized`, `package.file_uploaded`, `package.downloaded`, `package.revoked`, `package.deleted`, or `package.expired`. SpeedyFiles will POST a JSON body to your URL with an HMAC-SHA256 signature.

```
POST /your/webhook HTTP/1.1
Content-Type: application/json
X-SpeedyFiles-Event: package.finalized
X-SpeedyFiles-Signature: sha256=...

{"event":"package.finalized","timestamp":"...","package_id":"abc...",
 "title":"Q4 financials","recipient_email":"cfo@acme.com",...}
```

After 10 consecutive failures the hook auto-disables. Configure under **Settings → Webhooks** in the admin UI.

## Development

```bash
git clone https://github.com/bokelleher/speedyfiles
cd speedyfiles
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # pytest, ruff, mypy
cp .env.example .env
python -m app.cli init-db
uvicorn app.main:app --reload --port 5300
```

Run tests:

```bash
pytest -v
```

Lint:

```bash
ruff check .
mypy app/
```

## Roadmap

- [ ] OIDC / SSO support (Authelia / Authentik / Keycloak / Google Workspace)
- [ ] tus.io resumable upload protocol
- [ ] Per-package storage backend (mix local + S3 in the same instance)
- [ ] Browser-direct presigned S3 uploads (skip the app server)
- [ ] Migration tooling: import from Pingvin Share / WeTransfer

## SpeedyFiles Cloud

For teams that want **UDP-accelerated global transfers**, a **signed CLI** that
works on customer machines without IT help, **multi-region edge nodes**,
**managed email reputation**, and zero-ops operation — we're building
**SpeedyFiles Cloud**, a hosted SaaS layered on top of this same open-source
core.

The OSS will always include everything you need to run SpeedyFiles yourself.
Cloud adds the operationally-expensive bits (UDP edge network, signed clients,
abuse mitigation, deliverability-as-a-service) for teams that would rather
pay than build.

👉 [**Join the Cloud waitlist**](https://speedyfiles.app/cloud/) — early
access + a generous free tier for OSS contributors.

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerability reports go to [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Commercial use, modification, redistribution all permitted.

## Acknowledgments

Built with [FastAPI](https://fastapi.tiangolo.com/), [SQLAlchemy](https://www.sqlalchemy.org/), [HTMX](https://htmx.org/), and [argon2-cffi](https://argon2-cffi.readthedocs.io/).
