# Security policy

## Reporting a vulnerability

**Please do not file a public GitHub issue for security bugs.**

Email `security@speedyfiles.app` with:

- A description of the issue
- Steps to reproduce (proof-of-concept welcome)
- The affected version (`git rev-parse HEAD` or Docker tag)
- Your name + how you'd like to be credited (optional)

We aim to:

- Acknowledge within **3 business days**
- Triage and confirm within **7 business days**
- Ship a fix or coordinate disclosure within **30 days** for confirmed vulnerabilities (sooner for actively-exploited issues)

## Scope

In scope:

- Authentication / authorization bypasses
- Path traversal / file-system escape
- SQL injection
- XSS / CSRF (despite our defenses)
- Information disclosure (database leak via API, audit log access, settings leakage)
- Server-side request forgery (especially via webhooks)
- Cryptographic weaknesses
- Magic-link enumeration / brute-force
- Stored-secret recovery (e.g. extracting SMTP password from a DB dump)

Out of scope:

- Issues only reproducible in development mode (`DEBUG=true`)
- Self-hosting misconfigurations (open Redis, missing TLS, etc.) — these are the operator's responsibility
- DoS via genuine high-volume requests (rate-limit your reverse proxy)
- Issues in dependencies (report to the upstream)

## Supported versions

We support the current `main` and the latest tagged release. Security fixes are not backported to earlier releases.

## Threat model

SpeedyFiles is intended to be **deployed behind TLS by a trusted operator** for sharing files with **identified recipients via email**. Out of the box:

- ✅ Database is local-only, never exposed
- ✅ Magic-link tokens are 32-byte url-safe random, SHA-256 hashed at rest
- ✅ Passwords are argon2id
- ✅ SMTP passwords + webhook secrets are Fernet-encrypted at rest
- ✅ Session cookies are HttpOnly, Secure, SameSite=Lax
- ✅ CSRF on all state-changing internal routes
- ✅ Bearer-token API auth (separate from session)
- ❌ No rate limiting on /login or /p/&lt;token&gt; — you should put a rate-limiting layer (nginx, fail2ban) in front
- ❌ No anti-abuse on inbound uploads — open inbound packages could be abused if their tokens leak

## Cryptography

- **Passwords**: argon2id via `argon2-cffi`, defaults (m=64MB, t=3, p=4)
- **Session cookies**: `itsdangerous.TimestampSigner` with HMAC-SHA1 (Werkzeug-compatible)
- **CSRF**: 24-byte url-safe random per session
- **Magic-link tokens**: 32-byte url-safe random; SHA-256 hashed before DB storage
- **API tokens**: 32-byte url-safe random with `sf_` prefix; SHA-256 hashed
- **Webhook signatures**: HMAC-SHA256 over the raw body, hex-encoded
- **Stored-secret encryption**: Fernet (AES-128-CBC + HMAC-SHA256), key derived via SHA-256 of `SESSION_SECRET`

## Hall of fame

Researchers who have responsibly disclosed issues:

_(empty for now — be the first!)_
