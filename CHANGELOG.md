# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (Track changes here as you merge PRs)

## [0.1.0] — 2026-05-13

Initial public release.

### Added
- Web UI (admin + regular roles) for sending outbound packages and requesting inbound uploads
- Magic-link tokens (per-recipient, configurable TTL, revocable, SHA-256 hashed at rest)
- Local + S3 storage backends behind a `StorageBackend` Protocol
- BYO-SMTP mail delivery configured via the admin UI
- Per-file transfer stats (size + duration + speed) persisted in the DB
- REST API v1 with token authentication, OpenAPI 3 spec, Swagger UI at `/api/v1/docs`
- Webhooks (HMAC-SHA256 signed) on every package event
- Full audit log with admin-only viewer page
- Self-service password change + forgot-password email flow
- First-run setup wizard
- Settings infrastructure (DB-backed key/value with Fernet encryption for secrets)
- Docker + docker-compose deployment
- MIT license
