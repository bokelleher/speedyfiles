"""Double-submit-cookie CSRF middleware.

We exempt:
 - safe methods (GET, HEAD, OPTIONS)
 - the login form (no session yet)
 - all /p/* paths (magic-link token IS the auth)
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from app.auth import read_session_cookie
from app.config import settings

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
EXEMPT_PREFIXES = ("/p/", "/login", "/healthz", "/static/", "/api/",
                   "/setup", "/forgot", "/reset/")


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in SAFE_METHODS:
            return await call_next(request)
        path = request.url.path
        if any(path.startswith(p) for p in EXEMPT_PREFIXES):
            return await call_next(request)

        # Need session and matching CSRF token
        cookie = request.cookies.get(settings.session_cookie_name)
        if not cookie:
            return PlainTextResponse("missing session", status_code=403)
        data = read_session_cookie(cookie)
        if not data:
            return PlainTextResponse("bad session", status_code=403)

        # Accept the token via header or query string only.
        #
        # We deliberately do NOT read request.form() here. Starlette's
        # BaseHTTPMiddleware consumes the body stream on any form/body read,
        # which would strip the body before FastAPI's Form/File dependencies
        # can parse it (FastAPI 0.115 + Starlette 0.41 quirk).
        #
        # Templates put `?_csrf={{ csrf_token(request) }}` on every form
        # action URL. JS/HTMX callers should send X-CSRF-Token.
        header_token = request.headers.get("x-csrf-token")
        qs_token = request.query_params.get("_csrf")
        submitted = header_token or qs_token
        if not submitted or submitted != data.get("c"):
            return PlainTextResponse("csrf token mismatch", status_code=403)
        return await call_next(request)
