"""FastAPI app entry point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.config import settings
from app.csrf import CSRFMiddleware
from app.db import init_pragmas
from app.routes import admin as admin_routes
from app.routes import admin_audit as admin_audit_routes
from app.routes import admin_settings as admin_settings_routes
from app.routes import admin_site as admin_site_routes
from app.routes import admin_webhooks as admin_webhooks_routes
from app.routes import api as api_routes
from app.routes import auth as auth_routes
from app.routes import dash as dash_routes
from app.routes import public as public_routes
from app.routes import setup as setup_routes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_pragmas()
    if settings.storage_backend == "local":
        try:
            settings.packages_dir.mkdir(parents=True, exist_ok=True)
            settings.tmp_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            log.warning("could not create local storage dirs (will fail on first use): %s", e)
    log.info("%s started; storage_backend=%s",
             settings.app_name, settings.storage_backend)
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
# Setup-required check first — must come before CSRF (the wizard is exempt)
app.middleware("http")(setup_routes.setup_required_middleware)
app.add_middleware(CSRFMiddleware)

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(setup_routes.router)
app.include_router(auth_routes.router)
app.include_router(dash_routes.router)
app.include_router(admin_routes.router)
app.include_router(admin_settings_routes.router)
app.include_router(admin_site_routes.router)
app.include_router(admin_webhooks_routes.router)
app.include_router(admin_audit_routes.router)
app.include_router(public_routes.router)

# REST API sub-app — exposes its own OpenAPI spec + Swagger UI at /api/v1/docs
app.mount("/api/v1", api_routes.build_api_app())


@app.get("/")
async def root():
    return RedirectResponse("/dash", status_code=303)


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.exception_handler(401)
async def unauthorized(request: Request, exc):
    return RedirectResponse("/login", status_code=303)
