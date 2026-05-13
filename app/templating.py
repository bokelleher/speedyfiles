"""Jinja2 template environment for HTMX pages."""
from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.utils import fmt_bytes, fmt_duration_ms, fmt_transfer_stats

_TEMPLATE_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
templates.env.filters["bytes"] = fmt_bytes
templates.env.filters["duration_ms"] = fmt_duration_ms
templates.env.filters["transfer_stats"] = lambda f: fmt_transfer_stats(
    f.size_bytes if f is not None else None,
    f.duration_ms if f is not None else None,
)


def csrf_token(request) -> str:
    return getattr(request.state, "csrf_token", "") or ""


templates.env.globals["csrf_token"] = csrf_token
