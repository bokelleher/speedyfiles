"""SMTP sender. Config comes from the DB-backed settings store (admin-editable)
with env-var defaults as fallback for first-run / development."""
from __future__ import annotations

import logging
import smtplib
import ssl as ssl_lib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.config import settings as env_settings

log = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "email"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
    enable_async=False,
)


@dataclass
class MailConfig:
    """Resolved mail config — DB settings override env defaults."""
    host: str
    port: int
    security: str          # "none" | "starttls" | "tls"
    auth_method: str       # "none" | "login" | "plain"
    username: str
    password: str
    from_address: str
    from_name: str
    helo: str
    timeout_seconds: int = 30


def _bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool): return v
    if v is None: return default
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


async def load_mail_config(db: AsyncSession) -> MailConfig:
    s = await settings_store.get_section(db, "mail")
    return MailConfig(
        host=s.get("host", env_settings.smtp_host),
        port=int(s.get("port", env_settings.smtp_port)),
        security=s.get("security", "starttls" if int(s.get("port", env_settings.smtp_port)) == 587
                                              else "none"),
        auth_method=s.get("auth_method", "none"),
        username=s.get("username", ""),
        password=s.get("password", ""),  # already decrypted by settings_store
        from_address=s.get("from_address", env_settings.mail_from_address),
        from_name=s.get("from_name", env_settings.mail_from_name),
        helo=s.get("helo", env_settings.mail_envelope_helo or "")
             or env_settings.mail_envelope_helo
             or (env_settings.mail_from_address or "x@localhost").rsplit("@", 1)[-1],
        timeout_seconds=int(s.get("timeout_seconds", 30)),
    )


def render(template_name: str, **ctx) -> str:
    tpl = _env.get_template(template_name)
    return tpl.render(**ctx)


def _send_with_config(cfg: MailConfig, msg: EmailMessage) -> None:
    """Open an SMTP connection per cfg, send one message, close."""
    helo = cfg.helo or "localhost"
    if cfg.security == "tls":
        ctx = ssl_lib.create_default_context()
        with smtplib.SMTP_SSL(cfg.host, cfg.port, local_hostname=helo,
                              context=ctx, timeout=cfg.timeout_seconds) as s:
            if cfg.auth_method != "none" and cfg.username:
                s.login(cfg.username, cfg.password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(cfg.host, cfg.port, local_hostname=helo,
                          timeout=cfg.timeout_seconds) as s:
            s.ehlo(helo)
            if cfg.security == "starttls":
                s.starttls(context=ssl_lib.create_default_context())
                s.ehlo(helo)
            if cfg.auth_method != "none" and cfg.username:
                s.login(cfg.username, cfg.password)
            s.send_message(msg)


async def send_email(db: AsyncSession, to_addr: str, subject: str,
                     text_body: str, html_body: str) -> None:
    cfg = await load_mail_config(db)
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.from_name, cfg.from_address))
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    from_domain = cfg.from_address.rsplit("@", 1)[-1]
    msg["Message-ID"] = make_msgid(domain=from_domain)
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    try:
        _send_with_config(cfg, msg)
        log.info("sent email subject=%r to=%s via %s:%s helo=%s",
                 subject, to_addr, cfg.host, cfg.port, cfg.helo)
    except Exception as e:
        log.exception("email send failed to=%s err=%s", to_addr, e)
        raise


async def send_test_email(db: AsyncSession, to_addr: str) -> None:
    """Send a verification message to confirm the SMTP config works."""
    cfg = await load_mail_config(db)
    body_txt = (
        f"This is a test email from {env_settings.app_name}.\n\n"
        f"Mail server: {cfg.host}:{cfg.port} ({cfg.security})\n"
        f"From:        {cfg.from_name} <{cfg.from_address}>\n"
        f"HELO:        {cfg.helo}\n\n"
        f"If you received this, your SMTP configuration is working."
    )
    body_html = (
        f"<p>This is a test email from <b>{env_settings.app_name}</b>.</p>"
        f"<ul>"
        f"<li><b>Mail server:</b> <code>{cfg.host}:{cfg.port}</code> ({cfg.security})</li>"
        f"<li><b>From:</b> {cfg.from_name} &lt;{cfg.from_address}&gt;</li>"
        f"<li><b>HELO:</b> <code>{cfg.helo}</code></li>"
        f"</ul>"
        f"<p>If you received this, your SMTP configuration is working.</p>"
    )
    await send_email(db, to_addr, f"{env_settings.app_name} — SMTP test", body_txt, body_html)


async def send_outbound_notification(
    db: AsyncSession, *, to_email: str, to_name: str, sender_name: str,
    package_title: str, note: str | None, link_url: str,
    expires_at: str, file_count: int,
) -> None:
    ctx = dict(
        to_name=to_name, sender_name=sender_name,
        package_title=package_title, note=note, link_url=link_url,
        expires_at=expires_at, file_count=file_count, app_name=env_settings.app_name,
    )
    await send_email(
        db, to_email,
        f"{sender_name} has shared files with you: {package_title}",
        render("outbound.txt", **ctx),
        render("outbound.html", **ctx),
    )


async def send_inbound_request(
    db: AsyncSession, *, to_email: str, to_name: str, sender_name: str,
    package_title: str, note: str | None, link_url: str, expires_at: str,
) -> None:
    ctx = dict(
        to_name=to_name, sender_name=sender_name,
        package_title=package_title, note=note, link_url=link_url,
        expires_at=expires_at, app_name=env_settings.app_name,
    )
    await send_email(
        db, to_email,
        f"{sender_name} is requesting files: {package_title}",
        render("inbound.txt", **ctx),
        render("inbound.html", **ctx),
    )
