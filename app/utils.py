"""Small helpers."""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime

_BAD = re.compile(r"[^A-Za-z0-9._-]")


def gen_id(nbytes: int = 16) -> str:
    """URL-safe random id (~22 chars for 16 bytes)."""
    return secrets.token_urlsafe(nbytes)


def gen_magic_token() -> str:
    """43-char url-safe token for a magic link."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sanitize_filename(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = _BAD.sub("_", name).strip(".")
    if not name or name in {".", ".."}:
        name = "file"
    return name[:200]


def utcnow() -> datetime:
    """Naive UTC datetime — naive everywhere keeps SQLite comparisons consistent."""
    return datetime.now(tz=UTC).replace(tzinfo=None)


def fmt_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    return f"{f:.1f} {units[i]}" if i > 0 else f"{int(f)} {units[i]}"


def fmt_duration_ms(ms: int | None) -> str:
    """Human-friendly: '850 ms', '4.2s', '1m 23s', '2h 5m 30s'."""
    if ms is None:
        return "—"
    if ms < 1000:
        return f"{ms} ms"
    s = ms / 1000.0
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s + 0.5), 60)
    if m < 60:
        return f"{m}m {sec}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {sec}s"


def fmt_transfer_stats(bytes_n: int | None, ms: int | None) -> str:
    """One-liner like 'Transferred 1.42 GB in 2m 30s (9.7 MB/s)'."""
    if bytes_n is None or ms is None or ms <= 0:
        return ""
    bps = bytes_n * 1000.0 / ms
    return f"Transferred {fmt_bytes(bytes_n)} in {fmt_duration_ms(ms)} ({fmt_bytes(int(bps))}/s)"
