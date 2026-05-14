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


def stream_zip_files(members: list[tuple[str, str]], chunk_size: int = 1 << 16):
    """Yield bytes of a streamed ZIP archive containing the given members.

    Each member is (arc_name, absolute_path_on_disk). The archive uses ZIP64
    + data descriptors so we don't need to seek back to fix up sizes — works
    over a non-seekable HTTP response.

    Stored uncompressed (ZIP_STORED). Most package contents are already
    compressed media files; recompressing them would only burn CPU.
    """
    import zipfile

    class _StreamSink:
        """File-like sink that buffers writes; outer code drains() periodically."""
        def __init__(self) -> None:
            self._buf: list[bytes] = []
            self._pos = 0
        def write(self, data: bytes) -> int:
            self._buf.append(bytes(data))
            self._pos += len(data)
            return len(data)
        def tell(self) -> int:
            return self._pos
        def flush(self) -> None:
            pass
        def drain(self) -> bytes:
            if not self._buf:
                return b""
            out = b"".join(self._buf)
            self._buf.clear()
            return out

    sink = _StreamSink()
    with zipfile.ZipFile(sink, mode="w", compression=zipfile.ZIP_STORED,
                        allowZip64=True) as zf:
        for arc_name, path in members:
            info = zipfile.ZipInfo(filename=arc_name)
            info.compress_type = zipfile.ZIP_STORED
            with zf.open(info, mode="w", force_zip64=True) as zw:
                with open(path, "rb") as src:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        zw.write(chunk)
                        out = sink.drain()
                        if out:
                            yield out
            out = sink.drain()
            if out:
                yield out
    out = sink.drain()
    if out:
        yield out


def fmt_relative(dt: datetime | None) -> str:
    """'just now', '4 minutes ago', '2 hours ago', '3 days ago', '2 weeks ago'."""
    if dt is None:
        return "never"
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    delta = utcnow() - dt
    seconds = int(delta.total_seconds())
    if seconds < 45:
        return "just now"
    if seconds < 90:
        return "a minute ago"
    minutes = seconds // 60
    if minutes < 45:
        return f"{minutes} minutes ago"
    if minutes < 90:
        return "an hour ago"
    hours = minutes // 60
    if hours < 22:
        return f"{hours} hours ago"
    if hours < 36:
        return "a day ago"
    days = hours // 24
    if days < 7:
        return f"{days} days ago"
    if days < 14:
        return "a week ago"
    if days < 60:
        return f"{days // 7} weeks ago"
    months = days // 30
    if months < 12:
        return f"{months} months ago"
    return f"{days // 365} years ago"
