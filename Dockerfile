# SpeedyFiles — official image
# Multi-stage build: small final image, non-root runtime user.

FROM python:3.12-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# -----------------------------------------------------------------------------

FROM python:3.12-slim AS runtime

# Service user with stable UID/GID — easier bind-mount permissions
RUN groupadd --system --gid 8443 speedyfiles \
 && useradd  --system --uid 8443 --gid speedyfiles \
             --no-create-home --shell /usr/sbin/nologin speedyfiles \
 && mkdir -p /data /srv/files /app \
 && chown -R speedyfiles:speedyfiles /data /srv/files /app

# Bring deps from builder
COPY --from=builder /root/.local /home/speedyfiles/.local
ENV PATH=/home/speedyfiles/.local/bin:$PATH
RUN chown -R speedyfiles:speedyfiles /home/speedyfiles

# Bring the app
COPY --chown=speedyfiles:speedyfiles app /app/app

WORKDIR /app
USER speedyfiles

# Default env (override at runtime)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_URL="sqlite+aiosqlite:////data/app.db" \
    LOCAL_STORAGE_ROOT=/srv/files

EXPOSE 5300

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
       sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5300/healthz', timeout=3).status==200 else 1)"

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "5300", \
     "--forwarded-allow-ips", "*", "--proxy-headers"]
