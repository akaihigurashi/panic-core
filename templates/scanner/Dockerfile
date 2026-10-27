# @NAME@ - @TITLE@
FROM python:3.13-slim

LABEL org.opencontainers.image.title="@NAME@" \
      org.opencontainers.image.description="@TITLE@" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# unprivileged user, writable data volume (blocklist cache + audit log)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin scanner \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY @NAME@.py web.py ./
COPY static ./static

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PANIC_BIND=0.0.0.0 \
    PANIC_PORT=@PORT@ \
    STATE_DIRECTORY=/data \
    PANIC_AUDIT_DIR=/data/audit \
    PANIC_RETENTION_DAYS=30

USER 10001
VOLUME ["/data"]
EXPOSE @PORT@

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:@PORT@/healthz', timeout=3)" || exit 1

ENTRYPOINT ["python3", "web.py"]
