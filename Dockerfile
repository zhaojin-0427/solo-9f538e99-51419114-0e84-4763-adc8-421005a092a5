FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/registry.db \
    STORAGE_DIR=/data/storage

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY wsgi.py ./

# Run as the unprivileged user that owns the mounted volume.
RUN mkdir -p /data && chown -R 10001:10001 /data /srv \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin registry
USER 10001

EXPOSE 8000
VOLUME ["/data"]

# One gunicorn worker: SQLite writes are serialized in-process and the startup
# sweep must not race a second worker's in-flight publication. Threads give
# concurrency for reads and static assets. Cross-process safety is still
# enforced by BEGIN IMMEDIATE for anyone who scales out.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", \
     "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
