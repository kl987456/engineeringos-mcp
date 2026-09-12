FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN addgroup --system engineeringos && adduser --system --ingroup engineeringos engineeringos
WORKDIR /app
COPY pyproject.toml README.md NOTICE.md SECURITY.md ./
COPY config ./config
COPY engineeringos ./engineeringos
COPY dashboard ./dashboard
# ENGINEERINGOS_TENANT_ROOT must already exist (production.py never creates
# it silently) and the non-root user below can't create top-level dirs at
# runtime; pre-create default paths here for simple single-container
# deployments. docker-compose.yml overrides these with its own mounted
# volumes and never touches /data.
RUN pip install --no-cache-dir . \
    && mkdir -p /data/tenants /data/indexes \
    && chown -R engineeringos:engineeringos /data
USER engineeringos
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"]
CMD ["uvicorn", "engineeringos.production:application", "--host", "0.0.0.0", "--port", "8000"]
