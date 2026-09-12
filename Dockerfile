FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN addgroup --system engineeringos && adduser --system --ingroup engineeringos engineeringos
WORKDIR /app
COPY pyproject.toml README.md NOTICE.md SECURITY.md ./
COPY config ./config
COPY engineeringos ./engineeringos
COPY dashboard ./dashboard
RUN pip install --no-cache-dir .
USER engineeringos
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"]
CMD ["uvicorn", "engineeringos.production:application", "--host", "0.0.0.0", "--port", "8000"]
