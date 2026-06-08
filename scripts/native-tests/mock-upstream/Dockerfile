# Minimal ETag/counter/mutation-aware mock upstream for cache-correctness E2E.
# Stdlib-only Python server — no pip install, tiny image, fast startup.
FROM python:3.12-slim

WORKDIR /app
COPY mock_upstream.py /app/mock_upstream.py

EXPOSE 9101
# Healthcheck hits the out-of-band control endpoint (never proxied).
HEALTHCHECK --interval=3s --timeout=3s --retries=10 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:9101/__mock__/health').read()==b'ok' else 1)"

ENTRYPOINT ["python3", "/app/mock_upstream.py", "--port", "9101", "--host", "0.0.0.0"]
