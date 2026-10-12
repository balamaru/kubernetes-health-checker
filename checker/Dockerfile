FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HEALTH_PORT=8081 \
    STATE_FILE=/data/state.json

WORKDIR /app
# Tanpa dependensi eksternal — hanya Python standard library
COPY k8s_checker ./k8s_checker

RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir -p /data && chown 10001:10001 /data
USER 10001
VOLUME ["/data"]
EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('HEALTH_PORT','8081'), timeout=4)"

ENTRYPOINT ["python", "-m", "k8s_checker.main"]
