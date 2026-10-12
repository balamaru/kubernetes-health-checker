FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app
# Tanpa dependensi eksternal — hanya Python standard library
COPY discord_notifier ./discord_notifier

RUN useradd --system --uid 10001 --no-create-home app
USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'), timeout=4)"

ENTRYPOINT ["python", "-m", "discord_notifier.main"]
