# syntax=docker/dockerfile:1.7

FROM python:3.11.16-slim-trixie@sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    DATABASE_URL=sqlite:////data/vulntracker.db

RUN groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin app

WORKDIR /srv/app

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --no-compile --requirement /tmp/requirements.txt \
    && python -m pip uninstall --yes pip setuptools wheel jaraco.context \
    && rm /tmp/requirements.txt

COPY --chown=0:0 app/ ./
RUN mkdir -p /data \
    && chown "${APP_UID}:${APP_GID}" /data \
    && chmod -R a-w /srv/app

USER ${APP_UID}:${APP_GID}

EXPOSE 8000
VOLUME ["/data"]
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).close()"]

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--limit-concurrency", "100", "--timeout-keep-alive", "5"]
