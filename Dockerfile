# syntax=docker/dockerfile:1
# FSV — web dashboard + CLI. Build:  docker build -t fsv .   Run:  see docs/DEPLOYMENT.md
FROM python:3.12-slim AS build
WORKDIR /src
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt pyproject.toml LICENSE ./
COPY docs/PYPI.md ./docs/PYPI.md
COPY fsv ./fsv
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install . \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} +

FROM python:3.12-slim
# unprivileged user; data (scan DB) lives in a volume
RUN useradd --create-home --uid 10001 fsv && mkdir -p /data && chown fsv /data
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    FSV_DB=/data/scans.db \
    FSV_HOST=0.0.0.0 \
    FSV_PORT=7474 \
    FSV_BLOCK_PRIVATE=1 \
    FSV_REQUIRE_VERIFICATION=1
USER fsv
VOLUME ["/data"]
EXPOSE 7474
# FSV_TOKEN is deliberately NOT defaulted. Set it (and FSV_ALLOWED_HOSTS to the name users reach
# the dashboard by) for any container exposed beyond localhost; /healthz needs no token.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7474/healthz',timeout=4).status==200 else 1)"
ENTRYPOINT ["fsv"]
CMD ["web"]
