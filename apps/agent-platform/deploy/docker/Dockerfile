ARG PYTHON_BUILDER_IMAGE=python:3.12.13-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
ARG PYTHON_RUNTIME_IMAGE=ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

FROM ${PYTHON_BUILDER_IMAGE} AS builder
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN python -m pip install --no-cache-dir "uv==0.8.4"
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY prompts ./prompts
COPY evals ./evals
RUN uv sync --frozen --no-dev \
    && .venv/bin/python -c "import defusedxml.ElementTree" \
    && rm -f .venv/bin/python .venv/bin/python3 .venv/bin/python3.12 \
    && ln -s /usr/bin/python3.12 .venv/bin/python \
    && ln -s python .venv/bin/python3 \
    && ln -s python .venv/bin/python3.12

COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

FROM ${PYTHON_RUNTIME_IMAGE} AS runtime
WORKDIR /app

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3.12 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 agent \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agent

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --from=builder --chown=10001:10001 /app/src /app/src
COPY --from=builder --chown=10001:10001 /app/prompts /app/prompts
COPY --from=builder --chown=10001:10001 /app/evals /app/evals
COPY --from=builder --chown=10001:10001 /app/migrations /app/migrations
COPY --from=builder --chown=10001:10001 /app/alembic.ini /app/alembic.ini

USER 10001:10001
EXPOSE 8080 8081 9464
HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]

ENTRYPOINT ["agent-platform-api"]
