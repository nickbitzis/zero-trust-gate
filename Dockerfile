# Build stage: resolve and install dependencies with uv into a virtualenv.
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# Runtime stage: one image for the admin service, the proxy, and the demo backends (the command picks the role).
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 ztgate
WORKDIR /app
COPY --from=build --chown=ztgate:ztgate /app/.venv /app/.venv
COPY --chown=ztgate:ztgate policies ./policies
COPY --chown=ztgate:ztgate examples ./examples
# Nothing is written under /app today, but a data directory owned by the non-root user keeps that safe to add.
RUN mkdir -p /app/data && chown ztgate:ztgate /app/data
USER ztgate
ENV PATH="/app/.venv/bin:$PATH" HOST=0.0.0.0 PORT=8861 ZTGATE_POLICIES=/app/policies
EXPOSE 8861
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz', timeout=2)"
CMD ["ztgate", "serve"]
