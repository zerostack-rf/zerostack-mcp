FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-slim-trixie AS runtime

LABEL io.modelcontextprotocol.server.name="io.github.zerostack-rf/zerostack-mcp" \
      org.opencontainers.image.title="zerostack-mcp" \
      org.opencontainers.image.description="SMLIGHT ZeroStack RF Diagnostics & Benchmark MCP Server" \
      org.opencontainers.image.url="https://smlight.tech/software/zerostack" \
      org.opencontainers.image.source="https://github.com/zerostack-rf/zerostack-mcp" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd -g 10001 mcpuser \
    && useradd -u 10001 -g mcpuser -d /var/lib/mcpuser -s /usr/sbin/nologin mcpuser \
    && install -d -o mcpuser -g mcpuser -m 0700 /var/lib/mcpuser

WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
CMD ["zerostack-mcp"]