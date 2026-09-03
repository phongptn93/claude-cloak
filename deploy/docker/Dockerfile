# Build with uv, run without it: the final image carries only the resolved
# virtualenv, so neither uv nor pip nor a compiler is present at runtime.
#
#   docker build -f deploy/docker/Dockerfile -t claude-cloak .
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies resolve in their own layer, so editing source does not
# reinstall them. --locked fails the build when uv.lock and pyproject.toml
# have drifted apart, which is what makes the image reproducible.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --no-install-project

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable


FROM python:3.13-slim-bookworm

# The slim base ships pip; the venv is already resolved, so drop it rather
# than leave an installer in a production image.
RUN python -m pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true \
 && useradd --system --uid 10001 --create-home --home-dir /home/cloak cloak \
 && mkdir -p /data /acme && chown cloak:cloak /data /acme

COPY --from=builder --chown=cloak:cloak /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    CLAUDE_CLOAK_ENV=/data/.env

# /data holds .env (identity capture writes back to it), .quota.json and
# .coach.json. Mount it; nothing valuable lives in the image layer.
VOLUME ["/data"]
WORKDIR /data
USER cloak
EXPOSE 9999 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9999/health',timeout=4).status==200 else 1)"

CMD ["claude-cloak"]
