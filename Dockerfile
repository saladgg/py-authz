# ==========================================================
# django-authz — Demo Project Dockerfile
# ==========================================================

# Builds the demo Django application that exercises the
# django-authz library against a local Keycloak + OpenFGA
# stack.  Intended for development / local testing only.
#
# Build:  docker build -t django-authz-demo .
# Run:    docker compose up
#
# Stages
#   deps    — resolves and installs Python dependencies via uv
#   runtime — lean final image; copies venv from deps stage
# ==========================================================


# ── deps ──────────────────────────────────────────────────
FROM python:3.13-slim AS deps

# Bring in the uv binary from the official distroless image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency manifests first — this layer is cache-friendly:
# it is only invalidated when pyproject.toml or uv.lock change.
COPY pyproject.toml uv.lock ./

# The library source must be present so uv can install the project itself
COPY django_authz/ ./django_authz/

# Install production dependencies into a local virtual environment.
# --frozen  : respect the exact versions pinned in uv.lock
# --no-dev  : skip dev/test dependency groups
RUN uv sync --frozen --no-dev


# ── runtime ───────────────────────────────────────────────
FROM python:3.13-slim AS runtime

WORKDIR /app

# Import the pre-built virtual environment from the deps stage
COPY --from=deps /app/.venv /app/.venv

# Copy application source
COPY django_authz/ ./django_authz/
COPY demo_project/ ./demo_project/

# Activate the virtual environment by prepending it to PATH
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Keep Python output unbuffered so logs surface immediately in Docker
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV DJANGO_SETTINGS_MODULE=demo_project.settings

WORKDIR /app/demo_project

EXPOSE 8000

# Apply any outstanding migrations then start the development server.
# Replace with gunicorn / uvicorn for production workloads.
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000"]
