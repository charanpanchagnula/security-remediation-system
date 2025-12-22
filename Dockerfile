# ==========================================
# Stage 1: Frontend Builder
# ==========================================
FROM node:20-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --legacy-peer-deps
COPY frontend/ ./
# Add environment variables needed for build (e.g. Clerk keys if not public)
# For static export, we often need these at build time.
ARG NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
ENV NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=$NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
RUN npm run build

# ==========================================
# Stage 2: Final Image (Backend + Static Frontend)
# ==========================================
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    PATH="/root/.local/bin:$PATH" \
    PORT=8000

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    openssh-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go (needed for Trivy and some Semgrep extensions)
COPY --from=golang:1.23-bookworm /usr/local/go /usr/local/go
ENV PATH=$PATH:/usr/local/go/bin

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Install Checkov independently
RUN pip install --no-cache-dir checkov

# Setup Work Directory
WORKDIR /app/backend

# Copy backend dependency files
COPY backend/pyproject.toml backend/uv.lock ./
# Install dependencies
RUN uv sync --no-dev

# Copy backend source
COPY backend/src ./src
COPY backend/rules ./rules

# Copy built frontend from Stage 1
COPY --from=frontend-builder /app/frontend/out ./src/remediation_api/static

# Create necessary dirs
RUN mkdir -p local_storage work_dir

# Expose port
EXPOSE 8000

# Entrypoint
CMD ["sh", "-c", "uv run uvicorn src.remediation_api.main:app --host 0.0.0.0 --port 8000"]
