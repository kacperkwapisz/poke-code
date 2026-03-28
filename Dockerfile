# ---------- stage 1: deps ----------
FROM python:3.13-slim AS deps

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Python deps — cached unless requirements.txt changes
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Claude Code CLI — cached unless base image changes
RUN npm install -g @anthropic-ai/claude-code && \
    npm cache clean --force

# ---------- stage 2: runtime ----------
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000 \
    HOME=/home/appuser

# Minimal runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Copy Node.js from deps stage
COPY --from=deps /usr/bin/node /usr/bin/node
COPY --from=deps /usr/lib/node_modules /usr/lib/node_modules
COPY --from=deps /usr/bin/npm /usr/bin/npm
COPY --from=deps /usr/bin/npx /usr/bin/npx

# Copy globally installed npm packages (Claude Code CLI)
COPY --from=deps /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy Python packages from deps stage
COPY --from=deps /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

WORKDIR /app
COPY src/ src/
COPY config.example.yml config.example.yml

# Non-root user with home dir for Claude Code CLI config
RUN adduser --disabled-password --gecos "" appuser && \
    mkdir -p /workspaces /home/appuser/.claude && \
    chown -R appuser:appuser /workspaces /home/appuser/.claude /app

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/mcp || exit 1

CMD ["python", "src/server.py"]
