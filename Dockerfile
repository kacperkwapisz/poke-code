FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000 \
    HOME=/home/appuser

# System deps: git, node, ssh (for git push)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates openssh-client && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Claude Code CLI — cached unless base image changes
RUN npm install -g @anthropic-ai/claude-code && \
    npm cache clean --force

# Python deps — cached unless requirements.txt changes
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code — changes most often, last layer
COPY src/ src/
COPY config.example.yml config.example.yml

# Non-root user
RUN adduser --disabled-password --gecos "" appuser && \
    mkdir -p /workspaces /home/appuser/.claude && \
    chown -R appuser:appuser /workspaces /home/appuser/.claude /app

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/mcp || exit 1

CMD ["python", "src/server.py"]
