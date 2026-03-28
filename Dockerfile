FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000 \
    ENVIRONMENT=production \
    HOME=/home/appuser \
    PATH="/home/appuser/.opencode/bin:/home/appuser/.claude/local/bin:$PATH"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Claude Code CLI (native binary)
RUN curl -fsSL https://claude.ai/install.sh | bash && \
    which claude || (find / -name claude -type f 2>/dev/null | head -1 | xargs -I{} ln -sf {} /usr/local/bin/claude)

# OpenCode CLI
RUN curl -fsSL https://opencode.ai/install | bash && \
    which opencode || ln -sf /home/appuser/.opencode/bin/opencode /usr/local/bin/opencode

# Python deps — cached unless requirements.txt changes
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY src/ src/
COPY config.example.yml config.example.yml

# Non-root user — own entire home dir so CLIs can create any subdirs they need
RUN adduser --disabled-password --gecos "" appuser && \
    mkdir -p /workspaces && \
    chown -R appuser:appuser /home/appuser /workspaces /app

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/mcp || exit 1

CMD ["python", "src/server.py"]
