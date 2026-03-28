FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# System deps + Node.js
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates openssh-client && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Claude Code CLI (the slow part)
RUN npm install -g @anthropic-ai/claude-code && \
    npm cache clean --force
