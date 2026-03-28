FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Claude Code CLI (native binary, no Node.js needed)
RUN curl -fsSL https://claude.ai/install.sh | bash
