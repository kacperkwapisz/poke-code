ARG BASE_IMAGE=ghcr.io/kacperkwapisz/poke-code-base:latest
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000 \
    HOME=/home/appuser

WORKDIR /app

# Python deps — cached unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
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
