FROM python:3.11-slim

# Install system dependencies including curl for health checks
# and nmap for port scanning plugin
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Claude Code CLI)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI
# IMPORTANT: pin to the v1.x line — it's a Node.js script and runs on any CPU.
# v2.x switched to a Bun-bundled standalone binary that segfaults on CPUs lacking
# AVX/AVX2 (older bare-metal servers, low-spec VMs). Override at build time with
#   docker compose build --build-arg CLAUDE_CLI_VERSION=2 backend worker
# if your host has AVX2 and you want the newer CLI.
ARG CLAUDE_CLI_VERSION=1
WORKDIR /tmp
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CLI_VERSION}

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Default command (overridden by docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]

