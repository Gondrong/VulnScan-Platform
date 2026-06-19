FROM python:3.11-slim

# Install system dependencies including curl for health checks,
# nmap for port scanning, git for testssl.sh, and Perl for nikto/testssl
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    unzip \
    git \
    bsdmainutils \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ── External pentest tools ─────────────────────────────────────────

# Nuclei (ProjectDiscovery) — template-based vulnerability scanning
ARG NUCLEI_VERSION=3.3.7
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
      -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent || true

# testssl.sh — comprehensive TLS/SSL testing
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /opt/testssl.sh/testssl.sh

# ffuf — fast web fuzzer (directory/vhost/parameter discovery)
ARG FFUF_VERSION=2.1.0
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz" \
      -o /tmp/ffuf.tar.gz && \
    tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm /tmp/ffuf.tar.gz

# subfinder (ProjectDiscovery) — passive subdomain enumeration
ARG SUBFINDER_VERSION=2.6.7
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${ARCH}.zip" \
      -o /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

# httpx (ProjectDiscovery) — HTTP probing + tech detection
ARG HTTPX_VERSION=1.6.9
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" \
      -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm /tmp/httpx.zip

# sqlmap — advanced SQL injection testing
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Bundled wordlist for ffuf (common directories/files)
RUN mkdir -p /opt/wordlists && \
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
      -o /opt/wordlists/common.txt && \
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
      -o /opt/wordlists/raft-medium-directories.txt

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

