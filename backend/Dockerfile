FROM python:3.11-slim

# Install system dependencies including curl for health checks
# and nmap for port scanning plugin
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Default command (overridden by docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
