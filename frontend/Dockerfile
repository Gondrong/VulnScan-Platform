# node:20-slim is EOL and ships a Brotli decoder vulnerable to
# CVE-2026-111497; 24.22.1+ carries the fix.
FROM node:24-slim

WORKDIR /app

# Copy package files first for layer caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy rest of frontend source
COPY . .

# Default command (overridden by docker-compose)
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
