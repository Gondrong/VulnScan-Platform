#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# VulnScan Platform — Auto-Updater Service
# Watches for update-trigger.json and runs git pull + docker rebuild.
# Auto-detects project directory from script location.
# ═══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
WATCH_DIR="$PROJECT/data"
TRIGGER="$WATCH_DIR/update-trigger.json"
RESULT="$WATCH_DIR/update-result.json"
LOG="/var/log/vulnscan-update.log"

# Ensure data directory exists
mkdir -p "$WATCH_DIR"

echo "[$(date)] VulnScan updater started" >> "$LOG"
echo "[$(date)] Project directory: $PROJECT" >> "$LOG"
echo "[$(date)] Watching: $TRIGGER" >> "$LOG"

write_status() {
    local status="$1"
    local message="$2"
    echo "{\"status\":\"${status}\",\"message\":\"${message}\",\"updated_at\":\"$(date -Iseconds)\"}" > "$RESULT"
}

while true; do
    if [ -f "$TRIGGER" ]; then
        echo "" >> "$LOG"
        echo "═══════════════════════════════════════════════════" >> "$LOG"
        echo "[$(date)] Update triggered" >> "$LOG"

        # Remove trigger immediately to prevent re-processing
        rm -f "$TRIGGER"

        # Phase 1: Git pull
        write_status "updating" "Pulling latest code from GitHub..."
        echo "[$(date)] Phase 1: git pull" >> "$LOG"
        cd "$PROJECT"

        # Clean __pycache__ files that conflict with git
        find "$PROJECT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
        echo "[$(date)] Cleaned __pycache__ directories" >> "$LOG"

        # Backup .env before reset (user config must survive)
        cp -f "$PROJECT/.env" "$PROJECT/.env.bak" 2>/dev/null

        # Reset local changes so git pull doesn't conflict
        git checkout -- . >> "$LOG" 2>&1
        git clean -fd --exclude=.env --exclude=.env.bak --exclude=data/ >> "$LOG" 2>&1

        # Pull latest
        git pull origin main >> "$LOG" 2>&1
        GIT_RC=$?

        # Restore user's .env (preserve their config)
        if [ -f "$PROJECT/.env.bak" ]; then
            cp -f "$PROJECT/.env.bak" "$PROJECT/.env"
            rm -f "$PROJECT/.env.bak"
            echo "[$(date)] Restored user .env config" >> "$LOG"
        fi

        if [ $GIT_RC -ne 0 ]; then
            echo "[$(date)] ERROR: git pull failed (rc=$GIT_RC)" >> "$LOG"
            write_status "failed" "Git pull failed (rc=$GIT_RC). Check $LOG for details."
            continue
        fi
        echo "[$(date)] git pull succeeded" >> "$LOG"

        # Phase 2: Docker build
        write_status "updating" "Rebuilding Docker containers..."
        echo "[$(date)] Phase 2: docker compose build" >> "$LOG"
        docker compose build >> "$LOG" 2>&1
        BUILD_RC=$?

        if [ $BUILD_RC -ne 0 ]; then
            echo "[$(date)] ERROR: docker compose build failed (rc=$BUILD_RC)" >> "$LOG"
            write_status "failed" "Docker build failed (rc=$BUILD_RC). Check $LOG for details."
            continue
        fi
        echo "[$(date)] docker compose build succeeded" >> "$LOG"

        # Phase 3: Restart services
        write_status "updating" "Restarting services..."
        echo "[$(date)] Phase 3: docker compose up -d" >> "$LOG"
        docker compose up -d >> "$LOG" 2>&1
        UP_RC=$?

        if [ $UP_RC -ne 0 ]; then
            echo "[$(date)] ERROR: docker compose up failed (rc=$UP_RC)" >> "$LOG"
            write_status "failed" "Container restart failed (rc=$UP_RC). Check $LOG for details."
            continue
        fi

        echo "[$(date)] Update complete!" >> "$LOG"
        echo "═══════════════════════════════════════════════════" >> "$LOG"

        write_status "success" "Update complete. Platform restarted successfully."
    fi

    sleep 5
done
