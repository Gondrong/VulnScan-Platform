#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# VulnScan Platform — Updater Service Installer
# Auto-detects project directory. Works on any Linux distro/user/path.
#
# Usage:
#   cd /path/to/VulnScan-Platform
#   sudo bash scripts/install-updater.sh
# ═══════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
SERVICE_TEMPLATE="$SCRIPT_DIR/vulnscan-updater.service"
SERVICE_DST="/etc/systemd/system/vulnscan-updater.service"
UPDATER_SCRIPT="$SCRIPT_DIR/vulnscan-updater.sh"

echo "╔═══════════════════════════════════════════════╗"
echo "║  VulnScan Platform — Updater Installer        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "  Project directory: $PROJECT"
echo "  Updater script:    $UPDATER_SCRIPT"
echo "  Service file:      $SERVICE_DST"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Check prerequisites
if ! command -v docker &> /dev/null; then
    echo "ERROR: docker is not installed"
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "ERROR: git is not installed"
    exit 1
fi

if [ ! -f "$SERVICE_TEMPLATE" ]; then
    echo "ERROR: Service template not found at $SERVICE_TEMPLATE"
    exit 1
fi

# Make updater script executable
chmod +x "$UPDATER_SCRIPT"

# Generate systemd service from template
echo "[1/4] Generating systemd service file..."
sed "s|__PROJECT_DIR__|$PROJECT|g" "$SERVICE_TEMPLATE" > "$SERVICE_DST"

# Reload systemd
echo "[2/4] Reloading systemd..."
systemctl daemon-reload

# Enable service (auto-start on boot)
echo "[3/4] Enabling service..."
systemctl enable vulnscan-updater

# Start service
echo "[4/4] Starting updater service..."
systemctl start vulnscan-updater

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✓ VulnScan updater installed successfully!"
echo ""
echo "  Status:  systemctl status vulnscan-updater"
echo "  Logs:    journalctl -u vulnscan-updater -f"
echo "  Update:  tail -f /var/log/vulnscan-update.log"
echo "═══════════════════════════════════════════════"
