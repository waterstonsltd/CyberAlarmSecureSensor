#!/bin/bash
# CyberAlarm PCA Auto-Update Script
# Called by cron — paths passed in as arguments by the installer to avoid hardcoding.
#
# Usage: update.sh --install-dir <path> --compose-file <path> --compose-url <url>

set -e

LOG_FILE="/var/log/cyberalarm-update.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

usage() {
    echo "Usage: $0 --install-dir <path> --compose-file <path> --compose-url <url>"
    exit 1
}

# Parse arguments — all have defaults matching the standard installer locations
INSTALL_DIR="/opt/cyberalarm"
COMPOSE_FILE="/opt/cyberalarm/docker-compose.yml"
COMPOSE_URL="https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --compose-file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        --compose-url)
            COMPOSE_URL="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            ;;
    esac
done

log "Starting update check (install-dir=$INSTALL_DIR, compose-file=$COMPOSE_FILE)..."

# Download latest compose file
if ! curl -fsSL "$COMPOSE_URL" -o "${COMPOSE_FILE}.new" 2>/dev/null; then
    log "ERROR: Failed to download latest docker-compose file from $COMPOSE_URL"
    exit 1
fi

# Check if compose file has changed
if diff -q "$COMPOSE_FILE" "${COMPOSE_FILE}.new" &>/dev/null; then
    log "Compose file unchanged."
    rm -f "${COMPOSE_FILE}.new"
else
    log "Compose file updated — replacing."
    mv "${COMPOSE_FILE}.new" "$COMPOSE_FILE"
fi

# Pull latest images
cd "$INSTALL_DIR"
PULL_OUTPUT=$(docker compose pull 2>&1)
log "Pull output: $PULL_OUTPUT"

# Restart if any images were updated
if echo "$PULL_OUTPUT" | grep -q "Pull complete\|Downloaded newer image"; then
    log "New image(s) detected — restarting service..."
    docker compose up -d
    log "Service restarted."
else
    log "No new images. Service not restarted."
fi

log "Update check complete."