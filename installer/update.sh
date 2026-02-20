#!/bin/bash
# CyberAlarm PCA Auto-Update Script
# Called by cron — paths passed in as arguments by the installer to avoid hardcoding.
#
# Usage: update.sh [--install-dir <path>] [--compose-file <path>]
#
# Update logic:
#   1. Fetch hashes.json from the CyberAlarm portal and use jq to extract authoritative hashes
#   2. Compare the expected hash against the local compose file — skip download if already current
#   3. If the compose file has changed, download and verify it against the portal hash before replacing it
#   4. If the portal is unreachable, leave the compose file and update script untouched and proceed
#   5. Check whether this script itself needs updating — if so, download, verify, and replace it;
#      the new version will be used on the next scheduled run
#   6. Pull the latest images, then verify each image signature with Cosign after the pull
#      so the freshly downloaded image is what gets verified, not a cached version
#   7. Restart the service only if any image digest actually changed

set -e

LOG_FILE="/var/log/cyberalarm-update.log"
HASHES_URL="https://npcccipcauksstweb001.z33.web.core.windows.net/hashes/hashes.json"
COMPOSE_URL="https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml"
UPDATE_SCRIPT_URL="https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/update.sh"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

usage() {
    echo "Usage: $0 [--install-dir <path>] [--compose-file <path>]"
    exit 1
}

# Parse arguments — all have defaults matching the standard installer locations
INSTALL_DIR="/opt/cyberalarm"
COMPOSE_FILE="/opt/cyberalarm/docker-compose.yml"
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
        *)
            echo "Unknown argument: $1"
            usage
            ;;
    esac
done

log "Starting update check (install-dir=$INSTALL_DIR, compose-file=$COMPOSE_FILE)..."

# ---------------------------------------------------------------------------
# Step 1: Fetch hashes.json to get the authoritative compose SHA256
# ---------------------------------------------------------------------------
EXPECTED_COMPOSE_HASH=""
HASHES_FETCH_OK=false

HASHES_JSON=$(curl -fsSL --max-time 10 "$HASHES_URL" 2>/dev/null) && HASHES_FETCH_OK=true || true

if [ "$HASHES_FETCH_OK" = true ]; then
    # Extract the dockerCompose sha256 using jq
    EXPECTED_COMPOSE_HASH=$(echo "$HASHES_JSON" | jq -r '.artifacts.dockerCompose.sha256' 2>/dev/null) || EXPECTED_COMPOSE_HASH=""
    # jq returns the string "null" when the key is missing — treat that as empty
    [ "$EXPECTED_COMPOSE_HASH" = "null" ] && EXPECTED_COMPOSE_HASH=

    if [ -n "$EXPECTED_COMPOSE_HASH" ]; then
        log "Fetched expected compose hash from portal: $EXPECTED_COMPOSE_HASH"
    else
        log "WARNING: Could not parse compose hash from hashes.json — falling back to unverified download"
        HASHES_FETCH_OK=false
    fi
else
    log "WARNING: Could not reach $HASHES_URL — falling back to unverified compose download"
fi

# ---------------------------------------------------------------------------
# Step 2: Update the compose file
# ---------------------------------------------------------------------------
if [ "$HASHES_FETCH_OK" = true ] && [ -n "$EXPECTED_COMPOSE_HASH" ]; then

    # Check if the local compose file already matches the expected hash
    LOCAL_COMPOSE_HASH=$(sha256sum "$COMPOSE_FILE" | cut -d' ' -f1)

    if [ "$LOCAL_COMPOSE_HASH" = "$EXPECTED_COMPOSE_HASH" ]; then
        log "Compose file is already up to date (hash matches portal). No download needed."
    else
        log "Compose file hash mismatch — downloading updated file..."
        log "  Local:    $LOCAL_COMPOSE_HASH"
        log "  Expected: $EXPECTED_COMPOSE_HASH"

        if ! curl -fsSL --max-time 30 "$COMPOSE_URL" -o "${COMPOSE_FILE}.new" 2>/dev/null; then
            log "ERROR: Failed to download compose file from $COMPOSE_URL"
            exit 1
        fi

        DOWNLOADED_HASH=$(sha256sum "${COMPOSE_FILE}.new" | cut -d' ' -f1)
        if [ "$DOWNLOADED_HASH" != "$EXPECTED_COMPOSE_HASH" ]; then
            log "ERROR: Downloaded compose file hash does not match portal hash."
            log "  Downloaded: $DOWNLOADED_HASH"
            log "  Expected:   $EXPECTED_COMPOSE_HASH"
            log "  The file may have been tampered with or the portal is out of sync. Aborting."
            rm -f "${COMPOSE_FILE}.new"
            exit 1
        fi

        mv "${COMPOSE_FILE}.new" "$COMPOSE_FILE"
        log "Compose file updated and verified successfully."
    fi

else
    # Portal unavailable — assume the current compose file is correct and skip the download.
    # Without a trusted hash to verify against, downloading would offer no security guarantee.
    log "WARNING: Portal unreachable — skipping compose file update. Current file will be used as-is."
fi

# ---------------------------------------------------------------------------
# Step 3: Check for update script update
# ---------------------------------------------------------------------------
SELF="$(realpath "$0")"
SELF_HASH=$(sha256sum "$SELF" | cut -d' ' -f1)

EXPECTED_SCRIPT_HASH=$(echo "$HASHES_JSON" | jq -r '.artifacts.updateScript.sha256' 2>/dev/null) || EXPECTED_SCRIPT_HASH=""
[ "$EXPECTED_SCRIPT_HASH" = "null" ] && EXPECTED_SCRIPT_HASH=""

if [ "$HASHES_FETCH_OK" = true ] && [ -n "$EXPECTED_SCRIPT_HASH" ]; then
    if [ "$SELF_HASH" = "$EXPECTED_SCRIPT_HASH" ]; then
        log "Update script is already current."
    else
        log "Update script has changed — downloading new version..."
        if curl -fsSL --max-time 30 "$UPDATE_SCRIPT_URL" -o "${SELF}.new" 2>/dev/null; then
            DOWNLOADED_SCRIPT_HASH=$(sha256sum "${SELF}.new" | cut -d' ' -f1)
            if [ "$DOWNLOADED_SCRIPT_HASH" = "$EXPECTED_SCRIPT_HASH" ]; then
                chmod 750 "${SELF}.new"
                mv "${SELF}.new" "$SELF"
                log "Update script replaced and verified. New version will run on next scheduled execution."
                echo "A new version of the update script has been installed and will be used from the next scheduled run."
            else
                log "ERROR: Downloaded update script hash does not match portal hash. Keeping current version."
                log "  Downloaded: $DOWNLOADED_SCRIPT_HASH"
                log "  Expected:   $EXPECTED_SCRIPT_HASH"
                rm -f "${SELF}.new"
            fi
        else
            log "WARNING: Failed to download new update script. Keeping current version."
        fi
    fi
else
    log "Portal unavailable — skipping update script update check."
fi

# ---------------------------------------------------------------------------
# Step 4: Pull latest images, verify signatures, and restart if updated
# ---------------------------------------------------------------------------
# Extract all image references from the compose file first
mapfile -t COMPOSE_IMAGES < <(cd "$INSTALL_DIR" && docker compose config --format json 2>/dev/null | jq -r '.services[].image')

if [ "${#COMPOSE_IMAGES[@]}" -eq 0 ]; then
    log "ERROR: Could not extract any image references from $COMPOSE_FILE. Aborting."
    exit 1
fi

cd "$INSTALL_DIR"

# Capture digests before the pull so we can compare afterwards
declare -A PRE_DIGESTS
for COMPOSE_IMAGE in "${COMPOSE_IMAGES[@]}"; do
    PRE_DIGESTS["$COMPOSE_IMAGE"]=$(docker inspect --format='{{index .RepoDigests 0}}' "$COMPOSE_IMAGE" 2>/dev/null || echo "none")
done

log "Pulling latest images..."
docker compose pull 2>&1 | while IFS= read -r line; do log "Pull: $line"; done

# Verify signatures after the pull so Cosign inspects the freshly pulled image,
# not a potentially stale cached version that still carries the same tag.
if command -v cosign &>/dev/null; then
    for COMPOSE_IMAGE in "${COMPOSE_IMAGES[@]}"; do
        log "Verifying image signature with Cosign: $COMPOSE_IMAGE"
        if cosign verify \
            --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
            "$COMPOSE_IMAGE" &>/dev/null; then
            log "Image signature verified — $COMPOSE_IMAGE is authentic and untampered."
        else
            log "ERROR: Image signature verification failed for $COMPOSE_IMAGE."
            log "       The image may have been tampered with. Aborting update."
            exit 1
        fi
    done
else
    log "WARNING: Cosign is not installed — skipping image signature verification."
    log "         Install Cosign for production deployments: https://docs.sigstore.dev/cosign/installation"
fi

# Compare digests to detect whether any image actually changed
UPDATED=false
for COMPOSE_IMAGE in "${COMPOSE_IMAGES[@]}"; do
    POST_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$COMPOSE_IMAGE" 2>/dev/null || echo "none")
    if [ "${PRE_DIGESTS[$COMPOSE_IMAGE]}" != "$POST_DIGEST" ]; then
        log "New image detected: $COMPOSE_IMAGE"
        log "  Before: ${PRE_DIGESTS[$COMPOSE_IMAGE]}"
        log "  After:  $POST_DIGEST"
        UPDATED=true
    fi
done

if [ "$UPDATED" = true ]; then
    log "Restarting service..."
    docker compose up -d
    log "Service restarted."
else
    log "No new images. Service not restarted."
fi

log "Update check complete."