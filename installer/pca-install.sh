#!/bin/bash
set -e

# CyberAlarm PCA (Syslog Relay) Installation Script
# Usage: curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh | sudo bash -s -- <token> [auto-update]

VERSION="1.0.0"
INSTALL_DIR="/opt/cyberalarm"
DATA_DIR="$INSTALL_DIR/data"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
ENV_FILE="$INSTALL_DIR/.env"

COMPOSE_URL="https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml"
UPDATE_SCRIPT_URL="https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/update.sh"
UPDATE_SCRIPT="$INSTALL_DIR/scripts/update.sh"

# SHA256 hashes — replaced by CI pipeline at release time
COMPOSE_SHA256="2039c5e84d34be61b9a7f6ffabc94955217ede74a348ffc02d4167408a60bf93"
UPDATE_SCRIPT_SHA256="4a0015a14dcea2b05d22d53a3051c43da7f18f0e535075aeea4095cbc97b6530"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Print functions
print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                                                      ║"
    echo "║         CyberAlarm PCA Installer v${VERSION}              ║"
    echo "║                                                      ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root or with sudo"
        echo ""
        echo "Please run: curl -fsSL <url> | sudo bash -s -- <token> [auto-update]"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        print_info "Detected OS: $PRETTY_NAME"
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
}

# Check if Docker is installed
check_docker() {
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
        print_success "Docker is already installed (version $DOCKER_VERSION)"
        return 0
    else
        print_warning "Docker is not installed"
        return 1
    fi
}

# Check if Docker Compose is installed
check_docker_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_VERSION=$(docker compose version --short)
        print_success "Docker Compose is already installed (version $COMPOSE_VERSION)"
        return 0
    else
        print_warning "Docker Compose is not installed"
        return 1
    fi
}

# Install Docker on Ubuntu/Debian
install_docker_debian() {
    print_info "Installing Docker on Debian/Ubuntu..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_success "Docker installed successfully"
}

# Install Docker on RHEL/CentOS/Rocky/AlmaLinux
install_docker_rhel() {
    print_info "Installing Docker on RHEL-based system..."
    yum install -y -q yum-utils
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_success "Docker installed successfully"
}

# Install Docker on Fedora
install_docker_fedora() {
    print_info "Installing Docker on Fedora..."
    dnf -y -q install dnf-plugins-core
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    dnf install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_success "Docker installed successfully"
}

# Install Docker based on OS
install_docker() {
    case $OS in
        ubuntu|debian)               install_docker_debian ;;
        rhel|centos|rocky|almalinux) install_docker_rhel ;;
        fedora)                      install_docker_fedora ;;
        *)
            print_error "Unsupported OS: $OS"
            print_info "Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac
}

# Prompt for Docker installation
prompt_docker_install() {
    if [ -t 0 ]; then
        echo ""
        read -p "$(echo -e ${YELLOW}Would you like to install Docker now? [y/N]:${NC} )" -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_docker
        else
            print_error "Docker is required. Exiting."
            exit 1
        fi
    else
        print_info "Running in non-interactive mode. Installing Docker automatically..."
        install_docker
    fi
}

# Ensure cron is installed and running
ensure_cron() {
    print_info "Checking for cron daemon..."
    if command -v crontab &> /dev/null && (systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond 2>/dev/null); then
        print_success "Cron is already installed and running"
        return 0
    fi

    print_warning "Cron not found or not running. Installing..."
    case $OS in
        ubuntu|debian)
            apt-get install -y -qq cron
            systemctl enable cron
            systemctl start cron
            ;;
        rhel|centos|rocky|almalinux|fedora)
            yum install -y -q cronie 2>/dev/null || dnf install -y -q cronie
            systemctl enable crond
            systemctl start crond
            ;;
        *)
            print_warning "Cannot auto-install cron on $OS. Please install manually."
            return 1
            ;;
    esac
    print_success "Cron installed and started"
}
# Ensure jq is installed — used by the update script for reliable JSON parsing
ensure_jq() {
    print_info "Checking for jq..."
    if command -v jq &>/dev/null; then
        print_success "jq is already installed ($(jq --version))"
        return 0
    fi

    print_info "Installing jq..."
    case $OS in
        ubuntu|debian)
            apt-get install -y -qq jq
            ;;
        rhel|centos|rocky|almalinux|fedora)
            yum install -y -q jq 2>/dev/null || dnf install -y -q jq
            ;;
        *)
            print_warning "Cannot auto-install jq on $OS. Please install it manually."
            print_warning "The update script will fall back to grep/sed for JSON parsing."
            return 1
            ;;
    esac
    print_success "jq installed successfully"
}


# Check port 514 availability
check_port_514() {
    local port_in_use=false
    if command -v ss &>/dev/null; then
        ss -lntu 2>/dev/null | grep -q ':514 ' && port_in_use=true
    elif command -v netstat &>/dev/null; then
        netstat -lntu 2>/dev/null | grep -q ':514 ' && port_in_use=true
    fi

    if [ "$port_in_use" = true ]; then
        echo ""
        print_error "════════════════════════════════════════════════════════"
        print_error "Port 514 is already in use by another process."
        print_error ""
        print_error "CyberAlarm PCA requires TCP and UDP port 514 to be free"
        print_error "for syslog ingestion. Please stop the conflicting service"
        print_error "and re-run this installer."
        print_error ""
        print_error "To identify what is using port 514, run:"
        print_error "  sudo ss -lntup | grep ':514'"
        print_error "  sudo lsof -i :514"
        print_error "════════════════════════════════════════════════════════"
        echo ""
        exit 1
    fi
}

# Create directory structure
create_directories() {
    print_info "Creating directory structure at $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR/scripts"
    mkdir -p "$DATA_DIR"
    chown 1654:1654 "$DATA_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$INSTALL_DIR"
    print_success "Directories created (data dir: $DATA_DIR, owner: 1654:1654)"
}

# Download and verify a file from a URL against an expected SHA256
# Usage: download_verified_file <url> <destination> <expected_sha256> <friendly_name>
download_verified_file() {
    local url=$1
    local dest=$2
    local expected_hash=$3
    local name=$4
    local tmp_file="$dest.tmp"

    print_info "Downloading $name..."
    if ! curl -fsSL "$url" -o "$tmp_file"; then
        print_error "Failed to download $name from $url"
        rm -f "$tmp_file"
        exit 1
    fi

    print_info "Verifying $name integrity..."
    local actual_hash
    actual_hash=$(sha256sum "$tmp_file" | cut -d' ' -f1)

    if [ "$actual_hash" != "$expected_hash" ]; then
        print_error "════════════════════════════════════════════════════════"
        print_error "$name integrity check FAILED."
        print_error "The downloaded file does not match the expected hash."
        print_error ""
        print_error "Expected: $expected_hash"
        print_error "Got:      $actual_hash"
        print_error ""
        print_error "This may indicate the file has been tampered with or"
        print_error "that this installer is out of date. Please download a"
        print_error "fresh install command from the CyberAlarm portal."
        print_error "════════════════════════════════════════════════════════"
        rm -f "$tmp_file"
        exit 1
    fi

    mv "$tmp_file" "$dest"
    print_success "$name downloaded and verified"
}

# Download and verify docker-compose.yml
download_compose_file() {
    download_verified_file \
        "$COMPOSE_URL" \
        "$COMPOSE_FILE" \
        "$COMPOSE_SHA256" \
        "Docker Compose configuration"
    chmod 644 "$COMPOSE_FILE"
}

# Download and verify update script, then make executable
download_update_script() {
    download_verified_file \
        "$UPDATE_SCRIPT_URL" \
        "$UPDATE_SCRIPT" \
        "$UPDATE_SCRIPT_SHA256" \
        "update script"
    chmod 750 "$UPDATE_SCRIPT"
    print_success "Update script installed at $UPDATE_SCRIPT"
}

# Create .env file
create_env_file() {
    local token=$1
    print_info "Creating environment configuration..."
    cat > "$ENV_FILE" << ENV_EOF
# CyberAlarm PCA Configuration
# Generated on $(date)

# Required: Registration Token
REGISTRATION_TOKEN=$token

# Optional: Override defaults if needed
# STATUS_ENDPOINT=https://api-ci-cyberalarm.waterstons.win/api/v1/SyslogRelayStatus
# LOG_LEVEL=Information
# MAX_TCP_CLIENTS=50
ENV_EOF
    chmod 600 "$ENV_FILE"
    print_success "Environment file created and secured"
}

# Install cron job for auto-updates with random minute offset
# The cron job passes INSTALL_DIR and COMPOSE_FILE as arguments to the update script
install_cron_job() {
    print_info "Installing hourly auto-update cron job..."
    INSTALLED_CRON_MINUTE=$((RANDOM % 60))

    local cron_cmd="$UPDATE_SCRIPT --install-dir '$INSTALL_DIR' --compose-file '$COMPOSE_FILE'"

    (crontab -l 2>/dev/null | grep -v "$UPDATE_SCRIPT"; \
        echo "$INSTALLED_CRON_MINUTE * * * * $cron_cmd >> /var/log/cyberalarm-update.log 2>&1") | crontab -

    print_success "Cron job installed — will run at minute $INSTALLED_CRON_MINUTE past every hour"
}

# Verify image signature with Cosign
verify_image_signature() {
    print_info "Checking image signature verification capability..."

    if ! command -v cosign &> /dev/null; then
        echo ""
        print_warning "════════════════════════════════════════════════════════"
        print_warning "Cosign is not installed - skipping signature verification"
        print_warning ""
        print_warning "For production deployments in secure environments, we"
        print_warning "recommend installing Cosign to verify image signatures:"
        print_warning "  https://docs.sigstore.dev/cosign/installation"
        print_warning ""
        print_warning "To install Cosign:"
        print_warning "  curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        print_warning "  chmod +x cosign-linux-amd64"
        print_warning "  sudo mv cosign-linux-amd64 /usr/local/bin/cosign"
        print_warning "════════════════════════════════════════════════════════"
        echo ""
        return 0
    fi

    print_info "Verifying container image signature with Cosign..."

    mapfile -t COMPOSE_IMAGES < <(docker compose -f "$COMPOSE_FILE" config --format json 2>/dev/null | jq -r '.services[].image')

    if [ "${#COMPOSE_IMAGES[@]}" -eq 0 ]; then
        print_error "Could not extract image references from $COMPOSE_FILE. Aborting."
        exit 1
    fi

    local all_verified=true
    for COMPOSE_IMAGE in "${COMPOSE_IMAGES[@]}"; do
        print_info "Verifying: $COMPOSE_IMAGE"
        if cosign verify \
            --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
            "$COMPOSE_IMAGE" &>/dev/null; then
            print_success "✓ Signature verified - $COMPOSE_IMAGE is authentic and untampered"
        else
            print_error "Signature verification FAILED for $COMPOSE_IMAGE"
            all_verified=false
        fi
    done

    if [ "$all_verified" = false ]; then
        echo ""
        print_error "════════════════════════════════════════════════════════"
        print_error "Image signature verification FAILED"
        print_error ""
        print_error "One or more container images may have been tampered with"
        print_error "or are not from the official Waterstons repository."
        print_error ""
        print_error "For security compliance, we cannot proceed with installation."
        print_error "════════════════════════════════════════════════════════"
        echo ""
        exit 1
    fi
}

# Deploy the service
deploy_service() {
    print_info "Deploying CyberAlarm PCA service..."
    cd "$INSTALL_DIR"

    print_info "Pulling Docker image (this may take a moment)..."
    if docker compose pull; then
        print_success "Image pulled successfully"
    else
        print_error "Failed to pull Docker image"
        exit 1
    fi

    print_info "Starting service..."
    if docker compose up -d; then
        print_success "Service started"
    else
        print_error "Failed to start service"
        exit 1
    fi
}

# Verify the service registered correctly by checking for key.der
verify_service() {
    local KEY_FILE="$DATA_DIR/key.der"
    local MAX_WAIT=30
    local ELAPSED=0
    local INTERVAL=3

    print_info "Waiting for service to register (up to ${MAX_WAIT}s)..."

    while [ $ELAPSED -lt $MAX_WAIT ]; do
        if [ -f "$KEY_FILE" ]; then
            echo ""
            echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
            print_success "Service registered and running correctly!"
            echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
            echo ""
            return 0
        fi
        sleep $INTERVAL
        ELAPSED=$((ELAPSED + INTERVAL))
        echo -ne "${BLUE}[INFO]${NC} Still waiting for registration... (${ELAPSED}s / ${MAX_WAIT}s)\r"
    done

    echo ""
    echo -e "${RED}════════════════════════════════════════════════════════${NC}"
    print_error "Registration failed — registration key was not created after ${MAX_WAIT}s."
    print_error "The service may not have registered successfully with"
    print_error "the CyberAlarm platform. Check your registration token"
    print_error "and network connectivity, then review the logs below."
    echo -e "${RED}════════════════════════════════════════════════════════${NC}"
    echo ""
    print_info "Container logs (last 50 lines):"
    echo ""
    docker compose -f "$COMPOSE_FILE" logs --tail=50 syslog-relay
    echo ""
    print_info "To continue monitoring:"
    print_info "  docker compose -f $COMPOSE_FILE logs -f syslog-relay"
    echo ""
    exit 1
}

# Display summary
display_summary() {
    local has_autoupdate=$1
    local cron_minute=$2

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                      ║${NC}"
    echo -e "${GREEN}║        Installation Completed Successfully!         ║${NC}"
    echo -e "${GREEN}║                                                      S║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${BLUE}Data Directory:${NC}         $DATA_DIR"
    echo -e "${BLUE}Configuration File:${NC}     $ENV_FILE"
    echo -e "${BLUE}Container Name:${NC}         syslog-relay"
    echo ""

    if [[ "$has_autoupdate" == "true" ]]; then
        echo -e "${BLUE}Auto-Updates:${NC}  Enabled via cron (runs at minute $cron_minute of every hour)"
        echo -e "${BLUE}Update Script:${NC} $UPDATE_SCRIPT"
        echo -e "${BLUE}Update Log:${NC}    /var/log/cyberalarm-update.log"
        echo ""
    fi

    echo -e "${YELLOW}Useful Commands:${NC}"
    echo "  Check status:    docker compose -f $COMPOSE_FILE ps"
    echo "  View logs:       docker compose -f $COMPOSE_FILE logs -f syslog-relay"
    echo "  Restart service: docker compose -f $COMPOSE_FILE restart syslog-relay"
    echo "  Stop service:    docker compose -f $COMPOSE_FILE down"
    if [[ "$has_autoupdate" == "true" ]]; then
        echo "  Manual update:   $UPDATE_SCRIPT --install-dir '$INSTALL_DIR' --compose-file '$COMPOSE_FILE'"
    fi
    echo ""
    echo -e "${YELLOW}Port Configuration:${NC}"
    echo "  TCP/UDP 514: Syslog ingestion"
    echo ""
    echo -e "${GREEN}Your PCA is now ready to receive syslog messages!${NC}"
    echo ""
}

# Main installation flow
main() {
    print_banner

    REGISTRATION_TOKEN=${1:-}
    AUTO_UPDATE_FLAG=${2:-}

    if [ -z "$REGISTRATION_TOKEN" ]; then
        print_error "Registration token is required"
        echo ""
        echo "Usage:"
        echo "  curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh | sudo bash -s -- <token> [auto-update]"
        echo ""
        echo "Examples:"
        echo "  Without auto-update: ... | sudo bash -s -- mytoken"
        echo "  With auto-update:    ... | sudo bash -s -- mytoken auto-update"
        exit 1
    fi

    ENABLE_AUTOUPDATE="false"
    INSTALLED_CRON_MINUTE=0

    if [[ "$AUTO_UPDATE_FLAG" == "auto-update" || "$AUTO_UPDATE_FLAG" == "update" || "$AUTO_UPDATE_FLAG" == "yes" ]]; then
        ENABLE_AUTOUPDATE="true"
        print_info "Auto-updates will be enabled via cron job"
    else
        print_info "Auto-updates disabled (pass 'auto-update' as 2nd argument to enable)"
    fi

    check_root
    detect_os
    check_port_514

    # Check and install Docker if needed
    if ! check_docker; then
        prompt_docker_install
    fi

    # Require Docker Compose plugin
    if ! check_docker_compose; then
        print_error "Docker Compose plugin is required but not installed"
        exit 1
    fi

    # Prepare filesystem
    create_directories
    download_compose_file
    create_env_file "$REGISTRATION_TOKEN"

    # Setup auto-update if requested
    if [[ "$ENABLE_AUTOUPDATE" == "true" ]]; then
        ensure_cron
        ensure_jq
        download_update_script
        install_cron_job
    fi

    # Verify image signature before deployment
    verify_image_signature

    # Deploy and verify
    deploy_service
    verify_service

    # Summary (only reached if verify_service succeeds)
    display_summary "$ENABLE_AUTOUPDATE" "$INSTALLED_CRON_MINUTE"
}

main "$@"
