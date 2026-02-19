#!/bin/bash
set -e

# CyberAlarm PCA (Syslog Relay) Installation Script
# Usage: curl -fsSL <URL> | sudo bash -s -- <TOKEN> <ACR_USERNAME> <ACR_PASSWORD> [auto-update]

VERSION="1.0.0"
INSTALL_DIR="/opt/cyberalarm"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
ENV_FILE="$INSTALL_DIR/.env"
ACR_REGISTRY="npccprdcontainersukacr.azurecr.io"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Print functions
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                                                        ║"
    echo "║        CyberAlarm PCA Installer v${VERSION}                ║"
    echo "║                                                        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root or with sudo"
        echo ""
        echo "Please run: curl -fsSL <url> | sudo bash -s -- <token> <username> <password>"
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
        ubuntu|debian)
            install_docker_debian
            ;;
        rhel|centos|rocky|almalinux)
            install_docker_rhel
            ;;
        fedora)
            install_docker_fedora
            ;;
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

# Azure Container Registry Login
acr_login() {
    local username=$1
    local password=$2
    
    print_info "Logging into Azure Container Registry..."
    
    # Check if already logged in
    if docker manifest inspect $ACR_REGISTRY/syslog-relay:latest &>/dev/null; then
        print_success "Already authenticated to $ACR_REGISTRY"
        return 0
    fi
    
    # Login with provided credentials
    if echo "$password" | docker login $ACR_REGISTRY --username "$username" --password-stdin &>/dev/null; then
        print_success "Successfully logged into $ACR_REGISTRY"
        return 0
    else
        print_error "Failed to login to Azure Container Registry"
        print_info "Please verify your ACR username and password are correct"
        exit 1
    fi
}

# Create directory structure
create_directories() {
    print_info "Creating directory structure at $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR/scripts"
    chmod 755 "$INSTALL_DIR"
    print_success "Directories created"
}

# Create docker-compose.yml with optional Watchtower
create_compose_file() {
    local enable_watchtower=$1
    print_info "Creating Docker Compose configuration..."
    
    if [[ "$enable_watchtower" == "true" ]]; then
        # With Watchtower for auto-updates
        cat > "$COMPOSE_FILE" << 'COMPOSE_EOF'
services:
  syslog-relay:
    image: npccprdcontainersukacr.azurecr.io/syslog-relay:latest
    container_name: syslog-relay
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    mem_limit: 2g
    mem_reservation: 1g
    cpus: 1
    pids_limit: 100
    volumes:
      - syslog:/var/lib/syslog-relay:rw
    ports:
      - 514:514/udp
      - 514:514/tcp
    environment:
      - REGISTRATION_TOKEN=${REGISTRATION_TOKEN}
      - StatusEndpoint=${STATUS_ENDPOINT:-https://api-ci-cyberalarm.waterstons.win/api/v1/SyslogRelayStatus}
      - LOGGING__LOGLEVEL__DEFAULT=${LOG_LEVEL:-Information}
      - MaximumTcpClients=${MAX_TCP_CLIENTS:-50}
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  watchtower:
    image: nickfedor/watchtower:latest
    container_name: watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_POLL_INTERVAL=3600
      - WATCHTOWER_LABEL_ENABLE=true
      - WATCHTOWER_INCLUDE_RESTARTING=true
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"

volumes:
  syslog:
    name: cyberalarm-syslog
COMPOSE_EOF
        print_success "Docker Compose file created with Watchtower (auto-update every hour)"
    else
        # Without Watchtower
        cat > "$COMPOSE_FILE" << 'COMPOSE_EOF'
services:
  syslog-relay:
    image: npccprdcontainersukacr.azurecr.io/syslog-relay:latest
    container_name: syslog-relay
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    mem_limit: 2g
    mem_reservation: 1g
    cpus: 1
    pids_limit: 100
    volumes:
      - syslog:/var/lib/syslog-relay:rw
    ports:
      - 514:514/udp
      - 514:514/tcp
    environment:
      - REGISTRATION_TOKEN=${REGISTRATION_TOKEN}
      - StatusEndpoint=${STATUS_ENDPOINT:-https://api-ci-cyberalarm.waterstons.win/api/v1/SyslogRelayStatus}
      - LOGGING__LOGLEVEL__DEFAULT=${LOG_LEVEL:-Information}
      - MaximumTcpClients=${MAX_TCP_CLIENTS:-50}
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"

volumes:
  syslog:
    name: cyberalarm-syslog
COMPOSE_EOF
        print_success "Docker Compose file created (auto-updates disabled)"
    fi
    
    chmod 644 "$COMPOSE_FILE"
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

# Stop rsyslog if running
handle_rsyslog() {
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        print_warning "Detected rsyslog running on port 514"
        print_info "Stopping rsyslog to avoid port conflict..."
        systemctl stop rsyslog 2>/dev/null || true
        systemctl disable rsyslog 2>/dev/null || true
        print_success "rsyslog stopped and disabled"
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
        print_success "Docker Compose started"
    else
        print_error "Failed to start service"
        exit 1
    fi
    
    print_info "Waiting for containers to initialize..."
    sleep 8
    
    # Check if syslog-relay container exists (regardless of state)
    if docker compose ps -a | grep -q "syslog-relay"; then
        # Check the actual status
        RELAY_STATUS=$(docker compose ps --format json syslog-relay 2>/dev/null | grep -o '"State":"[^"]*"' | cut -d'"' -f4)
        
        if [[ "$RELAY_STATUS" == "running" ]]; then
            print_success "Service deployed and running!"
        elif [[ "$RELAY_STATUS" == "restarting" ]]; then
            print_warning "Service is restarting (this may be normal during registration)"
            print_info "Check status with: docker compose -f $COMPOSE_FILE ps"
        else
            print_warning "Service status: $RELAY_STATUS"
            print_info "Container may still be initializing. Check logs:"
            print_info "  docker compose -f $COMPOSE_FILE logs -f syslog-relay"
        fi
        
        # Show a snippet of recent logs
        echo ""
        print_info "Recent logs (last 10 lines):"
        docker compose logs --tail=10 syslog-relay
    else
        print_error "Service failed to start - container not found"
        docker compose logs
        exit 1
    fi
}

# Display summary
display_summary() {
    local has_watchtower=$1
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}║         Installation Completed Successfully!          ║${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${BLUE}Configuration File:${NC} $ENV_FILE"
    echo -e "${BLUE}Container Name:${NC} syslog-relay"
    echo ""
    
    if [[ "$has_watchtower" == "true" ]]; then
        echo -e "${BLUE}Auto-Updates:${NC} Enabled via Watchtower (checks hourly)"
        echo ""
    fi
    
    echo -e "${YELLOW}Useful Commands:${NC}"
    echo "  Check status:       docker compose -f $COMPOSE_FILE ps"
    echo "  View logs:          docker compose -f $COMPOSE_FILE logs -f syslog-relay"
    echo "  Restart service:    docker compose -f $COMPOSE_FILE restart syslog-relay"
    echo "  Stop service:       docker compose -f $COMPOSE_FILE down"
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
    
    # Parse arguments: token, username, password, optional auto-update flag
    REGISTRATION_TOKEN=${1:-}
    ACR_USERNAME=${2:-}
    ACR_PASSWORD=${3:-}
    AUTO_UPDATE_FLAG=${4:-}
    
    if [ -z "$REGISTRATION_TOKEN" ]; then
        print_error "Registration token is required"
        echo ""
        echo "Usage:"
        echo "  curl -fsSL <URL> | sudo bash -s -- <TOKEN> <ACR_USERNAME> <ACR_PASSWORD> [auto-update]"
        echo ""
        echo "Examples:"
        echo "  Without auto-update:"
        echo "    ... | sudo bash -s -- mytoken myuser mypass"
        echo ""
        echo "  With auto-update:"
        echo "    ... | sudo bash -s -- mytoken myuser mypass auto-update"
        exit 1
    fi
    
    if [ -z "$ACR_USERNAME" ] || [ -z "$ACR_PASSWORD" ]; then
        print_error "Azure Container Registry credentials are required"
        echo ""
        echo "Usage:"
        echo "  curl -fsSL <URL> | sudo bash -s -- <TOKEN> <ACR_USERNAME> <ACR_PASSWORD> [auto-update]"
        exit 1
    fi
    
    # Determine if auto-update is enabled
    ENABLE_WATCHTOWER="false"
    if [[ "$AUTO_UPDATE_FLAG" == "auto-update" || "$AUTO_UPDATE_FLAG" == "update" || "$AUTO_UPDATE_FLAG" == "yes" ]]; then
        ENABLE_WATCHTOWER="true"
        print_info "Auto-updates will be enabled via Watchtower"
    else
        print_info "Auto-updates disabled (add 'auto-update' as 4th parameter to enable)"
    fi
    
    check_root
    detect_os
    
    # Check and install Docker if needed
    if ! check_docker; then
        prompt_docker_install
    fi
    
    # Check Docker Compose
    if ! check_docker_compose; then
        print_error "Docker Compose plugin is required but not installed"
        exit 1
    fi
    
    # Login to Azure Container Registry
    acr_login "$ACR_USERNAME" "$ACR_PASSWORD"
    
    # Setup system
    handle_rsyslog
    create_directories
    create_compose_file "$ENABLE_WATCHTOWER"
    create_env_file "$REGISTRATION_TOKEN"
    
    # Deploy the service
    deploy_service
    
    # Summary
    display_summary "$ENABLE_WATCHTOWER"
}

main "$@"