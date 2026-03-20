#!/usr/bin/env bash
set -Eeuo pipefail

# CyberAlarm PCA (Syslog Relay) Installation Script
# Usage: curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh | sudo bash -s -- <token> [auto-update]

readonly VERSION="1.0.0"
readonly INSTALL_DIR="/opt/cyberalarm"
readonly DATA_DIR="${INSTALL_DIR}/data"
readonly COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"
readonly ENV_FILE="${INSTALL_DIR}/.env"
readonly COMPOSE_URL="https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/docker-compose.yaml"
readonly UPDATE_SCRIPT="${INSTALL_DIR}/scripts/update.sh"

# SHA256 hashes - replaced by CI pipeline at release time
readonly COMPOSE_SHA256="888ec31188e97f2628d787a42d0171bba50152cd065ae0fd37764197c93bdf01"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

OS=""
DOCKER_VERSION=""
COMPOSE_VERSION=""
INSTALLED_CRON_MINUTE=0
ASSUME_YES="false"
PARSED_REGISTRATION_TOKEN=""
PARSED_AUTO_UPDATE_FLAG=""

print_separator() {
    printf '%s\n' "========================================================"
    return 0
}

print_info() {
    local message="$1"

    printf '%b\n' "${BLUE}[INFO]${NC} ${message}"
    return 0
}

print_success() {
    local message="$1"

    printf '%b\n' "${GREEN}[SUCCESS]${NC} ${message}"
    return 0
}

print_warning() {
    local message="$1"

    printf '%b\n' "${YELLOW}[WARNING]${NC} ${message}"
    return 0
}

print_error() {
    local message="$1"

    printf '%b\n' "${RED}[ERROR]${NC} ${message}"
    return 0
}

die() {
    local message="$1"

    print_error "${message}"
    exit 1
    # shellcheck disable=SC2317
    return 1
}

on_error() {
    local exit_code="$?"
    local line_number="$1"

    print_error "Installer failed at line ${line_number} with exit code ${exit_code}."
    print_error "Re-run with the same arguments and review the output above for the failing command."
    exit "${exit_code}"
    # shellcheck disable=SC2317
    return "${exit_code}"
}

trap 'on_error ${LINENO}' ERR

print_banner() {
    printf '%b\n' "${BLUE}"
    print_separator
    printf '%s\n' "CyberAlarm PCA Installer v${VERSION}"
    print_separator
    printf '%b\n' "${NC}"
    return 0
}

usage() {
    printf '%s\n' "Usage:"
    printf '%s\n' "  curl -fsSL https://raw.githubusercontent.com/waterstonsltd/CyberAlarmSecureSensor/refs/heads/main/installer/pca-install.sh | sudo bash -s -- <token> [auto-update]"
    printf '%s\n' ""
    printf '%s\n' "Examples:"
    printf '%s\n' "  Without auto-update: ... | sudo bash -s -- mytoken"
    printf '%s\n' "  With auto-update:    ... | sudo bash -s -- mytoken auto-update"
    printf '%s\n' "  Non-interactive:     ... | sudo bash -s -- --yes mytoken auto-update"
    return 0
}

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        die "Required command '${command_name}' is not available on this host."
    fi

    return 0
}

check_required_commands() {
    require_command curl
    require_command sha256sum
    require_command grep
    require_command cut
    require_command tee
    require_command systemctl
    require_command bash
    return 0
}

validate_registration_token() {
    local registration_token="$1"

    if [[ -z "${registration_token//[[:space:]]/}" ]]; then
        die "Registration token is required."
    fi

    if [[ "${registration_token}" =~ [[:space:]] ]]; then
        die "Registration token must not contain whitespace."
    fi

    return 0
}

parse_arguments() {
    local -a positional_args=()
    local argument=""

    for argument in "$@"; do
        case "${argument}" in
            -h|--help)
                usage
                exit 0
                ;;
            -y|--yes)
                ASSUME_YES="true"
                ;;
            auto-update|update|yes)
                positional_args+=("${argument}")
                ;;
            --*)
                die "Unknown option: ${argument}"
                ;;
            *)
                positional_args+=("${argument}")
                ;;
        esac
    done

    if [[ "${#positional_args[@]}" -eq 0 ]]; then
        PARSED_REGISTRATION_TOKEN=""
        PARSED_AUTO_UPDATE_FLAG=""
        return 0
    fi

    if [[ "${#positional_args[@]}" -gt 2 ]]; then
        die "Too many positional arguments provided."
    fi

    PARSED_REGISTRATION_TOKEN="${positional_args[0]}"
    PARSED_AUTO_UPDATE_FLAG="${positional_args[1]:-}"

    if [[ -n "${PARSED_AUTO_UPDATE_FLAG}" && "${PARSED_AUTO_UPDATE_FLAG}" != "auto-update" && "${PARSED_AUTO_UPDATE_FLAG}" != "update" && "${PARSED_AUTO_UPDATE_FLAG}" != "yes" ]]; then
        die "Unsupported auto-update flag '${PARSED_AUTO_UPDATE_FLAG}'. Use 'auto-update'."
    fi

    return 0
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        printf '\n'
        printf '%s\n' "Please run: curl -fsSL <url> | sudo bash -s -- <token> [auto-update]"
        exit 1
    fi

    return 0
}

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS. /etc/os-release not found."
    fi

    # shellcheck disable=SC1091
    . /etc/os-release
    OS="${ID}"
    print_info "Detected OS: ${PRETTY_NAME}"
    return 0
}

check_docker() {
    if command -v docker >/dev/null 2>&1; then
        DOCKER_VERSION="$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)"
        print_success "Docker is already installed (version ${DOCKER_VERSION})"
        return 0
    fi

    print_warning "Docker is not installed"
    return 1
}

check_docker_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_VERSION="$(docker compose version --short)"
        print_success "Docker Compose is already installed (version ${COMPOSE_VERSION})"
        return 0
    fi

    print_warning "Docker Compose is not installed"
    return 1
}

install_docker_debian() {
    print_info "Installing Docker on Debian/Ubuntu..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${OS}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    printf '%s\n' "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS} $(lsb_release -cs) stable" \
        | tee /etc/apt/sources.list.d/docker.list >/dev/null
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_success "Docker installed successfully"
    return 0
}

install_docker_rhel() {
    print_info "Installing Docker on RHEL-based system..."
    yum install -y -q yum-utils
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_success "Docker installed successfully"
    return 0
}

install_docker_fedora() {
    print_info "Installing Docker on Fedora..."
    dnf -y -q install dnf-plugins-core
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    dnf install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    print_success "Docker installed successfully"
    return 0
}

install_docker() {
    case "${OS}" in
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
            print_error "Unsupported OS: ${OS}"
            print_info "Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac

    return 0
}

prompt_docker_install() {
    local reply=""

    if [[ "${ASSUME_YES}" == "true" ]]; then
        print_info "Non-interactive approval enabled. Installing Docker automatically..."
        install_docker
    elif [[ -t 0 ]]; then
        printf '\n'
        read -r -p "$(printf '%b' "${YELLOW}Would you like to install Docker now? [y/N]:${NC} ")" reply
        if [[ "${reply}" =~ ^[Yy]$ ]]; then
            install_docker
        else
            die "Docker is required. Exiting."
        fi
    else
        print_info "Running in non-interactive mode. Installing Docker automatically..."
        install_docker
    fi

    return 0
}

create_update_script() {
    print_info "Writing update script to ${UPDATE_SCRIPT}..."
    mkdir -p "$(dirname "${UPDATE_SCRIPT}")"

    cat > "${UPDATE_SCRIPT}" <<UPDATESCRIPT
#!/usr/bin/env bash
set -Eeuo pipefail

readonly LOG_FILE="/var/log/cyberalarm-update.log"
readonly INSTALL_DIR="${INSTALL_DIR}"
readonly COMPOSE_FILE="${COMPOSE_FILE}"

log() {
    local message="\$1"

    printf '%s %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\${message}" >> "\$LOG_FILE"
    return 0
}

: > "\$LOG_FILE"
cd "\$INSTALL_DIR"
log "Starting update..."

docker compose -f "\$COMPOSE_FILE" pull 2>&1 | while IFS= read -r line; do log "\$line"; done
docker compose -f "\$COMPOSE_FILE" up -d 2>&1 | while IFS= read -r line; do log "\$line"; done

log "Update complete."
UPDATESCRIPT

    bash -n "${UPDATE_SCRIPT}"
    chmod 750 "${UPDATE_SCRIPT}"
    print_success "Update script written to ${UPDATE_SCRIPT}"
    return 0
}

ensure_cron() {
    print_info "Checking for cron daemon..."
    if command -v crontab >/dev/null 2>&1 && { systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond 2>/dev/null; }; then
        print_success "Cron is already installed and running"
        return 0
    fi

    print_warning "Cron not found or not running. Installing..."
    case "${OS}" in
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
            print_warning "Cannot auto-install cron on ${OS}. Please install manually."
            return 1
            ;;
    esac

    print_success "Cron installed and started"
    return 0
}

check_port_514() {
    local port_in_use=false

    if command -v ss >/dev/null 2>&1; then
        ss -lntu 2>/dev/null | grep -q ':514 ' && port_in_use=true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntu 2>/dev/null | grep -q ':514 ' && port_in_use=true
    fi

    if [[ "${port_in_use}" == true ]]; then
        printf '\n'
        print_separator
        print_error "Port 514 is already in use by another process."
        print_error ""
        print_error "CyberAlarm PCA requires TCP and UDP port 514 to be free"
        print_error "for syslog ingestion. Please stop the conflicting service"
        print_error "and re-run this installer."
        print_error ""
        print_error "To identify what is using port 514, run:"
        print_error "  sudo ss -lntup | grep ':514'"
        print_error "  sudo lsof -i :514"
        print_separator
        printf '\n'
        exit 1
    fi

    return 0
}

create_directories() {
    print_info "Creating directory structure at ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}/scripts" "${DATA_DIR}"
    chown 1654:1654 "${DATA_DIR}"
    chmod 755 "${DATA_DIR}" "${INSTALL_DIR}"
    print_success "Directories created (data dir: ${DATA_DIR}, owner: 1654:1654)"
    return 0
}

download_verified_file() {
    local url="$1"
    local dest="$2"
    local expected_hash="$3"
    local name="$4"
    local tmp_file="${dest}.tmp"
    local actual_hash=""

    print_info "Downloading ${name}..."
    if ! curl -fsSL "${url}" -o "${tmp_file}"; then
        rm -f "${tmp_file}"
        die "Failed to download ${name} from ${url}"
    fi

    print_info "Verifying ${name} integrity..."
    actual_hash="$(sha256sum "${tmp_file}" | cut -d ' ' -f1)"
    if [[ "${actual_hash}" != "${expected_hash}" ]]; then
        print_separator
        print_error "${name} integrity check FAILED."
        print_error "The downloaded file does not match the expected hash."
        print_error ""
        print_error "Expected: ${expected_hash}"
        print_error "Got:      ${actual_hash}"
        print_error ""
        print_error "This may indicate the file has been tampered with or"
        print_error "that this installer is out of date. Please download a"
        print_error "fresh install command from the CyberAlarm portal."
        print_separator
        rm -f "${tmp_file}"
        exit 1
    fi

    mv "${tmp_file}" "${dest}"
    print_success "${name} downloaded and verified"
    return 0
}

download_compose_file() {
    download_verified_file \
        "${COMPOSE_URL}" \
        "${COMPOSE_FILE}" \
        "${COMPOSE_SHA256}" \
        "Docker Compose configuration"
    chmod 644 "${COMPOSE_FILE}"
    return 0
}

create_env_file() {
    local token="$1"

    print_info "Creating environment configuration..."
    cat > "${ENV_FILE}" <<ENV_EOF
# CyberAlarm PCA Configuration
# Generated on $(date)

# Required: Registration Token
REGISTRATION_TOKEN=${token}

# Optional: Override defaults if needed
# STATUS_ENDPOINT=https://api-ci-cyberalarm.waterstons.win/api/v1/SyslogRelayStatus
# LOG_LEVEL=Information
# MaximumTcpClients=50
ENV_EOF
    chmod 600 "${ENV_FILE}"
    print_success "Environment file created and secured"
    return 0
}

install_cron_job() {
    print_info "Installing hourly auto-update cron job..."
    INSTALLED_CRON_MINUTE=$((RANDOM % 60))

    {
        crontab -l 2>/dev/null | grep -F -v "${UPDATE_SCRIPT}" || true
        printf '%s\n' "${INSTALLED_CRON_MINUTE} * * * * ${UPDATE_SCRIPT} >> /var/log/cyberalarm-update.log 2>&1"
    } | crontab -

    print_success "Cron job installed - will run at minute ${INSTALLED_CRON_MINUTE} past every hour"
    return 0
}

verify_container_health() {
    local max_wait="$1"
    local interval="$2"
    local elapsed=0
    local health_status=""

    print_info "Waiting for container healthcheck to report healthy (up to ${max_wait}s)..."

    while [[ "${elapsed}" -lt "${max_wait}" ]]; do
        health_status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' syslog-relay 2>/dev/null || true)"

        case "${health_status}" in
            healthy)
                print_success "Container healthcheck is healthy."
                return 0
                ;;
            unhealthy)
                print_error "Container healthcheck reported unhealthy."
                return 1
                ;;
            none|"")
                print_warning "Container healthcheck is not available; falling back to registration file check."
                return 2
                ;;
            *)
                print_warning "Unexpected container health status '${health_status}'; continuing to wait."
                ;;
        esac

        sleep "${interval}"
        elapsed=$((elapsed + interval))
        printf '%b' "${BLUE}[INFO]${NC} Waiting for healthy container... (${elapsed}s / ${max_wait}s)\r"
    done

    printf '\n'
    print_error "Timed out waiting for container healthcheck to become healthy."
    return 1
}

verify_image_signature() {
    local all_verified=true
    local compose_image=""
    local -a compose_images=()

    print_info "Checking image signature verification capability..."
    if ! command -v cosign >/dev/null 2>&1; then
        printf '\n'
        print_separator
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
        print_separator
        printf '\n'
        return 0
    fi

    print_info "Verifying container image signature with Cosign..."
    mapfile -t compose_images < <(docker compose -f "${COMPOSE_FILE}" config --images 2>/dev/null)
    if [[ "${#compose_images[@]}" -eq 0 ]]; then
        die "Could not extract image references from ${COMPOSE_FILE}. Aborting."
    fi

    for compose_image in "${compose_images[@]}"; do
        print_info "Verifying: ${compose_image}"
        if cosign verify \
            --certificate-identity-regexp="https://github.com/waterstonsltd/CyberAlarmSecureSensor/.*" \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
            "${compose_image}" >/dev/null 2>&1; then
            print_success "Signature verified - ${compose_image} is authentic and untampered"
        else
            print_error "Signature verification FAILED for ${compose_image}"
            all_verified=false
        fi
    done

    if [[ "${all_verified}" == false ]]; then
        printf '\n'
        print_separator
        print_error "Image signature verification FAILED"
        print_error ""
        print_error "One or more container images may have been tampered with"
        print_error "or are not from the official Waterstons repository."
        print_error ""
        print_error "For security compliance, we cannot proceed with installation."
        print_separator
        printf '\n'
        exit 1
    fi

    return 0
}

deploy_service() {
    print_info "Deploying CyberAlarm PCA service..."

    print_info "Pulling Docker image (this may take a moment)..."
    if ! docker compose -f "${COMPOSE_FILE}" pull; then
        die "Failed to pull Docker image"
    fi
    print_success "Image pulled successfully"

    print_info "Starting service..."
    if ! docker compose -f "${COMPOSE_FILE}" up -d; then
        die "Failed to start service"
    fi
    print_success "Service started"
    return 0
}

verify_service() {
    local key_file="${DATA_DIR}/key.der"
    local max_wait=60
    local elapsed=0
    local interval=3
    local health_result=0

    if verify_container_health "${max_wait}" "${interval}"; then
        health_result=0
    else
        health_result=$?
        if [[ "${health_result}" -eq 1 ]]; then
            print_info "Container logs (last 50 lines):"
            printf '\n'
            docker compose -f "${COMPOSE_FILE}" logs --tail=50 syslog-relay
            printf '\n'
            exit 1
        fi
    fi

    print_info "Waiting for service registration file (up to ${max_wait}s)..."
    while [[ "${elapsed}" -lt "${max_wait}" ]]; do
        if [[ -f "${key_file}" ]]; then
            printf '\n'
            printf '%b\n' "${GREEN}========================================================${NC}"
            print_success "Service registered and running correctly!"
            printf '%b\n' "${GREEN}========================================================${NC}"
            printf '\n'
            return 0
        fi

        sleep "${interval}"
        elapsed=$((elapsed + interval))
        printf '%b' "${BLUE}[INFO]${NC} Still waiting for registration... (${elapsed}s / ${max_wait}s)\r"
    done

    printf '\n'
    printf '%b\n' "${RED}========================================================${NC}"
    print_error "Registration failed - registration key was not created after ${max_wait}s."
    print_error "The service may not have registered successfully with"
    print_error "the CyberAlarm platform. Check your registration token"
    print_error "and network connectivity, then review the logs below."
    printf '%b\n' "${RED}========================================================${NC}"
    printf '\n'
    print_info "Container logs (last 50 lines):"
    printf '\n'
    docker compose -f "${COMPOSE_FILE}" logs --tail=50 syslog-relay
    printf '\n'
    print_info "To continue monitoring:"
    print_info "  docker compose -f ${COMPOSE_FILE} logs -f syslog-relay"
    printf '\n'
    exit 1
}

display_summary() {
    local has_autoupdate="$1"
    local cron_minute="$2"

    printf '\n'
    printf '%b\n' "${GREEN}========================================================${NC}"
    printf '%b\n' "${GREEN}Installation Completed Successfully!${NC}"
    printf '%b\n' "${GREEN}========================================================${NC}"
    printf '\n'
    printf '%b\n' "${BLUE}Installation Directory:${NC} ${INSTALL_DIR}"
    printf '%b\n' "${BLUE}Data Directory:${NC}         ${DATA_DIR}"
    printf '%b\n' "${BLUE}Configuration File:${NC}     ${ENV_FILE}"
    printf '%b\n' "${BLUE}Container Name:${NC}         syslog-relay"
    printf '\n'

    if [[ "${has_autoupdate}" == "true" ]]; then
        printf '%b\n' "${BLUE}Auto-Updates:${NC}  Enabled via cron (runs at minute ${cron_minute} of every hour)"
        printf '%b\n' "${BLUE}Update Script:${NC} ${UPDATE_SCRIPT}"
        printf '%b\n' "${BLUE}Update Log:${NC}    /var/log/cyberalarm-update.log"
        printf '\n'
    fi

    printf '%b\n' "${YELLOW}Useful Commands:${NC}"
    printf '%s\n' "  Check status:    docker compose -f ${COMPOSE_FILE} ps"
    printf '%s\n' "  View logs:       docker compose -f ${COMPOSE_FILE} logs -f syslog-relay"
    printf '%s\n' "  Restart service: docker compose -f ${COMPOSE_FILE} restart syslog-relay"
    printf '%s\n' "  Stop service:    docker compose -f ${COMPOSE_FILE} down"
    if [[ "${has_autoupdate}" == "true" ]]; then
        printf '%s\n' "  Manual update:   sudo ${UPDATE_SCRIPT}"
    fi
    printf '\n'
    printf '%b\n' "${YELLOW}Port Configuration:${NC}"
    printf '%s\n' "  TCP/UDP 514: Syslog ingestion"
    printf '\n'
    printf '%b\n' "${GREEN}Your PCA is now ready to receive syslog messages!${NC}"
    printf '\n'
    return 0
}

main() {
    local registration_token=""
    local auto_update_flag=""
    local enable_autoupdate="false"

    print_banner

    parse_arguments "$@"
    registration_token="${PARSED_REGISTRATION_TOKEN}"
    auto_update_flag="${PARSED_AUTO_UPDATE_FLAG}"

    validate_registration_token "${registration_token}"

    if [[ "${auto_update_flag}" == "auto-update" || "${auto_update_flag}" == "update" || "${auto_update_flag}" == "yes" ]]; then
        enable_autoupdate="true"
        print_info "Auto-updates will be enabled via cron job"
    else
        print_info "Auto-updates disabled (pass 'auto-update' as 2nd argument to enable)"
    fi

    check_root
    check_required_commands
    detect_os
    check_port_514

    if ! check_docker; then
        prompt_docker_install
    fi

    if ! check_docker_compose; then
        die "Docker Compose plugin is required but not installed"
    fi

    create_directories
    download_compose_file
    create_env_file "${registration_token}"

    if [[ "${enable_autoupdate}" == "true" ]]; then
        ensure_cron
        create_update_script
        install_cron_job
    fi

    verify_image_signature
    deploy_service
    verify_service
    display_summary "${enable_autoupdate}" "${INSTALLED_CRON_MINUTE}"
    return 0
}

main "$@"
