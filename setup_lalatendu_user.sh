#!/bin/bash

set -euo pipefail

# ============================================================================
# User Setup Script
# Creates a user with sudo privileges and configures SSH access
# ============================================================================

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly DEFAULT_USERNAME="lalatendu"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly BACKUP_DIR="/root/setup_backups"
readonly LOG_FILE="/var/log/user_setup.log"

# SSH Public Key
readonly SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8IdDscm8+MRACm3dpE6796u2Y+vxi9bajA/y1YKE+l4ylGNzk43YGBpSXEjMlGe5t6S+PYg6xi0Wr0wO1mROwF1RSkEYee0Pszue+kDm1yuDEk3EjasdCgrxwnz5J1T6EN2ngBjcK7ZPDvhni1fcfG1VJNblzpQlzC8vkvU4aRABCkqV4jgio/+IfXO9Qqo/0NP3IEBUHFuTbSPpMwMWDoxwIQN/K6e7nCjuQ0t+YAuQLIRRYzBDS+j79/IL2TEbD0kbopnZqaiZ94HU5KlZ1G1EmZurhQaSP6UIF+YXMqwkLFrNUuisfWXZduo3XRS4fj5xQpZNfZwNzjf6IAaQwLcRfpMpVkoYUX00hklLf0OInSDjBcGoDqBFg7NyG2Kty9Ihm9Fl+NWpbMDb0mTZ9/l1dUOy8WMzEhPlFZuSGBfLc/9L+3FQDv48HuvYyajOtmgPdytHmVc+Lbj62kX30qPq297g628vBE0PrWj/2QJGPCNeoXGfbnzmGAW2a3yU="

# Script state
DRY_RUN=false
VERBOSE=false
USERNAME=""

# ============================================================================
# Utility Functions
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)  color="$GREEN"  ;;
        WARN)  color="$YELLOW" ;;
        ERROR) color="$RED"    ;;
        DEBUG) color="$BLUE"   ;;
        *)     color="$NC"     ;;
    esac

    echo -e "${color}[${level}]${NC} ${message}"

    # Log to file if we have write permission
    if [[ -w "$(dirname "$LOG_FILE")" ]] || [[ -w "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

info()  { log "INFO" "$@"; }
warn()  { log "WARN" "$@"; }
error() { log "ERROR" "$@"; }
debug() { [[ "$VERBOSE" == true ]] && log "DEBUG" "$@" || true; }

die() {
    error "$@"
    exit 1
}

run_cmd() {
    local cmd="$*"
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would execute: $cmd"
        return 0
    fi
    debug "Executing: $cmd"
    eval "$cmd"
}

backup_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        warn "File $file does not exist, skipping backup"
        return 0
    fi

    local backup_path="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would backup: $file -> $backup_path"
        return 0
    fi

    mkdir -p "$BACKUP_DIR"
    cp -p "$file" "$backup_path"
    info "Backed up: $file -> $backup_path"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [USERNAME]

Sets up a new user with sudo privileges and SSH access.

Options:
    -h, --help          Show this help message
    -d, --dry-run       Show what would be done without making changes
    -v, --verbose       Enable verbose output
    -n, --no-backup     Skip backing up configuration files

Arguments:
    USERNAME            Username to create (default: $DEFAULT_USERNAME)

Examples:
    $(basename "$0")                    # Create user '$DEFAULT_USERNAME'
    $(basename "$0") john               # Create user 'john'
    $(basename "$0") -d john            # Dry run for user 'john'
    $(basename "$0") -v --dry-run       # Verbose dry run

EOF
    exit 0
}

# ============================================================================
# Validation Functions
# ============================================================================

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root. Use: sudo $0"
    fi
    debug "Root check passed"
}

validate_username() {
    local name="$1"

    # Check if username is valid (alphanumeric, underscore, hyphen, starts with letter)
    if [[ ! "$name" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        die "Invalid username '$name'. Must start with a letter and contain only lowercase letters, numbers, underscores, or hyphens."
    fi

    # Check length
    if [[ ${#name} -gt 32 ]]; then
        die "Username '$name' is too long (max 32 characters)"
    fi

    debug "Username validation passed for: $name"
}

check_dependencies() {
    local deps=(adduser usermod chmod cat grep sed systemctl)
    local missing=()

    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing[*]}"
    fi

    debug "All dependencies are available"
}

# ============================================================================
# Main Functions
# ============================================================================

create_user() {
    if id "$USERNAME" &>/dev/null; then
        info "User '$USERNAME' already exists"
        return 0
    fi

    info "Creating user: $USERNAME"
    run_cmd "adduser --gecos '' --disabled-password '$USERNAME'"
    info "User '$USERNAME' created successfully"
}

configure_sudo() {
    local sudoers_file="/etc/sudoers.d/$USERNAME"
    local main_sudoers="/etc/sudoers"

    # Add user to sudo group
    if groups "$USERNAME" 2>/dev/null | grep -qw sudo; then
        info "User '$USERNAME' is already in sudo group"
    else
        info "Adding '$USERNAME' to sudo group"
        run_cmd "usermod -aG sudo '$USERNAME'"
    fi

    # Add user to main sudoers file under "User privilege specification"
    info "Configuring main sudoers file: $main_sudoers"

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would add '$USERNAME ALL=(ALL:ALL) ALL' to $main_sudoers"
    else
        # Backup main sudoers file
        backup_file "$main_sudoers"

        # Check if user entry already exists in main sudoers
        if grep -q "^${USERNAME}[[:space:]]*ALL=(ALL:ALL)[[:space:]]*ALL" "$main_sudoers"; then
            info "User '$USERNAME' already in main sudoers file"
        else
            # Add user after "User privilege specification" section (after root line)
            if grep -q "^root[[:space:]]*ALL=(ALL:ALL)[[:space:]]*ALL" "$main_sudoers"; then
                sed -i "/^root[[:space:]]*ALL=(ALL:ALL)[[:space:]]*ALL/a $USERNAME\tALL=(ALL:ALL) ALL" "$main_sudoers"
                info "Added '$USERNAME' to main sudoers file"
            else
                # Fallback: add before @includedir if root line not found
                sed -i "/@includedir/i $USERNAME\tALL=(ALL:ALL) ALL" "$main_sudoers"
                info "Added '$USERNAME' to main sudoers file (before @includedir)"
            fi

            # Validate main sudoers
            if visudo -c &>/dev/null; then
                info "Main sudoers file validated successfully"
            else
                error "Invalid sudoers syntax in main file"
                # Restore backup
                local latest_backup
                latest_backup=$(ls -t "${BACKUP_DIR}/sudoers."* 2>/dev/null | head -1)
                if [[ -n "$latest_backup" ]]; then
                    cp "$latest_backup" "$main_sudoers"
                    warn "Restored sudoers from backup: $latest_backup"
                fi
                die "Failed to configure main sudoers"
            fi
        fi
    fi

    # Create sudoers.d file for NOPASSWD
    info "Configuring sudoers.d: $sudoers_file"

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would create $sudoers_file with NOPASSWD rules"
    else
        cat <<EOF > "$sudoers_file"
# Sudoers configuration for $USERNAME
# Created by setup script on $(date)
$USERNAME ALL=(ALL) NOPASSWD: ALL
EOF
        chmod 0440 "$sudoers_file"

        # Validate sudoers.d file syntax
        if visudo -c -f "$sudoers_file" &>/dev/null; then
            info "Sudoers.d file validated successfully"
        else
            error "Invalid sudoers syntax, removing file"
            rm -f "$sudoers_file"
            die "Failed to configure sudoers.d"
        fi
    fi
}

configure_ssh() {
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        die "SSH config file not found: $SSHD_CONFIG"
    fi

    backup_file "$SSHD_CONFIG"

    info "Configuring SSH for user '$USERNAME'"

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would update SSH configuration"
        return 0
    fi

    # Handle AllowUsers directive
    if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
        # Check if user is already in AllowUsers
        if grep -q "^AllowUsers.*\b${USERNAME}\b" "$SSHD_CONFIG"; then
            info "User '$USERNAME' already in AllowUsers"
        else
            info "Appending '$USERNAME' to existing AllowUsers"
            sed -i "/^AllowUsers/ s/$/ $USERNAME/" "$SSHD_CONFIG"
        fi
    else
        info "Adding AllowUsers directive for '$USERNAME'"
        echo "AllowUsers $USERNAME" >> "$SSHD_CONFIG"
    fi

    # Disable password authentication
    if grep -q "^PasswordAuthentication no" "$SSHD_CONFIG"; then
        info "Password authentication already disabled"
    else
        info "Disabling password authentication"
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    fi

    # Validate SSH configuration
    if sshd -t &>/dev/null; then
        info "SSH configuration validated successfully"
    else
        warn "SSH configuration validation failed - check $SSHD_CONFIG"
    fi
}

setup_ssh_directory() {
    local ssh_dir="/home/$USERNAME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would create SSH directory and add public key"
        return 0
    fi

    info "Setting up SSH directory for '$USERNAME'"

    mkdir -p "$ssh_dir"
    touch "$auth_keys"

    # Add public key if not already present
    if grep -qF "$SSH_PUBLIC_KEY" "$auth_keys" 2>/dev/null; then
        info "SSH public key already exists in authorized_keys"
    else
        info "Adding SSH public key to authorized_keys"
        echo "$SSH_PUBLIC_KEY" >> "$auth_keys"
        info "SSH public key added successfully"
    fi

    chown -R "$USERNAME:$USERNAME" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_keys"

    info "SSH directory configured: $ssh_dir"
}

restart_ssh() {
    info "Restarting SSH service..."

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would restart SSH service"
        return 0
    fi

    if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
        info "SSH service restarted successfully"
    else
        warn "Failed to restart SSH service - manual restart may be required"
    fi
}

print_summary() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo 'your-server')

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Setup Complete${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  User:       ${BLUE}$USERNAME${NC}"
    echo -e "  Sudo:       ${GREEN}Enabled (NOPASSWD)${NC}"
    echo -e "  SSH:        ${GREEN}Configured${NC}"
    echo -e "  Public Key: ${GREEN}Added to authorized_keys${NC}"
    echo ""
    echo -e "  ${YELLOW}Test your connection:${NC}"
    echo "  ssh $USERNAME@$server_ip"
    echo ""

    if [[ -d "$BACKUP_DIR" ]]; then
        echo -e "  ${BLUE}Backups saved to:${NC} $BACKUP_DIR"
        echo ""
    fi
}

# ============================================================================
# Main Entry Point
# ============================================================================

main() {
    local skip_backup=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -n|--no-backup)
                skip_backup=true
                shift
                ;;
            -*)
                die "Unknown option: $1 (use --help for usage)"
                ;;
            *)
                USERNAME="$1"
                shift
                ;;
        esac
    done

    # Set default username if not provided
    USERNAME="${USERNAME:-$DEFAULT_USERNAME}"

    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  User Setup Script${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""

    if [[ "$DRY_RUN" == true ]]; then
        warn "Running in DRY-RUN mode - no changes will be made"
        echo ""
    fi

    # Pre-flight checks
    check_root
    check_dependencies
    validate_username "$USERNAME"

    # Execute setup steps
    create_user
    configure_sudo
    configure_ssh
    setup_ssh_directory
    restart_ssh

    # Print summary
    if [[ "$DRY_RUN" != true ]]; then
        print_summary
    else
        echo ""
        info "Dry run complete - no changes were made"
    fi
}

main "$@"
