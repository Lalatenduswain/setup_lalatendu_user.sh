#!/bin/bash
#
# Script: create_user_lalatendu.sh
# Purpose: Create user 'lalatendu' with sudo privileges, passwordless sudo, and SSH/SFTP access
# Usage: sudo ./create_user_lalatendu.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

USERNAME="lalatendu"

# SSH Public Key
SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8IdDscm8+MRACm3dpE6796u2Y+vxi9bajA/y1YKE+l4ylGNzk43YGBpSXEjMlGe5t6S+PYg6xi0Wr0wO1mROwF1RSkEYee0Pszue+kDm1yuDEk3EjasdCgrxwnz5J1T6EN2ngBjcK7ZPDvhni1fcfG1VJNblzpQlzC8vkvU4aRABCkqV4jgio/+IfXO9Qqo/0NP3IEBUHFuTbSPpMwMWDoxwIQN/K6e7nCjuQ0t+YAuQLIRRYzBDS+j79/IL2TEbD0kbopnZqaiZ94HU5KlZ1G1EmZurhQaSP6UIF+YXMqwkLFrNUuisfWXZduo3XRS4fj5xQpZNfZwNzjf6IAaQwLcRfpMpVkoYUX00hklLf0OInSDjBcGoDqBFg7NyG2Kty9Ihm9Fl+NWpbMDb0mTZ9/l1dUOy8WMzEhPlFZuSGBfLc/9L+3FQDv48HuvYyajOtmgPdytHmVc+Lbj62kX30qPq297g628vBE0PrWj/2QJGPCNeoXGfbnzmGAW2a3yU="

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Detect OS type
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_ID_LIKE="$ID_LIKE"
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"

        # Determine OS family
        if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID_LIKE" == *"debian"* ]]; then
            OS_FAMILY="debian"
            SUDO_GROUP="sudo"
        elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "centos" || "$OS_ID" == "rhel" || "$OS_ID" == "rocky" || "$OS_ID" == "almalinux" || "$OS_ID" == "amzn" || "$OS_ID_LIKE" == *"rhel"* || "$OS_ID_LIKE" == *"fedora"* ]]; then
            OS_FAMILY="rhel"
            SUDO_GROUP="wheel"
        else
            print_error "Unsupported OS: $OS_NAME"
            print_error "Supported: Ubuntu, Debian, Fedora, CentOS, RHEL, Rocky Linux, AlmaLinux, Amazon Linux"
            exit 1
        fi

        print_info "Detected OS: $OS_NAME $OS_VERSION (Family: $OS_FAMILY)"
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
}

# Create user account
create_user() {
    if id "$USERNAME" &>/dev/null; then
        print_warn "User '$USERNAME' already exists. Skipping user creation."
    else
        print_info "Creating user '$USERNAME'..."

        if [[ "$OS_FAMILY" == "debian" ]]; then
            useradd -m -s /bin/bash "$USERNAME"
        else
            useradd -m -s /bin/bash "$USERNAME"
        fi

        print_info "User '$USERNAME' created successfully."

        # Lock password - user will authenticate via SSH key only
        # To set a password later, run: sudo passwd lalatendu
        passwd -l "$USERNAME" &>/dev/null
        print_info "Password locked (SSH key authentication only)."
        print_info "To set a password later, run: sudo passwd $USERNAME"
    fi
}

# Setup SSH public key
setup_ssh_key() {
    USER_HOME=$(eval echo ~$USERNAME)
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    print_info "Setting up SSH public key for '$USERNAME'..."

    # Create .ssh directory if it doesn't exist
    if [[ ! -d "$SSH_DIR" ]]; then
        mkdir -p "$SSH_DIR"
        print_info "Created $SSH_DIR directory."
    fi

    # Check if key already exists
    if [[ -f "$AUTH_KEYS" ]] && grep -q "$SSH_PUBLIC_KEY" "$AUTH_KEYS"; then
        print_warn "SSH public key already exists in authorized_keys."
    else
        # Add public key to authorized_keys
        echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
        print_info "SSH public key added to authorized_keys."
    fi

    # Set correct ownership and permissions
    chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_KEYS"

    print_info "SSH key setup completed. Permissions set correctly."
}

# Add user to sudo group
add_to_sudo_group() {
    print_info "Adding '$USERNAME' to '$SUDO_GROUP' group..."

    if groups "$USERNAME" | grep -q "\b$SUDO_GROUP\b"; then
        print_warn "User '$USERNAME' is already in '$SUDO_GROUP' group."
    else
        usermod -aG "$SUDO_GROUP" "$USERNAME"
        print_info "User '$USERNAME' added to '$SUDO_GROUP' group."
    fi
}

# Configure passwordless sudo
configure_passwordless_sudo() {
    SUDOERS_FILE="/etc/sudoers.d/$USERNAME"

    print_info "Configuring passwordless sudo for '$USERNAME'..."

    # Create sudoers file
    echo "$USERNAME ALL=(ALL) NOPASSWD: ALL" > "$SUDOERS_FILE"

    # Set correct permissions
    chmod 440 "$SUDOERS_FILE"

    # Validate sudoers file
    if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        print_info "Passwordless sudo configured successfully."
    else
        print_error "Invalid sudoers configuration. Removing file."
        rm -f "$SUDOERS_FILE"
        exit 1
    fi
}

# Configure SSH and SFTP access
configure_ssh_sftp() {
    SSHD_CONFIG="/etc/ssh/sshd_config"
    BACKUP_FILE="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

    print_info "Configuring SSH/SFTP access for '$USERNAME'..."

    # Create backup
    cp "$SSHD_CONFIG" "$BACKUP_FILE"
    print_info "Backup created: $BACKUP_FILE"

    # Check if AllowUsers directive exists
    if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
        # Check if user is already in AllowUsers
        if grep "^AllowUsers" "$SSHD_CONFIG" | grep -q "\b$USERNAME\b"; then
            print_warn "User '$USERNAME' already in AllowUsers."
        else
            # Add user to existing AllowUsers line
            sed -i "s/^AllowUsers.*/& $USERNAME/" "$SSHD_CONFIG"
            print_info "Added '$USERNAME' to existing AllowUsers directive."
        fi
    else
        # Add AllowUsers directive with default users + new user
        echo "" >> "$SSHD_CONFIG"
        echo "# Added by create_user_lalatendu.sh script" >> "$SSHD_CONFIG"
        echo "AllowUsers ramesh $USERNAME" >> "$SSHD_CONFIG"
        print_info "Added AllowUsers directive with '$USERNAME'."
    fi

    # Ensure SFTP subsystem is configured
    if ! grep -q "^Subsystem.*sftp" "$SSHD_CONFIG"; then
        if [[ "$OS_FAMILY" == "debian" ]]; then
            echo "Subsystem sftp /usr/lib/openssh/sftp-server" >> "$SSHD_CONFIG"
        else
            echo "Subsystem sftp /usr/libexec/openssh/sftp-server" >> "$SSHD_CONFIG"
        fi
        print_info "Added SFTP subsystem configuration."
    else
        print_info "SFTP subsystem already configured."
    fi

    # Validate sshd config
    if sshd -t &>/dev/null; then
        print_info "SSH configuration is valid."

        # Restart sshd service
        if [[ "$OS_FAMILY" == "debian" ]]; then
            systemctl restart sshd || systemctl restart ssh
        else
            systemctl restart sshd
        fi
        print_info "SSH service restarted."
    else
        print_error "Invalid SSH configuration. Restoring backup."
        cp "$BACKUP_FILE" "$SSHD_CONFIG"
        exit 1
    fi
}

# Main execution
main() {
    echo "========================================"
    echo "  User Setup Script for '$USERNAME'"
    echo "========================================"
    echo ""

    check_root
    detect_os
    create_user
    setup_ssh_key
    add_to_sudo_group
    configure_passwordless_sudo
    configure_ssh_sftp

    echo ""
    echo "========================================"
    print_info "Setup completed successfully!"
    echo "========================================"
    echo ""
    echo "Summary:"
    echo "  - User: $USERNAME"
    echo "  - SSH Key: Added to ~/.ssh/authorized_keys"
    echo "  - Sudo Group: $SUDO_GROUP"
    echo "  - Passwordless Sudo: Enabled"
    echo "  - SSH/SFTP Access: Enabled"
    echo ""
    echo "You can now login as '$USERNAME' via SSH using the configured key."
    echo ""
}

# Run main function
main "$@"
