#!/bin/bash

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

USERNAME="lalatendu"

# Create the user if it doesn't exist
if id "$USERNAME" &>/dev/null; then
    echo "User $USERNAME already exists."
else
    echo "Creating user: $USERNAME"
    adduser --gecos "" "$USERNAME"
    usermod -aG sudo "$USERNAME"
    echo "User $USERNAME added to sudo group."
fi

# Add to visudo safely
SUDOERS_FILE="/etc/sudoers.d/$USERNAME"
echo "Configuring sudoers file: $SUDOERS_FILE"

cat <<EOF > "$SUDOERS_FILE"
$USERNAME ALL=(ALL) NOPASSWD: ALL
$USERNAME       ALL=(ALL:ALL) ALL
EOF

chmod 0440 "$SUDOERS_FILE"

# Update SSH configuration
SSHD_CONFIG="/etc/ssh/sshd_config"

if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
    # Append lalatendu if AllowUsers already exists
    sed -i "/^AllowUsers/ s/$/ $USERNAME/" "$SSHD_CONFIG"
else
    echo "AllowUsers $USERNAME" >> "$SSHD_CONFIG"
fi

# Disable password authentication
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"

# Restart SSH service
echo "Restarting SSH service..."
systemctl restart ssh

echo "User $USERNAME has been created and configured."
