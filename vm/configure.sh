#!/bin/sh
# Configure script for alpine-make-vm-image
# This runs inside the VM image chroot during build.
set -eu

# ============================================================
# Basic system setup
# ============================================================

# Set timezone
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Set hostname
echo "squid4claw" > /etc/hostname
echo "127.0.0.1 squid4claw squid4claw.localdomain" >> /etc/hosts

# Set root password (change on first login)
echo "root:squid4claw" | chpasswd

# ============================================================
# Copy the squid4claw binary
# ============================================================
cp /mnt/squid4claw /usr/bin/squid4claw
chmod 755 /usr/bin/squid4claw

# ============================================================
# Enable services
# ============================================================
rc-update add networking boot
rc-update add dnsmasq default
rc-update add local default
rc-update add squid4claw default
rc-update add acpid default

# ============================================================
# Enable IP forwarding at boot
# ============================================================
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# ============================================================
# Configure DNS resolver for the host itself
# ============================================================
cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

# ============================================================
# Create data directory
# ============================================================
mkdir -p /var/lib/squid4claw

# ============================================================
# Serial console for headless access
# ============================================================
sed -i 's/^#ttyS0/ttyS0/' /etc/inittab 2>/dev/null || true

echo "Squid4Claw VM configuration complete"
