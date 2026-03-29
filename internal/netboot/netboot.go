// Package netboot manages the deploy boot system for agent VMs.
// Each image build produces its own kernel and initrd in the image
// version's netboot/ directory. For Debian/Ubuntu, deploy tools and a
// premount script are baked into the initrd via initramfs-tools hooks.
// For Alpine, the apkovl mechanism handles deployment.
package netboot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

const (
	// Alpine version used for the deploy boot system.
	deployAlpineVersion = "3.23"
)

// DeployBootInfo contains the information needed to generate an iPXE boot script.
type DeployBootInfo struct {
	AgentID      string
	ImageID      string
	ImageVersion int
	OSType       agent.OSType
	OSVersion    string
}

// Manager handles the deploy boot system and iPXE script generation.
type Manager struct {
	DataDir  string // e.g., /var/lib/firewall4ai
	ServerIP string // e.g., 10.255.255.1

	mu sync.RWMutex
}

// NewManager creates a new netboot manager.
func NewManager(dataDir, serverIP string) *Manager {
	return &Manager{
		DataDir:  dataDir,
		ServerIP: serverIP,
	}
}

// DeployDir returns the path where deploy boot files are stored.
func (m *Manager) DeployDir() string {
	return filepath.Join(m.DataDir, "netboot", "deploy")
}

// TFTPDir returns the path for TFTP-served files (iPXE bootloaders).
func (m *Manager) TFTPDir() string {
	return filepath.Join(m.DataDir, "netboot", "tftp")
}

// EnsureTFTPDir creates the TFTP directory structure.
func (m *Manager) EnsureTFTPDir() error {
	return os.MkdirAll(m.TFTPDir(), 0o755)
}

// HasImageBootFiles checks if the image version has netboot files ready.
func (m *Manager) HasImageBootFiles(imageID string, version int) bool {
	netbootDir := filepath.Join(m.DataDir, "images", imageID, fmt.Sprintf("%d", version), "netboot")
	return fileExists(filepath.Join(netbootDir, "vmlinuz")) &&
		fileExists(filepath.Join(netbootDir, "initrd.img"))
}

// GenerateDeployIPXEScript generates an iPXE boot script that boots the
// image's own kernel and initrd. For Debian/Ubuntu, the initrd has deploy
// tools and a premount script baked in. For Alpine, the apkovl mechanism
// is used.
func (m *Manager) GenerateDeployIPXEScript(info DeployBootInfo) string {
	var b strings.Builder

	baseURL := fmt.Sprintf("http://%s/images/%s/%d/netboot",
		m.ServerIP, info.ImageID, info.ImageVersion)
	kernelURL := baseURL + "/vmlinuz"
	initrdURL := baseURL + "/initrd.img"

	b.WriteString("#!ipxe\n\n")

	switch info.OSType {
	case agent.OSDebian, agent.OSUbuntu:
		// Boot image's kernel+initrd. The initrd has deploy tools and a premount
		// script baked in via initramfs-tools hooks. The premount script detects
		// fw4ai_agent/fw4ai_server kernel params and handles partitioning,
		// formatting, and rootfs extraction before root mount.
		b.WriteString(fmt.Sprintf("kernel %s root=/dev/sda1 net.ifnames=0 biosdevname=0 ip=dhcp fw4ai_agent=%s fw4ai_server=%s\n",
			kernelURL, info.AgentID, m.ServerIP))
		b.WriteString(fmt.Sprintf("initrd %s\n", initrdURL))

	case agent.OSAlpine:
		// Boot image's kernel+initrd with Alpine's apkovl mechanism.
		apkovlURL := fmt.Sprintf("http://%s/boot/deploy/apkovl.tar.gz", m.ServerIP)
		b.WriteString(fmt.Sprintf("kernel %s alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v%s/main/ ip=dhcp apkovl=%s fw4ai_agent=%s fw4ai_server=%s\n",
			kernelURL, info.OSVersion, apkovlURL, info.AgentID, m.ServerIP))
		b.WriteString(fmt.Sprintf("initrd %s\n", initrdURL))
	}

	b.WriteString("boot\n")
	return b.String()
}

// GenerateDeployApkovl creates the apkovl tarball that runs the image
// deployment script on the Alpine boot system.
func (m *Manager) GenerateDeployApkovl() []byte {
	script := `#!/bin/sh
# Firewall4AI: Disk image deployment script
# Runs on Alpine netboot system to deploy a pre-built rootfs to disk.
set -e

echo "=== Firewall4AI Image Deploy starting ==="

# Extract parameters from kernel cmdline.
AGENT_ID=""
SERVER=""
for p in $(cat /proc/cmdline); do
    case "$p" in
        fw4ai_agent=*) AGENT_ID="${p#fw4ai_agent=}" ;;
        fw4ai_server=*) SERVER="${p#fw4ai_server=}" ;;
    esac
done

if [ -z "$AGENT_ID" ] || [ -z "$SERVER" ]; then
    echo "ERROR: fw4ai_agent and fw4ai_server parameters required"
    exit 1
fi

API="http://${SERVER}"

# Report deploying status.
wget -qO /dev/null "${API}/boot/status/${AGENT_ID}?status=deploying" || true

# Get deployment info from the firewall.
echo "-> Fetching deployment info..."
wget -qO /tmp/deploy-info.txt "${API}/boot/deploy-info/${AGENT_ID}"

# Parse simple key=value format.
DISK=$(grep '^disk=' /tmp/deploy-info.txt | cut -d= -f2-)
IMAGE_URL=$(grep '^image_url=' /tmp/deploy-info.txt | cut -d= -f2-)
HOSTNAME=$(grep '^hostname=' /tmp/deploy-info.txt | cut -d= -f2-)

if [ -z "$DISK" ] || [ -z "$IMAGE_URL" ]; then
    echo "ERROR: Missing disk or image_url in deploy info"
    wget -qO /dev/null "${API}/boot/status/${AGENT_ID}?status=error&msg=missing+deploy+info" || true
    exit 1
fi

echo "-> Disk: $DISK"
echo "-> Image: $IMAGE_URL"
echo "-> Hostname: $HOSTNAME"

# Install deployment tools.
echo "-> Installing deployment tools..."
apk add e2fsprogs syslinux kexec-tools 2>/dev/null || true

# Partition disk: single partition, entire disk, bootable.
echo "-> Partitioning ${DISK}..."
echo -e "o\nn\np\n1\n\n\na\n1\nw" | fdisk ${DISK} || true
sleep 1

# Detect partition name (sda1 vs vda1 vs nvme0n1p1).
PART="${DISK}1"
if echo "$DISK" | grep -q "nvme"; then
    PART="${DISK}p1"
fi

# Format partition.
echo "-> Formatting ${PART}..."
mke2fs ${PART}

# Mount and extract rootfs.
echo "-> Extracting rootfs image..."
mkdir -p /mnt/target
mount ${PART} /mnt/target
wget -qO - "${IMAGE_URL}" | tar xzf - -C /mnt/target

# Set hostname.
if [ -n "$HOSTNAME" ]; then
    echo "$HOSTNAME" > /mnt/target/etc/hostname
fi

# Setup SSH authorized keys (if provided).
SSH_KEYS=$(grep '^ssh_key=' /tmp/deploy-info.txt | cut -d= -f2-)
if [ -n "$SSH_KEYS" ]; then
    echo "-> Configuring SSH access..."
    mkdir -p /mnt/target/root/.ssh
    chmod 700 /mnt/target/root/.ssh
    grep '^ssh_key=' /tmp/deploy-info.txt | cut -d= -f2- > /mnt/target/root/.ssh/authorized_keys
    chmod 600 /mnt/target/root/.ssh/authorized_keys
    # Enable sshd on boot (Alpine).
    chroot /mnt/target rc-update add sshd default 2>/dev/null || true
    # Configure sshd to allow root login with keys only.
    if [ -f /mnt/target/etc/ssh/sshd_config ]; then
        sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' /mnt/target/etc/ssh/sshd_config
    fi
fi

# Download CA certificate.
echo "-> Installing CA certificate..."
mkdir -p /mnt/target/usr/local/share/ca-certificates
wget -qO /mnt/target/usr/local/share/ca-certificates/firewall4ai-ca.crt "${API}/ca.crt" || true
if [ -f /mnt/target/usr/sbin/update-ca-certificates ]; then
    chroot /mnt/target update-ca-certificates 2>/dev/null || true
fi

# Install bootloader.
echo "-> Installing bootloader..."
MBR_BIN=""
EXTLINUX_BIN=""

for p in /mnt/target/usr/share/syslinux/mbr.bin /usr/share/syslinux/mbr.bin; do
    if [ -f "$p" ]; then MBR_BIN="$p"; break; fi
done
for p in /mnt/target/sbin/extlinux /mnt/target/usr/bin/extlinux /usr/bin/extlinux /sbin/extlinux; do
    if [ -x "$p" ]; then EXTLINUX_BIN="$p"; break; fi
done

if [ -n "$MBR_BIN" ]; then
    dd if="$MBR_BIN" of=${DISK} bs=440 count=1 2>/dev/null
fi
if [ -n "$EXTLINUX_BIN" ]; then
    mkdir -p /mnt/target/boot
    "$EXTLINUX_BIN" --install /mnt/target/boot
fi

# Report success.
echo "-> Deployment complete!"
wget -qO /dev/null "${API}/boot/status/${AGENT_ID}?status=installed" || true

# Boot into the installed system via kexec.
sync

KERNEL=$(ls /mnt/target/boot/vmlinuz-* 2>/dev/null | head -n1)
INITRD=$(ls /mnt/target/boot/initramfs-* 2>/dev/null | head -n1)
APPEND="root=${PART} modules=ext2 net.ifnames=0 biosdevname=0"

if [ -n "$KERNEL" ] && [ -n "$INITRD" ]; then
    echo "-> Loading installed kernel via kexec..."
    kexec -l "$KERNEL" --initrd="$INITRD" --command-line="$APPEND"
    umount /mnt/target
    echo "-> kexec into installed system..."
    kexec -e
fi

# Fallback: traditional reboot (if kexec fails).
umount /mnt/target 2>/dev/null || true
echo "-> Rebooting..."
reboot -f
`

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{
		Name:    "etc/local.d/deploy.start",
		Mode:    0755,
		Size:    int64(len(script)),
		ModTime: time.Now(),
	}
	tw.WriteHeader(header)
	tw.Write([]byte(script))

	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
