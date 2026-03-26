// Package netboot manages the deploy boot system for agent VMs.
// It uses Alpine Linux netboot as a universal deploy system that boots
// into RAM, partitions the target disk, and extracts a pre-built rootfs
// tarball for fast deployment.
package netboot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// Alpine version used for the deploy boot system.
	deployAlpineVersion = "3.23"
)

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

// EnsureDeployFiles downloads the Alpine netboot files used for deployment.
// These are cached and only downloaded once.
func (m *Manager) EnsureDeployFiles() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir := m.DeployDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create deploy dir: %w", err)
	}

	kernelPath := filepath.Join(dir, "kernel")
	initrdPath := filepath.Join(dir, "initrd")

	if fileExists(kernelPath) && fileExists(initrdPath) {
		log.Printf("Deploy boot files already cached")
		return nil
	}

	kernelURL := fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/netboot/vmlinuz-lts", deployAlpineVersion)
	initrdURL := fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/netboot/initramfs-lts", deployAlpineVersion)

	log.Printf("Downloading deploy boot files (Alpine %s netboot)...", deployAlpineVersion)

	if err := downloadFile(kernelURL, kernelPath); err != nil {
		return fmt.Errorf("download deploy kernel: %w", err)
	}
	if err := downloadFile(initrdURL, initrdPath); err != nil {
		return fmt.Errorf("download deploy initrd: %w", err)
	}

	log.Printf("Deploy boot files ready")
	return nil
}

// HasDeployFiles checks if the deploy boot files are already downloaded.
func (m *Manager) HasDeployFiles() bool {
	dir := m.DeployDir()
	return fileExists(filepath.Join(dir, "kernel")) && fileExists(filepath.Join(dir, "initrd"))
}

// GenerateDeployIPXEScript generates an iPXE boot script that boots the
// Alpine deploy system. The deploy system will partition, format, and
// extract the rootfs image onto the agent's disk.
func (m *Manager) GenerateDeployIPXEScript(agentID string) string {
	var b strings.Builder

	kernelURL := fmt.Sprintf("http://%s/boot/deploy/kernel", m.ServerIP)
	initrdURL := fmt.Sprintf("http://%s/boot/deploy/initrd", m.ServerIP)
	modloopURL := fmt.Sprintf("http://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/netboot/modloop-lts", deployAlpineVersion)
	apkovlURL := fmt.Sprintf("http://%s/boot/deploy/apkovl.tar.gz", m.ServerIP)

	b.WriteString("#!ipxe\n\n")
	b.WriteString(fmt.Sprintf("kernel %s alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v%s/main/ modloop=%s ip=dhcp apkovl=%s fw4ai_agent=%s fw4ai_server=%s\n",
		kernelURL, deployAlpineVersion, modloopURL, apkovlURL, agentID, m.ServerIP))
	b.WriteString(fmt.Sprintf("initrd %s\n", initrdURL))
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
OS_TYPE=$(grep '^os_type=' /tmp/deploy-info.txt | cut -d= -f2-)

if [ -z "$DISK" ] || [ -z "$IMAGE_URL" ]; then
    echo "ERROR: Missing disk or image_url in deploy info"
    wget -qO /dev/null "${API}/boot/status/${AGENT_ID}?status=error&msg=missing+deploy+info" || true
    exit 1
fi

echo "-> Disk: $DISK"
echo "-> Image: $IMAGE_URL"
echo "-> Hostname: $HOSTNAME"

# Install e2fsprogs for mkfs.ext4 (busybox version is limited).
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
mkfs.ext4 -F ${PART}

# Mount and extract rootfs.
echo "-> Extracting rootfs image..."
mkdir -p /mnt/target
mount ${PART} /mnt/target
wget -qO - "${IMAGE_URL}" | tar xzf - -C /mnt/target

# Set hostname.
if [ -n "$HOSTNAME" ]; then
    echo "$HOSTNAME" > /mnt/target/etc/hostname
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

# Try Alpine paths first, then Debian paths.
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

# Boot into the installed system.
sync

# Use kexec to boot directly into the installed kernel without hardware reboot.
KERNEL=$(ls /mnt/target/boot/vmlinuz-* 2>/dev/null | head -n1)
INITRD=""
if [ "$OS_TYPE" = "debian" ] || [ "$OS_TYPE" = "ubuntu" ]; then
    INITRD=$(ls /mnt/target/boot/initrd.img-* 2>/dev/null | head -n1)
    APPEND="root=${PART} ro quiet"
elif [ "$OS_TYPE" = "alpine" ]; then
    INITRD=$(ls /mnt/target/boot/initramfs-* 2>/dev/null | head -n1)
    APPEND="root=${PART} modules=ext4 quiet"
fi

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

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	tmpPath := dest + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.Close()

	return os.Rename(tmpPath, dest)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
