package image

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

// BuildLogger captures build output for later viewing.
type BuildLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewBuildLogger creates a new build logger.
func NewBuildLogger() *BuildLogger {
	return &BuildLogger{}
}

// Write implements io.Writer, capturing output.
func (bl *BuildLogger) Write(p []byte) (n int, err error) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	return bl.buf.Write(p)
}

// String returns all captured output.
func (bl *BuildLogger) String() string {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	return bl.buf.String()
}

// BuildSettings holds global settings applied during image builds.
type BuildSettings struct {
	Keyboard    string // keyboard layout, e.g. "us", "fi"
	Timezone    string // timezone, e.g. "UTC", "Europe/Helsinki"
	GitUsername string // git user.name
	GitEmail    string // git user.email
}

// BuildImage builds a new version of a disk image by creating a rootfs tarball.
// This runs as a long-running operation and should be called in a goroutine.
// The serverIP is the firewall's agent-facing IP (e.g., 10.255.255.1).
// If bl is non-nil, build output is captured to it.
func (m *Manager) BuildImage(img *DiskImage, version int, serverIP string, settings BuildSettings, bl *BuildLogger) error {
	if bl != nil {
		setBuildLogger(bl)
		defer setBuildLogger(nil)
	}
	versionDir := m.VersionDir(img.ID, version)
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		return fmt.Errorf("create version dir: %w", err)
	}

	rootfsPath := filepath.Join(versionDir, "rootfs.tar.gz")

	switch img.OS {
	case agent.OSAlpine:
		return m.buildAlpine(img, rootfsPath, serverIP, settings, bl)
	case agent.OSDebian:
		return m.buildDebian(img, rootfsPath, serverIP, "debian", settings, bl)
	case agent.OSUbuntu:
		return m.buildDebian(img, rootfsPath, serverIP, "ubuntu", settings, bl)
	default:
		return fmt.Errorf("unsupported OS type: %s", img.OS)
	}
}

// buildAlpine builds an Alpine Linux rootfs tarball.
func (m *Manager) buildAlpine(img *DiskImage, rootfsPath, serverIP string, settings BuildSettings, _ *BuildLogger) error {
	// Download Alpine minirootfs.
	minirootfsURL := fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/alpine-minirootfs-%s.0-x86_64.tar.gz",
		img.OSVersion, img.OSVersion)

	tmpDir, err := os.MkdirTemp("/opt/firewall4ai", "fw4ai-build-alpine-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootfsDir := filepath.Join(tmpDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return fmt.Errorf("create rootfs dir: %w", err)
	}

	// Download and extract minirootfs.
	buildLog("Image build [%s v%s]: downloading Alpine minirootfs", img.Name, img.OSVersion)
	minirootfs := filepath.Join(tmpDir, "minirootfs.tar.gz")
	if err := downloadFile(minirootfsURL, minirootfs); err != nil {
		return fmt.Errorf("download minirootfs: %w", err)
	}

	if err := run("tar", "xzf", minirootfs, "-C", rootfsDir); err != nil {
		return fmt.Errorf("extract minirootfs: %w", err)
	}

	// Setup resolv.conf for DNS in chroot.
	if err := os.WriteFile(filepath.Join(rootfsDir, "etc/resolv.conf"), []byte("nameserver 10.255.255.1\n"), 0o644); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}

	// Setup Alpine repositories.
	repos := fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/main\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n",
		img.OSVersion, img.OSVersion)
	if err := os.WriteFile(filepath.Join(rootfsDir, "etc/apk/repositories"), []byte(repos), 0o644); err != nil {
		return fmt.Errorf("write repositories: %w", err)
	}

	// Mount proc/sys/dev for chroot.
	mounts := []struct{ src, dst, fstype string }{
		{"proc", filepath.Join(rootfsDir, "proc"), "proc"},
		{"sysfs", filepath.Join(rootfsDir, "sys"), "sysfs"},
	}
	for _, mnt := range mounts {
		os.MkdirAll(mnt.dst, 0o755)
		if err := run("mount", "-t", mnt.fstype, mnt.src, mnt.dst); err != nil {
			buildLog("Warning: mount %s failed: %v", mnt.fstype, err)
		}
	}
	os.MkdirAll(filepath.Join(rootfsDir, "dev"), 0o755)
	run("mount", "--bind", "/dev", filepath.Join(rootfsDir, "dev"))

	defer func() {
		run("umount", "-l", filepath.Join(rootfsDir, "dev"))
		run("umount", "-l", filepath.Join(rootfsDir, "sys"))
		run("umount", "-l", filepath.Join(rootfsDir, "proc"))
	}()

	// Install base packages + kernel + bootloader.
	buildLog("Image build [%s v%s]: installing packages", img.Name, img.OSVersion)

	basePkgs := []string{"linux-virt", "syslinux", "e2fsprogs", "openrc", "alpine-base", "ca-certificates", "openssh", "git"}
	allPkgs := append(basePkgs, img.Packages...)

	if err := runChroot(rootfsDir, "apk", append([]string{"update"})...); err != nil {
		return fmt.Errorf("apk update: %w", err)
	}
	if err := runChroot(rootfsDir, "apk", append([]string{"add"}, allPkgs...)...); err != nil {
		return fmt.Errorf("apk add: %w", err)
	}

	// Reconfigure mkinitfs to include network and Hyper-V support for PXE boot.
	// This must be done AFTER apk add, because installing the mkinitfs package
	// overwrites mkinitfs.conf with its default (which lacks "network").
	// We must pass the kernel version explicitly because mkinitfs defaults to
	// uname -r which returns the host kernel, not the chroot's Alpine kernel.
	buildLog("Image build [%s v%s]: regenerating initrd with network support", img.Name, img.OSVersion)

	// Create a custom "hyperv" feature for mkinitfs that includes the Hyper-V
	// VMBus driver (hv_vmbus) and the tulip driver (used by Hyper-V Gen1 legacy NIC).
	// The "network" feature covers kernel/drivers/net (hv_netvsc, tulip) but NOT
	// kernel/drivers/hv (hv_vmbus), so hv_netvsc would fail to load without this.
	os.MkdirAll(filepath.Join(rootfsDir, "etc/mkinitfs/features.d"), 0o755)
	hypervModules := "kernel/drivers/hv\nkernel/drivers/net/ethernet/dec/tulip\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/mkinitfs/features.d/hyperv.modules"), []byte(hypervModules), 0o644)

	mkinitfsConf := "features=\"ata base cdrom ext2 hyperv keymap kms mmc network nvme scsi usb virtio\"\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/mkinitfs/mkinitfs.conf"), []byte(mkinitfsConf), 0o644)

	// Find the installed kernel version from /lib/modules/<version>/.
	moduleDirs, _ := filepath.Glob(filepath.Join(rootfsDir, "lib/modules/*"))
	if len(moduleDirs) == 0 {
		return fmt.Errorf("no kernel modules found in chroot")
	}
	kernelVersion := filepath.Base(moduleDirs[0])
	if err := runChroot(rootfsDir, "mkinitfs", kernelVersion); err != nil {
		return fmt.Errorf("mkinitfs: %w", err)
	}

	// Configure the system.
	buildLog("Image build [%s v%s]: configuring system", img.Name, img.OSVersion)

	// fstab
	fstab := "/dev/sda1\t/\text2\tdefaults,noatime\t0\t1\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/fstab"), []byte(fstab), 0o644)

	// Auto-login on tty1.
	inittab := filepath.Join(rootfsDir, "etc/inittab")
	if data, err := os.ReadFile(inittab); err == nil {
		content := strings.ReplaceAll(string(data),
			"tty1::respawn:/sbin/getty 38400 tty1",
			"tty1::respawn:/sbin/getty -n -l /bin/sh 38400 tty1")
		os.WriteFile(inittab, []byte(content), 0o644)
	}

	// Network: auto eth0 via DHCP.
	os.MkdirAll(filepath.Join(rootfsDir, "etc/network"), 0o755)
	interfaces := "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/network/interfaces"), []byte(interfaces), 0o644)

	// Install custom CA certificate into the rootfs.
	buildLog("Image build [%s v%s]: installing CA certificate", img.Name, img.OSVersion)
	caDir := filepath.Join(rootfsDir, "usr/local/share/ca-certificates")
	os.MkdirAll(caDir, 0o755)
	caURL := fmt.Sprintf("http://%s/ca.crt", serverIP)
	if err := downloadFile(caURL, filepath.Join(caDir, "firewall4ai-ca.crt")); err != nil {
		buildLog("Warning: failed to download CA certificate: %v", err)
	} else {
		runChroot(rootfsDir, "update-ca-certificates")
	}

	// Root password: set to 'root'.
	runChroot(rootfsDir, "sh", "-c", "echo 'root:root' | chpasswd")

	// Enable networking services.
	runChroot(rootfsDir, "rc-update", "add", "networking", "boot")
	runChroot(rootfsDir, "rc-update", "add", "hostname", "boot")

	// Bootloader config (extlinux) - use linux-virt for disk boot (optimized for VMs).
	os.MkdirAll(filepath.Join(rootfsDir, "boot"), 0o755)
	virtKernelGlob, _ := filepath.Glob(filepath.Join(rootfsDir, "boot/vmlinuz-*-virt"))
	kernelFile := "vmlinuz-virt"
	initrdFile := "initramfs-virt"
	if len(virtKernelGlob) > 0 {
		kernelFile = filepath.Base(virtKernelGlob[0])
		initrdFile = strings.Replace(kernelFile, "vmlinuz-", "initramfs-", 1)
	}

	extlinuxConf := fmt.Sprintf(`DEFAULT alpine
LABEL alpine
  LINUX /boot/%s
  INITRD /boot/%s
  APPEND root=/dev/sda1 modules=ext2 net.ifnames=0 biosdevname=0
`, kernelFile, initrdFile)
	os.WriteFile(filepath.Join(rootfsDir, "boot/extlinux.conf"), []byte(extlinuxConf), 0o644)

	// Configure keyboard layout.
	if settings.Keyboard != "" {
		buildLog("Image build [%s v%s]: configuring keyboard layout: %s", img.Name, img.OSVersion, settings.Keyboard)
		runChroot(rootfsDir, "apk", "add", "kbd-bkeymaps")
		kbConf := fmt.Sprintf("KEYMAPOPTS=\"%s %s\"\n", settings.Keyboard, settings.Keyboard)
		os.WriteFile(filepath.Join(rootfsDir, "etc/conf.d/loadkmap"), []byte(kbConf), 0o644)
		runChroot(rootfsDir, "rc-update", "add", "loadkmap", "boot")
	}

	// Configure timezone.
	if settings.Timezone != "" {
		buildLog("Image build [%s v%s]: configuring timezone: %s", img.Name, img.OSVersion, settings.Timezone)
		runChroot(rootfsDir, "apk", "add", "tzdata")
		os.MkdirAll(filepath.Join(rootfsDir, "etc/zoneinfo"), 0o755)
		runChroot(rootfsDir, "sh", "-c", fmt.Sprintf("cp /usr/share/zoneinfo/%s /etc/localtime", settings.Timezone))
		os.WriteFile(filepath.Join(rootfsDir, "etc/timezone"), []byte(settings.Timezone+"\n"), 0o644)
	}

	// Configure git client.
	configureGit(rootfsDir, serverIP, settings)

	// Install container tools.
	if err := installContainerTools(img, rootfsDir, false, nil); err != nil {
		return fmt.Errorf("install container tools: %w", err)
	}

	// Install AI tools.
	if err := installAITools(img, rootfsDir, false, nil); err != nil {
		return fmt.Errorf("install AI tools: %w", err)
	}

	// Install rtk.
	if err := installRtk(img, rootfsDir, false, nil); err != nil {
		return fmt.Errorf("install rtk: %w", err)
	}

	// Run custom scripts.
	for i, script := range img.Scripts {
		buildLog("Image build [%s v%s]: running custom script %d", img.Name, img.OSVersion, i+1)
		if err := runChroot(rootfsDir, "sh", "-c", script); err != nil {
			return fmt.Errorf("custom script %d: %w", i+1, err)
		}
	}

	// Export virt kernel + initrd for netboot use.
	// Use the same kernel/initrd files identified for extlinux config.
	// Alpine names files as vmlinuz-virt (no version number), while the glob
	// vmlinuz-*-virt wouldn't match, so we use the resolved file names directly.
	buildLog("Image build [%s v%s]: exporting kernel and initrd for netboot", img.Name, img.OSVersion)
	netbootDir := filepath.Join(filepath.Dir(rootfsPath), "netboot")
	if err := os.MkdirAll(netbootDir, 0o755); err != nil {
		return fmt.Errorf("create netboot dir: %w", err)
	}

	kernelPath := filepath.Join(rootfsDir, "boot", kernelFile)
	initrdPath := filepath.Join(rootfsDir, "boot", initrdFile)
	if err := copyFile(kernelPath, filepath.Join(netbootDir, "vmlinuz")); err != nil {
		return fmt.Errorf("export kernel: %w", err)
	}
	if err := copyFile(initrdPath, filepath.Join(netbootDir, "initrd.img")); err != nil {
		return fmt.Errorf("export initrd: %w", err)
	}

	// Create rootfs tarball.
	buildLog("Image build [%s v%s]: creating rootfs tarball", img.Name, img.OSVersion)

	// Unmount before tarring.
	run("umount", "-l", filepath.Join(rootfsDir, "dev"))
	run("umount", "-l", filepath.Join(rootfsDir, "sys"))
	run("umount", "-l", filepath.Join(rootfsDir, "proc"))

	tmpTar := rootfsPath + ".tmp"
	if err := run("tar", "czf", tmpTar, "-C", rootfsDir, "."); err != nil {
		return fmt.Errorf("create tarball: %w", err)
	}
	if err := os.Rename(tmpTar, rootfsPath); err != nil {
		return fmt.Errorf("rename tarball: %w", err)
	}

	buildLog("Image build [%s v%s]: build complete", img.Name, img.OSVersion)
	return nil
}

// buildDebian builds a Debian or Ubuntu rootfs tarball using debootstrap.
func (m *Manager) buildDebian(img *DiskImage, rootfsPath, serverIP, distro string, settings BuildSettings, _ *BuildLogger) error {
	codename := debianCodename(img.OSVersion)
	mirror := "http://deb.debian.org/debian"
	if distro == "ubuntu" {
		codename = ubuntuCodename(img.OSVersion)
		mirror = "http://archive.ubuntu.com/ubuntu"
	}

	os.MkdirAll("/opt/firewall4ai", 0755)
	tmpDir, err := os.MkdirTemp("/opt/firewall4ai", "fw4ai-build-debian-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootfsDir := filepath.Join(tmpDir, "rootfs")

	// Run debootstrap.
	buildLog("Image build [%s v%s]: running debootstrap (%s %s)", img.Name, img.OSVersion, codename, mirror)
	if err := run("debootstrap", "--arch=amd64", codename, rootfsDir, mirror); err != nil {
		return fmt.Errorf("debootstrap: %w", err)
	}

	// Mount proc/sys/dev for chroot.
	run("mount", "-t", "proc", "proc", filepath.Join(rootfsDir, "proc"))
	run("mount", "-t", "sysfs", "sysfs", filepath.Join(rootfsDir, "sys"))
	run("mount", "--bind", "/dev", filepath.Join(rootfsDir, "dev"))

	defer func() {
		run("umount", "-l", filepath.Join(rootfsDir, "dev"))
		run("umount", "-l", filepath.Join(rootfsDir, "sys"))
		run("umount", "-l", filepath.Join(rootfsDir, "proc"))
	}()

	// For Ubuntu, enable universe repository (extlinux, syslinux-common, ifupdown
	// are in universe, not main). Debootstrap only configures main by default.
	if distro == "ubuntu" {
		sources := fmt.Sprintf("deb %s %s main universe\n", mirror, codename)
		os.WriteFile(filepath.Join(rootfsDir, "etc/apt/sources.list"), []byte(sources), 0o644)
	}

	// Install kernel + bootloader + packages.
	buildLog("Image build [%s v%s]: installing packages", img.Name, img.OSVersion)

	// Set DEBIAN_FRONTEND to avoid interactive prompts.
	debEnv := []string{"DEBIAN_FRONTEND=noninteractive"}

	// Use distro-specific kernel package.
	kernelPkg := "linux-image-amd64"
	if distro == "ubuntu" {
		kernelPkg = "linux-image-generic"
	}

	basePkgs := []string{kernelPkg, "extlinux", "syslinux-common", "ca-certificates", "systemd-sysv", "ifupdown", "wget", "e2fsprogs", "openssh-server", "locales", "git"}
	allPkgs := append(basePkgs, img.Packages...)

	if err := runChrootEnv(rootfsDir, debEnv, "apt-get", "update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	if err := runChrootEnv(rootfsDir, debEnv, "apt-get", append([]string{"install", "-y"}, allPkgs...)...); err != nil {
		return fmt.Errorf("apt-get install: %w", err)
	}

	// Configure locales
	os.WriteFile(filepath.Join(rootfsDir, "etc/locale.gen"), []byte("en_US.UTF-8 UTF-8\n"), 0o644)
	runChrootEnv(rootfsDir, debEnv, "locale-gen")

	// Install custom CA certificate into the rootfs.
	buildLog("Image build [%s v%s]: installing CA certificate", img.Name, img.OSVersion)
	caDir := filepath.Join(rootfsDir, "usr/local/share/ca-certificates")
	os.MkdirAll(caDir, 0o755)
	caURL := fmt.Sprintf("http://%s/ca.crt", serverIP)
	if err := downloadFile(caURL, filepath.Join(caDir, "firewall4ai-ca.crt")); err != nil {
		buildLog("Warning: failed to download CA certificate: %v", err)
	} else {
		runChroot(rootfsDir, "update-ca-certificates")
	}

	// Configure the system.
	buildLog("Image build [%s v%s]: configuring system", img.Name, img.OSVersion)
	os.WriteFile(filepath.Join(rootfsDir, "etc/motd"), []byte(""), 0o644)

	// fstab.
	fstab := "/dev/sda1\t/\text2\tdefaults,noatime\t0\t1\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/fstab"), []byte(fstab), 0o644)

	// Automatically enable dynamically added memory.
	balloon := `SUBSYSTEM=="memory", ACTION=="add", ATTR{state}="online"`
	os.WriteFile(filepath.Join(rootfsDir, "etc/udev/rules.d/100-balloon.rules"), []byte(balloon), 0o644)

	// Auto-login on tty1 via systemd.
	overrideDir := filepath.Join(rootfsDir, "etc/systemd/system/getty@tty1.service.d")
	os.MkdirAll(overrideDir, 0o755)
	override := "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %I $TERM\n"
	os.WriteFile(filepath.Join(overrideDir, "override.conf"), []byte(override), 0o644)

	// Network: auto eth0 via DHCP.
	interfaces := "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/network/interfaces"), []byte(interfaces), 0o644)

	// Root password: set to 'root'.
	runChroot(rootfsDir, "sh", "-c", "echo 'root:root' | chpasswd")

	// Hostname placeholder.
	os.WriteFile(filepath.Join(rootfsDir, "etc/hostname"), []byte("agent\n"), 0o644)

	// Bootloader config (extlinux).
	os.MkdirAll(filepath.Join(rootfsDir, "boot"), 0o755)
	// Find installed kernel.
	kernelGlob, _ := filepath.Glob(filepath.Join(rootfsDir, "boot/vmlinuz-*"))
	initrdGlob, _ := filepath.Glob(filepath.Join(rootfsDir, "boot/initrd.img-*"))
	kernelFile := "vmlinuz"
	initrdFile := "initrd.img"
	if len(kernelGlob) > 0 {
		kernelFile = filepath.Base(kernelGlob[0])
	}
	if len(initrdGlob) > 0 {
		initrdFile = filepath.Base(initrdGlob[0])
	}

	extlinuxConf := fmt.Sprintf(`DEFAULT linux
LABEL linux
  LINUX /boot/%s
  INITRD /boot/%s
  APPEND root=/dev/sda1 ro net.ifnames=0 biosdevname=0
`, kernelFile, initrdFile)
	os.WriteFile(filepath.Join(rootfsDir, "boot/extlinux.conf"), []byte(extlinuxConf), 0o644)

	// Install initramfs-tools hook and premount script for PXE deploy.
	// The hook copies deploy tools (wget, fdisk, mkfs.ext2, tar) into the initrd.
	// The premount script runs during PXE boot to partition, format, and extract rootfs.
	// On normal disk boots, the premount script detects no fw4ai params and exits.
	buildLog("Image build [%s v%s]: adding deploy support to initrd", img.Name, img.OSVersion)
	os.MkdirAll(filepath.Join(rootfsDir, "etc/initramfs-tools/hooks"), 0o755)
	os.MkdirAll(filepath.Join(rootfsDir, "etc/initramfs-tools/scripts/init-premount"), 0o755)
	os.WriteFile(filepath.Join(rootfsDir, "etc/initramfs-tools/modules"), []byte("ext2"), 0o644)

	deployHook := `#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/wget
copy_exec /sbin/fdisk
copy_exec /sbin/mkfs.ext2
copy_exec /sbin/fsck.ext2
copy_exec /sbin/fsck.vfat
copy_exec /sbin/mke2fs
copy_exec /bin/tar
copy_exec /bin/gzip
copy_exec /bin/dd
copy_exec /usr/sbin/chroot
copy_exec /sbin/blockdev
`
	os.WriteFile(filepath.Join(rootfsDir, "etc/initramfs-tools/hooks/fw4ai-deploy"), []byte(deployHook), 0o755)

	deployScript := `#!/bin/sh
# Firewall4AI: Deploy premount script
# Runs inside initramfs before root is mounted.
# Partitions disk, downloads rootfs, extracts it, installs bootloader.

PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac

# Extract deploy parameters from kernel cmdline.
FW4AI_AGENT=""
FW4AI_SERVER=""
for p in $(cat /proc/cmdline); do
    case "$p" in
        fw4ai_agent=*) FW4AI_AGENT="${p#fw4ai_agent=}" ;;
        fw4ai_server=*) FW4AI_SERVER="${p#fw4ai_server=}" ;;
    esac
done

# Skip if not a deploy boot (no fw4ai parameters).
[ -z "$FW4AI_AGENT" ] && exit 0
[ -z "$FW4AI_SERVER" ] && exit 0

# Ensure networking is configured. On some distros (e.g., Ubuntu),
# configure_networking may not have been called yet at premount time.
# The function is idempotent (guards with CONFIGURE_NETWORKING_DONE).
if [ -f /scripts/functions ]; then
    . /scripts/functions
    configure_networking
fi

API="http://${FW4AI_SERVER}"

echo "=== Firewall4AI Deploy starting ==="

# Report deploying status.
wget -qO /dev/null "${API}/boot/status/${FW4AI_AGENT}?status=deploying" 2>/dev/null || true

# Get deployment info.
echo "-> Fetching deployment info..."
wget -qO /tmp/deploy-info.txt "${API}/boot/deploy-info/${FW4AI_AGENT}"

DISK=$(grep '^disk=' /tmp/deploy-info.txt | cut -d= -f2-)
IMAGE_URL=$(grep '^image_url=' /tmp/deploy-info.txt | cut -d= -f2-)
HOSTNAME=$(grep '^hostname=' /tmp/deploy-info.txt | cut -d= -f2-)

if [ -z "$DISK" ] || [ -z "$IMAGE_URL" ]; then
    echo "ERROR: Missing disk or image_url in deploy info"
    wget -qO /dev/null "${API}/boot/status/${FW4AI_AGENT}?status=error&msg=missing+deploy+info" 2>/dev/null || true
    exit 0
fi

echo "-> Disk: $DISK"
echo "-> Image: $IMAGE_URL"

# Partition disk: single partition, entire disk, bootable.
echo "-> Partitioning ${DISK}..."
echo -e "o\nn\np\n1\n\n\na\n1\nw" | fdisk ${DISK} 2>/dev/null || true

# Force kernel to re-read the partition table and wait for device node.
blockdev --rereadpt ${DISK} 2>/dev/null || true

# Detect partition name (sda1 vs vda1 vs nvme0n1p1).
PART="${DISK}1"
if echo "$DISK" | grep -q "nvme"; then
    PART="${DISK}p1"
fi

# Wait for partition device to appear (udev may be slow in initramfs).
echo "-> Waiting for ${PART}..."
i=0
while [ ! -b "${PART}" ] && [ "$i" -lt 10 ]; do
    sleep 1
    i=$((i + 1))
done
if [ ! -b "${PART}" ]; then
    echo "ERROR: ${PART} did not appear after partitioning"
    wget -qO /dev/null "${API}/boot/status/${FW4AI_AGENT}?status=error&msg=partition+not+found" 2>/dev/null || true
    exit 0
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
    # Enable SSH server on first boot.
    if [ -d /mnt/target/etc/systemd ]; then
        chroot /mnt/target systemctl enable ssh 2>/dev/null || true
    fi
    if [ -f /mnt/target/etc/conf.d/sshd ] || [ -x /mnt/target/usr/sbin/sshd ]; then
        chroot /mnt/target rc-update add sshd default 2>/dev/null || true
    fi
    # Configure sshd to allow root login with keys only.
    if [ -f /mnt/target/etc/ssh/sshd_config ]; then
        sed -i 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' /mnt/target/etc/ssh/sshd_config
    fi
fi

# Download CA certificate.
echo "-> Installing CA certificate..."
mkdir -p /mnt/target/usr/local/share/ca-certificates
wget -qO /mnt/target/usr/local/share/ca-certificates/firewall4ai-ca.crt "${API}/ca.crt" 2>/dev/null || true
if [ -x /mnt/target/usr/sbin/update-ca-certificates ]; then
    chroot /mnt/target update-ca-certificates 2>/dev/null || true
fi

# Install bootloader for future disk boots.
echo "-> Installing bootloader..."
MBR_BIN=""
EXTLINUX_BIN=""
for p in /mnt/target/usr/share/syslinux/mbr.bin /mnt/target/usr/lib/syslinux/mbr/mbr.bin; do
    [ -f "$p" ] && MBR_BIN="$p" && break
done
for p in /mnt/target/sbin/extlinux /mnt/target/usr/bin/extlinux /mnt/target/usr/sbin/extlinux; do
    [ -x "$p" ] && EXTLINUX_BIN="$p" && break
done
if [ -n "$MBR_BIN" ]; then
    dd if="$MBR_BIN" of=${DISK} bs=440 count=1 2>/dev/null
fi
if [ -n "$EXTLINUX_BIN" ]; then
    mkdir -p /mnt/target/boot
    "$EXTLINUX_BIN" --install /mnt/target/boot
fi

# Report success.
echo "-> Deploy complete!"
wget -qO /dev/null "${API}/boot/status/${FW4AI_AGENT}?status=installed" 2>/dev/null || true

# Unmount so initrd can mount it as root.
umount /mnt/target

echo "=== Firewall4AI Deploy done, continuing boot ==="
`
	os.WriteFile(filepath.Join(rootfsDir, "etc/initramfs-tools/scripts/init-premount/fw4ai-deploy"), []byte(deployScript), 0o755)

	// Rebuild initrd with deploy tools included.
	buildLog("Image build [%s v%s]: rebuilding initrd with deploy tools", img.Name, img.OSVersion)
	if err := runChrootEnv(rootfsDir, debEnv, "update-initramfs", "-u"); err != nil {
		return fmt.Errorf("update-initramfs: %w", err)
	}

	// Re-read initrd glob after rebuild.
	initrdGlob, _ = filepath.Glob(filepath.Join(rootfsDir, "boot/initrd.img-*"))
	if len(initrdGlob) > 0 {
		initrdFile = filepath.Base(initrdGlob[0])
	}

	// Configure keyboard layout.
	if settings.Keyboard != "" {
		buildLog("Image build [%s v%s]: configuring keyboard layout: %s", img.Name, img.OSVersion, settings.Keyboard)
		kbDefault := fmt.Sprintf("keyboard-configuration\tkeyboard-configuration/layoutcode\tstring\t%s\n", settings.Keyboard)
		runChrootEnv(rootfsDir, debEnv, "sh", "-c", fmt.Sprintf("echo '%s' | debconf-set-selections", kbDefault))
		runChrootEnv(rootfsDir, debEnv, "apt-get", "install", "-y", "keyboard-configuration", "console-setup")
	}

	// Configure timezone.
	if settings.Timezone != "" {
		buildLog("Image build [%s v%s]: configuring timezone: %s", img.Name, img.OSVersion, settings.Timezone)
		os.WriteFile(filepath.Join(rootfsDir, "etc/timezone"), []byte(settings.Timezone+"\n"), 0o644)
		runChrootEnv(rootfsDir, debEnv, "ln", "-sf", "/usr/share/zoneinfo/"+settings.Timezone, "/etc/localtime")
		runChrootEnv(rootfsDir, debEnv, "dpkg-reconfigure", "-f", "noninteractive", "tzdata")
	}

	// Configure git client.
	configureGit(rootfsDir, serverIP, settings)

	// Install container tools.
	if err := installContainerTools(img, rootfsDir, true, debEnv); err != nil {
		return fmt.Errorf("install container tools: %w", err)
	}

	// Install AI tools.
	if err := installAITools(img, rootfsDir, true, debEnv); err != nil {
		return fmt.Errorf("install AI tools: %w", err)
	}

	// Install rtk.
	if err := installRtk(img, rootfsDir, true, debEnv); err != nil {
		return fmt.Errorf("install rtk: %w", err)
	}

	// Run custom scripts.
	for i, script := range img.Scripts {
		buildLog("Image build [%s v%s]: running custom script %d", img.Name, img.OSVersion, i+1)
		if err := runChrootEnv(rootfsDir, debEnv, "sh", "-c", script); err != nil {
			return fmt.Errorf("custom script %d: %w", i+1, err)
		}
	}

	// Export kernel + initrd for netboot use.
	// The initrd already contains the deploy hook and premount script,
	// so no separate deploy overlay is needed.
	buildLog("Image build [%s v%s]: exporting kernel and initrd for netboot", img.Name, img.OSVersion)
	netbootDir := filepath.Join(filepath.Dir(rootfsPath), "netboot")
	if err := os.MkdirAll(netbootDir, 0o755); err != nil {
		return fmt.Errorf("create netboot dir: %w", err)
	}

	if len(kernelGlob) > 0 {
		if err := copyFile(kernelGlob[0], filepath.Join(netbootDir, "vmlinuz")); err != nil {
			return fmt.Errorf("export kernel: %w", err)
		}
	}
	if len(initrdGlob) > 0 {
		if err := copyFile(initrdGlob[0], filepath.Join(netbootDir, "initrd.img")); err != nil {
			return fmt.Errorf("export initrd: %w", err)
		}
	}

	// Create rootfs tarball.
	buildLog("Image build [%s v%s]: creating rootfs tarball", img.Name, img.OSVersion)

	run("umount", "-l", filepath.Join(rootfsDir, "dev"))
	run("umount", "-l", filepath.Join(rootfsDir, "sys"))
	run("umount", "-l", filepath.Join(rootfsDir, "proc"))

	tmpTar := rootfsPath + ".tmp"
	if err := run("tar", "czf", tmpTar, "-C", rootfsDir, "."); err != nil {
		return fmt.Errorf("create tarball: %w", err)
	}
	if err := os.Rename(tmpTar, rootfsPath); err != nil {
		return fmt.Errorf("rename tarball: %w", err)
	}

	buildLog("Image build [%s v%s]: build complete", img.Name, img.OSVersion)
	return nil
}

// run executes a command and returns an error if it fails.
// activeBuildLogger holds the current build logger (if any) for capturing output.
var activeBuildLogger struct {
	mu sync.Mutex
	bl *BuildLogger
}

func setBuildLogger(bl *BuildLogger) {
	activeBuildLogger.mu.Lock()
	activeBuildLogger.bl = bl
	activeBuildLogger.mu.Unlock()
}

func getBuildLogger() *BuildLogger {
	activeBuildLogger.mu.Lock()
	defer activeBuildLogger.mu.Unlock()
	return activeBuildLogger.bl
}

func cmdOutput() (io.Writer, io.Writer) {
	bl := getBuildLogger()
	if bl != nil {
		return bl, bl
	}
	return io.Discard, io.Discard
}

// buildLog logs a message to the active build logger only.
func buildLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	bl := getBuildLogger()
	if bl != nil {
		bl.mu.Lock()
		bl.buf.WriteString(msg + "\n")
		bl.mu.Unlock()
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = cmdOutput()
	return cmd.Run()
}

// runChroot runs a command inside a chroot.
func runChroot(rootfs, name string, args ...string) error {
	chrootArgs := append([]string{rootfs, name}, args...)
	cmd := exec.Command("chroot", chrootArgs...)
	cmd.Stdout, cmd.Stderr = cmdOutput()
	return cmd.Run()
}

// runChrootEnv runs a command inside a chroot with extra environment variables.
func runChrootEnv(rootfs string, env []string, name string, args ...string) error {
	// Use env to set variables, then chroot.
	envArgs := append(env, "chroot", rootfs, name)
	envArgs = append(envArgs, args...)
	cmd := exec.Command("env", envArgs...)
	cmd.Stdout, cmd.Stderr = cmdOutput()
	return cmd.Run()
}

// copyFile copies a file from src to dst atomically.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmpPath := dst + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return err
	}
	out.Close()

	return os.Rename(tmpPath, dst)
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

// configureGit sets up git configuration in the rootfs.
// It configures user.name, user.email (if provided in settings), and sets up
// a credential helper that uses the firewall proxy for HTTPS authentication.
func configureGit(rootfsDir, serverIP string, settings BuildSettings) {
	var gitconfig strings.Builder

	if settings.GitUsername != "" {
		buildLog("Configuring git user.name: %s", settings.GitUsername)
		gitconfig.WriteString(fmt.Sprintf("[user]\n\tname = %s\n", settings.GitUsername))
		if settings.GitEmail != "" {
			gitconfig.WriteString(fmt.Sprintf("\temail = %s\n", settings.GitEmail))
		}
	} else if settings.GitEmail != "" {
		buildLog("Configuring git user.email: %s", settings.GitEmail)
		gitconfig.WriteString(fmt.Sprintf("[user]\n\temail = %s\n", settings.GitEmail))
	}

	// Configure git to trust the firewall CA for HTTPS operations.
	caCertPath := "/usr/local/share/ca-certificates/firewall4ai-ca.crt"
	gitconfig.WriteString(fmt.Sprintf("[http]\n\tsslCAInfo = %s\n", caCertPath))

	if gitconfig.Len() > 0 {
		buildLog("Writing /root/.gitconfig")
		os.WriteFile(filepath.Join(rootfsDir, "root/.gitconfig"), []byte(gitconfig.String()), 0o644)
	}
}

// installAITools installs the selected AI coding tools into the rootfs.
// It handles installing prerequisites (Node.js, npm, gh CLI) as needed.
func installAITools(img *DiskImage, rootfsDir string, isDebian bool, debEnv []string) error {
	if len(img.AITools) == 0 {
		return nil
	}

	buildLog("Image build [%s v%s]: installing AI tools", img.Name, img.OSVersion)

	needsNodeJS := false
	needsCurl := false
	for _, tool := range img.AITools {
		switch tool {
		case AIToolOpenCode, AIToolClaudeCode, AIToolOpenAICodex:
			needsNodeJS = true
		case AIToolGitHubCopilot:
			needsCurl = true
		}
	}

	// Install prerequisites.
	if isDebian {
		if needsNodeJS {
			buildLog("Image build [%s v%s]: installing Node.js (prerequisite for AI tools)", img.Name, img.OSVersion)
			if err := runChrootEnv(rootfsDir, debEnv, "apt-get", "install", "-y", "nodejs", "npm"); err != nil {
				return fmt.Errorf("install nodejs/npm: %w", err)
			}
		}
		if needsCurl {
			buildLog("Image build [%s v%s]: installing curl (prerequisite for GitHub Copilot)", img.Name, img.OSVersion)
			if err := runChrootEnv(rootfsDir, debEnv, "apt-get", "install", "-y", "curl"); err != nil {
				return fmt.Errorf("install curl: %w", err)
			}
		}
	} else {
		// Alpine
		if needsNodeJS {
			buildLog("Image build [%s v%s]: installing Node.js (prerequisite for AI tools)", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "apk", "add", "nodejs", "npm"); err != nil {
				return fmt.Errorf("install nodejs/npm: %w", err)
			}
		}
		if needsCurl {
			buildLog("Image build [%s v%s]: installing curl (prerequisite for GitHub Copilot)", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "apk", "add", "curl"); err != nil {
				return fmt.Errorf("install curl: %w", err)
			}
		}
	}

	// Install each AI tool.
	for _, tool := range img.AITools {
		switch tool {
		case AIToolOpenCode:
			buildLog("Image build [%s v%s]: installing OpenCode", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "npm", "install", "-g", "opencode-ai"); err != nil {
				return fmt.Errorf("install OpenCode: %w", err)
			}

		case AIToolClaudeCode:
			buildLog("Image build [%s v%s]: installing Claude Code", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "npm", "install", "-g", "@anthropic-ai/claude-code"); err != nil {
				return fmt.Errorf("install Claude Code: %w", err)
			}

		case AIToolOpenAICodex:
			buildLog("Image build [%s v%s]: installing OpenAI Codex", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "npm", "install", "-g", "@openai/codex"); err != nil {
				return fmt.Errorf("install OpenAI Codex: %w", err)
			}

		case AIToolGitHubCopilot:
			buildLog("Image build [%s v%s]: installing GitHub Copilot CLI", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "sh", "-c", "curl -fsSL https://gh.io/copilot-install | bash"); err != nil {
				return fmt.Errorf("install GitHub Copilot: %w", err)
			}
		}
	}

	return nil
}

// installContainerTools installs the selected container runtimes into the rootfs.
func installContainerTools(img *DiskImage, rootfsDir string, isDebian bool, debEnv []string) error {
	if len(img.ContainerTools) == 0 {
		return nil
	}

	buildLog("Image build [%s v%s]: installing container tools", img.Name, img.OSVersion)

	// Docker is automatically included when Nomad is selected.
	needsDocker := false
	for _, tool := range img.ContainerTools {
		if tool == ContainerToolDocker || tool == ContainerToolNomad {
			needsDocker = true
		}
	}

	if isDebian {
		if needsDocker {
			buildLog("Image build [%s v%s]: installing Docker", img.Name, img.OSVersion)
			if err := runChrootEnv(rootfsDir, debEnv, "apt-get", "install", "-y", "docker.io"); err != nil {
				return fmt.Errorf("install docker: %w", err)
			}
		}
		for _, tool := range img.ContainerTools {
			switch tool {
			case ContainerToolNomad:
				buildLog("Image build [%s v%s]: installing Nomad", img.Name, img.OSVersion)
				// Install Nomad from HashiCorp APT repo.
				if err := runChrootEnv(rootfsDir, debEnv, "sh", "-c",
					"apt-get install -y gpg lsb-release && "+
						"wget -qO- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && "+
						"echo \"deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main\" > /etc/apt/sources.list.d/hashicorp.list && "+
						"apt-get update && apt-get install -y nomad",
				); err != nil {
					return fmt.Errorf("install nomad: %w", err)
				}
			case ContainerToolKubernetes:
				buildLog("Image build [%s v%s]: installing K3s from pre-built binary", img.Name, img.OSVersion)
				if err := installK3s(rootfsDir, true, debEnv); err != nil {
					return fmt.Errorf("install k3s: %w", err)
				}
			}
		}
	} else {
		// Alpine
		if needsDocker {
			buildLog("Image build [%s v%s]: installing Docker", img.Name, img.OSVersion)
			if err := runChroot(rootfsDir, "apk", "add", "docker", "docker-cli-compose"); err != nil {
				return fmt.Errorf("install docker: %w", err)
			}
			runChroot(rootfsDir, "rc-update", "add", "docker", "default")
		}
		for _, tool := range img.ContainerTools {
			switch tool {
			case ContainerToolNomad:
				buildLog("Image build [%s v%s]: installing Nomad", img.Name, img.OSVersion)
				if err := runChroot(rootfsDir, "apk", "add", "nomad"); err != nil {
					return fmt.Errorf("install nomad: %w", err)
				}
			case ContainerToolKubernetes:
				buildLog("Image build [%s v%s]: installing K3s from pre-built binary", img.Name, img.OSVersion)
				if err := installK3s(rootfsDir, false, nil); err != nil {
					return fmt.Errorf("install k3s: %w", err)
				}
			}
		}
	}

	return nil
}

// installK3s downloads the K3s binary and sets up the K3s service.
// It pre-runs K3s during build so that container images are pulled and the node
// is ready immediately when the agent VM boots.
func installK3s(rootfsDir string, isDebian bool, debEnv []string) error {
	k3sVersion := "v1.32.4+k3s1"
	k3sURL := fmt.Sprintf("https://github.com/k3s-io/k3s/releases/download/%s/k3s", k3sVersion)

	// Download K3s binary and create symlinks.
	installScript := fmt.Sprintf(
		"wget -qO /usr/local/bin/k3s '%s' && "+
			"chmod 755 /usr/local/bin/k3s && "+
			"ln -sf k3s /usr/local/bin/kubectl && "+
			"ln -sf k3s /usr/local/bin/crictl && "+
			"ln -sf k3s /usr/local/bin/ctr",
		k3sURL,
	)

	if isDebian {
		if err := runChrootEnv(rootfsDir, debEnv, "sh", "-c", installScript); err != nil {
			return fmt.Errorf("download k3s binary: %w", err)
		}
	} else {
		if err := runChroot(rootfsDir, "sh", "-c", installScript); err != nil {
			return fmt.Errorf("download k3s binary: %w", err)
		}
	}

	// Create K3s data directories.
	for _, dir := range []string{
		"etc/rancher/k3s",
		"var/lib/rancher/k3s/server",
		"var/lib/rancher/k3s/agent",
	} {
		os.MkdirAll(filepath.Join(rootfsDir, dir), 0o755)
	}

	if isDebian {
		// systemd service unit for K3s.
		k3sService := `[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s server
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`
		os.MkdirAll(filepath.Join(rootfsDir, "etc/systemd/system"), 0o755)
		os.WriteFile(filepath.Join(rootfsDir, "etc/systemd/system/k3s.service"), []byte(k3sService), 0o644)
		runChrootEnv(rootfsDir, debEnv, "systemctl", "enable", "k3s")
	} else {
		// OpenRC init script for K3s (Alpine).
		k3sInit := `#!/sbin/openrc-run

name="k3s"
description="Lightweight Kubernetes"
command="/usr/local/bin/k3s"
command_args="server"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/k3s.log"
error_log="/var/log/k3s.log"

depend() {
	need net
	after firewall
}
`
		os.MkdirAll(filepath.Join(rootfsDir, "etc/init.d"), 0o755)
		os.WriteFile(filepath.Join(rootfsDir, "etc/init.d/k3s"), []byte(k3sInit), 0o755)
		runChroot(rootfsDir, "rc-update", "add", "k3s", "default")
	}

	// Pre-run K3s to pull images and initialize the node so it's ready at boot.
	buildLog("Pre-running K3s to pull container images and initialize node...")

	// K3s needs /proc, /sys, /dev mounted (already done by build flow).
	// Run K3s server briefly to let it pull all required images.
	preRunScript := `k3s server --data-dir /var/lib/rancher/k3s &
K3S_PID=$!
# Wait for K3s to become ready (node registered + system pods pulled).
for i in $(seq 1 120); do
  if k3s kubectl get nodes 2>/dev/null | grep -q " Ready"; then
    echo "K3s node is Ready"
    # Wait a bit more for core pods to be pulled.
    sleep 15
    break
  fi
  sleep 5
done
# Show status for build log.
k3s kubectl get nodes 2>/dev/null || true
k3s kubectl get pods -A 2>/dev/null || true
# Stop K3s gracefully.
kill $K3S_PID 2>/dev/null
wait $K3S_PID 2>/dev/null || true
# Also stop containerd that K3s spawned.
pkill -f "k3s.*containerd" 2>/dev/null || true
sleep 2
# Clean up runtime state but keep pre-pulled images and manifests.
rm -rf /var/lib/rancher/k3s/server/db/etcd 2>/dev/null || true
rm -rf /var/lib/rancher/k3s/server/tls 2>/dev/null || true
rm -rf /var/lib/rancher/k3s/server/cred 2>/dev/null || true
rm -rf /var/lib/rancher/k3s/server/token 2>/dev/null || true
rm -f /var/lib/rancher/k3s/server/node-token 2>/dev/null || true
rm -rf /etc/rancher/k3s/k3s.yaml 2>/dev/null || true
rm -rf /run/k3s 2>/dev/null || true
rm -rf /var/lib/rancher/k3s/agent/client-* 2>/dev/null || true
rm -rf /var/lib/rancher/k3s/agent/etc 2>/dev/null || true
rm -rf /tmp/k3s-* 2>/dev/null || true
echo "K3s pre-initialization complete"
`

	if isDebian {
		if err := runChrootEnv(rootfsDir, debEnv, "sh", "-c", preRunScript); err != nil {
			buildLog("Warning: K3s pre-run returned error (may be expected during shutdown): %v", err)
		}
	} else {
		if err := runChroot(rootfsDir, "sh", "-c", preRunScript); err != nil {
			buildLog("Warning: K3s pre-run returned error (may be expected during shutdown): %v", err)
		}
	}

	return nil
}

// installRtk downloads and installs the rtk binary from GitHub releases.
// It uses the pre-built musl binary (rtk-x86_64-unknown-linux-musl.tar.gz) for Linux amd64.
func installRtk(img *DiskImage, rootfsDir string, isDebian bool, debEnv []string) error {
	if img.RtkVersion == "" || img.RtkVersion == "none" {
		return nil
	}

	buildLog("Image build [%s v%s]: installing rtk %s", img.Name, img.OSVersion, img.RtkVersion)

	// Download URL for the pre-built musl binary.
	url := fmt.Sprintf("https://github.com/rtk-ai/rtk/releases/download/%s/rtk-x86_64-unknown-linux-musl.tar.gz", img.RtkVersion)

	// Download, extract, and install to /usr/local/bin.
	script := fmt.Sprintf(
		"wget -qO /tmp/rtk.tar.gz '%s' && "+
			"tar -xzf /tmp/rtk.tar.gz -C /tmp && "+
			"install -m 755 /tmp/rtk /usr/local/bin/rtk && "+
			"rm -f /tmp/rtk.tar.gz /tmp/rtk",
		url,
	)

	if isDebian {
		if err := runChrootEnv(rootfsDir, debEnv, "sh", "-c", script); err != nil {
			return fmt.Errorf("install rtk %s: %w", img.RtkVersion, err)
		}
	} else {
		if err := runChroot(rootfsDir, "sh", "-c", script); err != nil {
			return fmt.Errorf("install rtk %s: %w", img.RtkVersion, err)
		}
	}

	return nil
}

func debianCodename(version string) string {
	switch version {
	case "13":
		return "trixie"
	case "12":
		return "bookworm"
	case "11":
		return "bullseye"
	default:
		return "trixie"
	}
}

func ubuntuCodename(version string) string {
	switch version {
	case "24.04":
		return "noble"
	case "22.04":
		return "jammy"
	case "20.04":
		return "focal"
	default:
		return "noble"
	}
}
