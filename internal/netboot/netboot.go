// Package netboot manages network boot files and installer configurations
// for Alpine Linux, Debian, and Ubuntu agent VMs.
package netboot

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

// NetbootURLs contains download URLs for a given OS version's netboot files.
type NetbootURLs struct {
	Kernel string
	Initrd string
}

// Manager handles netboot file downloads and installer config generation.
type Manager struct {
	DataDir   string // e.g., /var/lib/firewall4ai
	ServerIP  string // e.g., 10.255.255.1

	mu sync.RWMutex
}

// NewManager creates a new netboot manager.
func NewManager(dataDir, serverIP string) *Manager {
	return &Manager{
		DataDir:  dataDir,
		ServerIP: serverIP,
	}
}

// BootDir returns the path where netboot files are stored.
func (m *Manager) BootDir() string {
	return filepath.Join(m.DataDir, "netboot")
}

// OSDir returns the path for a specific OS/version's boot files.
func (m *Manager) OSDir(osType agent.OSType, version string) string {
	return filepath.Join(m.BootDir(), string(osType), version)
}

// TFTPDir returns the path for TFTP-served files (iPXE bootloaders).
func (m *Manager) TFTPDir() string {
	return filepath.Join(m.BootDir(), "tftp")
}

// EnsureTFTPDir creates the TFTP directory structure.
func (m *Manager) EnsureTFTPDir() error {
	return os.MkdirAll(m.TFTPDir(), 0o755)
}

// GetNetbootURLs returns download URLs for the given OS type and version.
func GetNetbootURLs(osType agent.OSType, version string) NetbootURLs {
	switch osType {
	case agent.OSAlpine:
		return NetbootURLs{
			Kernel: fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/netboot/vmlinuz-lts", version),
			Initrd: fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/netboot/initramfs-lts", version),
		}
	case agent.OSDebian:
		codename := debianCodename(version)
		return NetbootURLs{
			Kernel: fmt.Sprintf("https://deb.debian.org/debian/dists/%s/main/installer-amd64/current/images/netboot/debian-installer/amd64/linux", codename),
			Initrd: fmt.Sprintf("https://deb.debian.org/debian/dists/%s/main/installer-amd64/current/images/netboot/debian-installer/amd64/initrd.gz", codename),
		}
	case agent.OSUbuntu:
		codename := ubuntuCodename(version)
		return NetbootURLs{
			Kernel: fmt.Sprintf("https://archive.ubuntu.com/ubuntu/dists/%s/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/linux", codename),
			Initrd: fmt.Sprintf("https://archive.ubuntu.com/ubuntu/dists/%s/main/installer-amd64/current/legacy-images/netboot/ubuntu-installer/amd64/initrd.gz", codename),
		}
	}
	return NetbootURLs{}
}

// DownloadBootFiles downloads kernel and initrd for the given OS.
func (m *Manager) DownloadBootFiles(a *agent.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir := m.OSDir(a.OS, a.OSVersion)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create boot dir: %w", err)
	}

	urls := GetNetbootURLs(a.OS, a.OSVersion)

	// Check if files already exist.
	kernelPath := filepath.Join(dir, "kernel")
	initrdPath := filepath.Join(dir, "initrd")

	if fileExists(kernelPath) && fileExists(initrdPath) {
		log.Printf("Netboot files already cached for %s %s", a.OS, a.OSVersion)
		return nil
	}

	log.Printf("Downloading netboot files for %s %s...", a.OS, a.OSVersion)

	if err := downloadFile(urls.Kernel, kernelPath); err != nil {
		return fmt.Errorf("download kernel: %w", err)
	}
	if err := downloadFile(urls.Initrd, initrdPath); err != nil {
		return fmt.Errorf("download initrd: %w", err)
	}

	log.Printf("Netboot files ready for %s %s", a.OS, a.OSVersion)
	return nil
}

// HasBootFiles checks if boot files are already downloaded for the OS.
func (m *Manager) HasBootFiles(osType agent.OSType, version string) bool {
	dir := m.OSDir(osType, version)
	return fileExists(filepath.Join(dir, "kernel")) && fileExists(filepath.Join(dir, "initrd"))
}

// GenerateIPXEScript generates an iPXE boot script for an agent.
func (m *Manager) GenerateIPXEScript(a *agent.Agent) string {
	var sb strings.Builder
	sb.WriteString("#!ipxe\n\n")

	kernelURL := fmt.Sprintf("http://%s/boot/%s/%s/kernel", m.ServerIP, a.OS, a.OSVersion)
	initrdURL := fmt.Sprintf("http://%s/boot/%s/%s/initrd", m.ServerIP, a.OS, a.OSVersion)

	switch a.OS {
	case agent.OSAlpine:
		sb.WriteString(fmt.Sprintf("kernel %s alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v%s/main/ modloop=http://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/netboot/modloop-lts ip=dhcp autoinstall=http://%s/boot/autoinstall/%s\n",
			kernelURL, a.OSVersion, a.OSVersion, m.ServerIP, a.ID))
		sb.WriteString(fmt.Sprintf("initrd %s\n", initrdURL))

	case agent.OSDebian:
		sb.WriteString(fmt.Sprintf("kernel %s auto=true priority=critical url=http://%s/boot/preseed/%s interface=auto netcfg/dhcp_timeout=60\n",
			kernelURL, m.ServerIP, a.ID))
		sb.WriteString(fmt.Sprintf("initrd %s\n", initrdURL))

	case agent.OSUbuntu:
		sb.WriteString(fmt.Sprintf("kernel %s auto=true priority=critical url=http://%s/boot/preseed/%s interface=auto netcfg/dhcp_timeout=60\n",
			kernelURL, m.ServerIP, a.ID))
		sb.WriteString(fmt.Sprintf("initrd %s\n", initrdURL))
	}

	sb.WriteString("boot\n")
	return sb.String()
}

// GeneratePreseed generates a Debian/Ubuntu preseed file for automated installation.
func (m *Manager) GeneratePreseed(a *agent.Agent) string {
	var sb strings.Builder

	mirror := "deb.debian.org"
	suite := debianCodename(a.OSVersion)
	if a.OS == agent.OSUbuntu {
		mirror = "archive.ubuntu.com"
		suite = ubuntuCodename(a.OSVersion)
	}

	sb.WriteString("# Automated installation preseed\n")
	sb.WriteString("d-i debian-installer/locale string en_US.UTF-8\n")
	sb.WriteString("d-i keyboard-configuration/xkb-keymap select us\n")
	sb.WriteString("\n# Network\n")
	sb.WriteString("d-i netcfg/choose_interface select auto\n")
	sb.WriteString("d-i netcfg/get_hostname string " + a.Hostname + "\n")
	sb.WriteString("d-i netcfg/get_domain string local\n")
	sb.WriteString("\n# Mirror\n")
	if a.OS == agent.OSUbuntu {
		sb.WriteString("d-i mirror/country string US\n")
		sb.WriteString("d-i mirror/http/hostname string " + mirror + "\n")
		sb.WriteString("d-i mirror/http/directory string /ubuntu\n")
	} else {
		sb.WriteString("d-i mirror/country string manual\n")
		sb.WriteString("d-i mirror/http/hostname string " + mirror + "\n")
		sb.WriteString("d-i mirror/http/directory string /debian\n")
	}
	sb.WriteString("d-i mirror/http/proxy string http://" + m.ServerIP + ":8080\n")
	sb.WriteString("d-i mirror/suite string " + suite + "\n")

	sb.WriteString("\n# Clock\n")
	sb.WriteString("d-i clock-setup/utc boolean true\n")
	sb.WriteString("d-i time/zone string UTC\n")
	sb.WriteString("d-i clock-setup/ntp boolean true\n")

	// Partitioning - single disk, entire disk.
	disk := a.DiskDevice
	if disk == "" {
		disk = agent.DefaultDiskDevice()
	}
	sb.WriteString("\n# Partitioning\n")
	sb.WriteString("d-i partman-auto/method string regular\n")
	sb.WriteString("d-i partman-auto/disk string " + disk + "\n")
	sb.WriteString("d-i partman-auto/choose_recipe select atomic\n")
	sb.WriteString("d-i partman-partitioning/confirm_write_new_label boolean true\n")
	sb.WriteString("d-i partman/choose_partition select finish\n")
	sb.WriteString("d-i partman/confirm boolean true\n")
	sb.WriteString("d-i partman/confirm_nooverwrite boolean true\n")

	// Root account.
	sb.WriteString("\n# Account setup - root only\n")
	sb.WriteString("d-i passwd/root-login boolean true\n")
	sb.WriteString("d-i passwd/make-user boolean false\n")
	sb.WriteString("d-i passwd/root-password password root\n")
	sb.WriteString("d-i passwd/root-password-again password root\n")

	// Package selection.
	sb.WriteString("\n# Package selection\n")
	sb.WriteString("tasksel tasksel/first multiselect standard\n")
	if len(a.Packages) > 0 {
		sb.WriteString("d-i pkgsel/include string " + strings.Join(a.Packages, " ") + "\n")
	}
	sb.WriteString("d-i pkgsel/upgrade select full-upgrade\n")

	// GRUB.
	sb.WriteString("\n# GRUB\n")
	sb.WriteString("d-i grub-installer/only_debian boolean true\n")
	sb.WriteString("d-i grub-installer/bootdev string " + disk + "\n")

	// Finish.
	sb.WriteString("\n# Finish\n")
	sb.WriteString("d-i finish-install/reboot_in_progress note\n")

	// Late command: enable auto-login, inject CA cert, configure proxy, ensure ca-certificates
	sb.WriteString("\n# Post-install (CA + proxy + auto-login)\n")
	sb.WriteString("d-i preseed/late_command string \\\n")
	sb.WriteString(" in-target apt-get update ; \\\n")
	sb.WriteString(" in-target apt-get install -y ca-certificates ; \\\n")
	sb.WriteString(" in-target wget -qO /usr/local/share/ca-certificates/firewall4ai-ca.crt http://" + m.ServerIP + "/ca.crt ; \\\n")
	sb.WriteString(" in-target update-ca-certificates ; \\\n")
	sb.WriteString("  in-target mkdir -p /etc/systemd/system/getty@tty1.service.d ; \\\n")
	sb.WriteString("  printf '[Service]\\nExecStart=\\nExecStart=-/sbin/agetty --autologin root --noclear %%I $TERM\\n' > /target/etc/systemd/system/getty@tty1.service.d/override.conf ; \\\n")
	sb.WriteString("  in-target systemctl enable getty@tty1.service\n")

	return sb.String()
}

// GenerateAlpineAnswerFile generates an Alpine Linux answer file for setup-alpine.
func (m *Manager) GenerateAlpineAnswerFile(a *agent.Agent) string {
	var sb strings.Builder

	disk := a.DiskDevice
	if disk == "" {
		disk = agent.DefaultDiskDevice()
	}

	sb.WriteString("# Alpine Linux automated installation\n")
	sb.WriteString("KEYMAPOPTS=\"us us\"\n")
	sb.WriteString("HOSTNAMEOPTS=\"-n " + a.Hostname + "\"\n")
	sb.WriteString("INTERFACESOPTS=\"auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\"\n")
	sb.WriteString("DNSOPTS=\"-d local " + m.ServerIP + "\"\n")
	sb.WriteString("TIMEZONEOPTS=\"-z UTC\"\n")
	sb.WriteString("PROXYOPTS=\"http://" + m.ServerIP + ":8080\"\n")
	sb.WriteString("APKREPOSOPTS=\"http://dl-cdn.alpinelinux.org/alpine/v" + a.OSVersion + "/main http://dl-cdn.alpinelinux.org/alpine/v" + a.OSVersion + "/community\"\n")
	sb.WriteString("SSHDOPTS=\"-c openssh\"\n")
	sb.WriteString("NTPOPTS=\"-c busybox\"\n")
	sb.WriteString("DISKOPTS=\"-m sys " + disk + "\"\n")
	sb.WriteString("LABOROPTS=\"none\"\n")
	sb.WriteString("USEROPTS=\"none\"\n")

	// Root password: set to 'root'.
	sb.WriteString("\n# Root password\n")
	sb.WriteString("ROOTPASSOPTS=\"-a root\"\n")

	// Extra packages.
	if len(a.Packages) > 0 {
		sb.WriteString("\n# Extra packages\n")
		sb.WriteString("apk add --no-cache " + strings.Join(a.Packages, " ") + " \n")
	} else {
		sb.WriteString("\n# Extra packages\n")
		sb.WriteString("apk add --no-cache ca-certificates\n")
	}

	return sb.String()
}

// GeneratePostInstallScript generates a post-installation script.
func (m *Manager) GeneratePostInstallScript(a *agent.Agent) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	sb.WriteString("# Post-installation configuration\n\n")

	switch a.OS {
	case agent.OSAlpine:
		// Enable auto-login on tty1.
		sb.WriteString("# Enable auto-login\n")
		sb.WriteString("sed -i 's|^tty1::.*|tty1::respawn:/sbin/getty -L -n -l /bin/sh 0 tty1 vt100|' /etc/inittab\n")
		// Install extra packages.
		if len(a.Packages) > 0 {
			sb.WriteString("\n# Install extra packages\n")
			sb.WriteString("apk add " + strings.Join(a.Packages, " ") + "\n")
		}
	case agent.OSDebian, agent.OSUbuntu:
		// Auto-login is configured via preseed late_command.
		if len(a.Packages) > 0 {
			sb.WriteString("\n# Install extra packages\n")
			sb.WriteString("apt-get update && apt-get install -y " + strings.Join(a.Packages, " ") + "\n")
		}
	}

	return sb.String()
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
