package image

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

// BuildImage builds a new version of a disk image by creating a rootfs tarball.
// This runs as a long-running operation and should be called in a goroutine.
// The serverIP is the firewall's agent-facing IP (e.g., 10.255.255.1).
func (m *Manager) BuildImage(img *DiskImage, version int, serverIP string) error {
	versionDir := m.VersionDir(img.ID, version)
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		return fmt.Errorf("create version dir: %w", err)
	}

	rootfsPath := filepath.Join(versionDir, "rootfs.tar.gz")

	switch img.OS {
	case agent.OSAlpine:
		return m.buildAlpine(img, rootfsPath, serverIP)
	case agent.OSDebian:
		return m.buildDebian(img, rootfsPath, serverIP, "debian")
	case agent.OSUbuntu:
		return m.buildDebian(img, rootfsPath, serverIP, "ubuntu")
	default:
		return fmt.Errorf("unsupported OS type: %s", img.OS)
	}
}

// buildAlpine builds an Alpine Linux rootfs tarball.
func (m *Manager) buildAlpine(img *DiskImage, rootfsPath, serverIP string) error {
	// Download Alpine minirootfs.
	minirootfsURL := fmt.Sprintf("https://dl-cdn.alpinelinux.org/alpine/v%s/releases/x86_64/alpine-minirootfs-%s.0-x86_64.tar.gz",
		img.OSVersion, img.OSVersion)

	tmpDir, err := os.MkdirTemp("", "fw4ai-build-alpine-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootfsDir := filepath.Join(tmpDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return fmt.Errorf("create rootfs dir: %w", err)
	}

	// Download and extract minirootfs.
	log.Printf("Image build [%s v%s]: downloading Alpine minirootfs", img.Name, img.OSVersion)
	minirootfs := filepath.Join(tmpDir, "minirootfs.tar.gz")
	if err := downloadFile(minirootfsURL, minirootfs); err != nil {
		return fmt.Errorf("download minirootfs: %w", err)
	}

	if err := run("tar", "xzf", minirootfs, "-C", rootfsDir); err != nil {
		return fmt.Errorf("extract minirootfs: %w", err)
	}

	// Setup resolv.conf for DNS in chroot.
	if err := os.WriteFile(filepath.Join(rootfsDir, "etc/resolv.conf"), []byte("nameserver 1.1.1.1\nnameserver 1.0.0.1\n"), 0o644); err != nil {
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
			log.Printf("Warning: mount %s failed: %v", mnt.fstype, err)
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
	log.Printf("Image build [%s v%s]: installing packages", img.Name, img.OSVersion)
	basePkgs := []string{"linux-virt", "syslinux", "e2fsprogs", "openrc", "alpine-base", "ca-certificates"}
	allPkgs := append(basePkgs, img.Packages...)

	if err := runChroot(rootfsDir, "apk", append([]string{"update"})...); err != nil {
		return fmt.Errorf("apk update: %w", err)
	}
	if err := runChroot(rootfsDir, "apk", append([]string{"add"}, allPkgs...)...); err != nil {
		return fmt.Errorf("apk add: %w", err)
	}

	// Configure the system.
	log.Printf("Image build [%s v%s]: configuring system", img.Name, img.OSVersion)

	// fstab
	fstab := "/dev/sda1\t/\text4\tdefaults,noatime\t0\t1\n"
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

	// Proxy configuration.
	proxyConf := fmt.Sprintf("export http_proxy=http://%s:8080\nexport https_proxy=http://%s:8080\n", serverIP, serverIP)
	os.WriteFile(filepath.Join(rootfsDir, "etc/profile.d/proxy.sh"), []byte(proxyConf), 0o644)

	// Root password: set to 'root'.
	runChroot(rootfsDir, "sh", "-c", "echo 'root:root' | chpasswd")

	// Enable networking services.
	runChroot(rootfsDir, "rc-update", "add", "networking", "boot")
	runChroot(rootfsDir, "rc-update", "add", "hostname", "boot")

	// Bootloader config (extlinux).
	os.MkdirAll(filepath.Join(rootfsDir, "boot"), 0o755)
	// Find the kernel version.
	kernelGlob, _ := filepath.Glob(filepath.Join(rootfsDir, "boot/vmlinuz-*"))
	kernelFile := "vmlinuz-virt"
	initrdFile := "initramfs-virt"
	if len(kernelGlob) > 0 {
		kernelFile = filepath.Base(kernelGlob[0])
		// Derive initramfs name from kernel name.
		initrdFile = strings.Replace(kernelFile, "vmlinuz-", "initramfs-", 1)
	}

	extlinuxConf := fmt.Sprintf(`DEFAULT alpine
LABEL alpine
  LINUX /boot/%s
  INITRD /boot/%s
  APPEND root=/dev/sda1 modules=ext4 quiet
`, kernelFile, initrdFile)
	os.WriteFile(filepath.Join(rootfsDir, "boot/extlinux.conf"), []byte(extlinuxConf), 0o644)

	// Run custom scripts.
	for i, script := range img.Scripts {
		log.Printf("Image build [%s v%s]: running custom script %d", img.Name, img.OSVersion, i+1)
		if err := runChroot(rootfsDir, "sh", "-c", script); err != nil {
			return fmt.Errorf("custom script %d: %w", i+1, err)
		}
	}

	// Create rootfs tarball.
	log.Printf("Image build [%s v%s]: creating rootfs tarball", img.Name, img.OSVersion)

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

	log.Printf("Image build [%s v%s]: build complete", img.Name, img.OSVersion)
	return nil
}

// buildDebian builds a Debian or Ubuntu rootfs tarball using debootstrap.
func (m *Manager) buildDebian(img *DiskImage, rootfsPath, serverIP, distro string) error {
	codename := debianCodename(img.OSVersion)
	mirror := "http://deb.debian.org/debian"
	if distro == "ubuntu" {
		codename = ubuntuCodename(img.OSVersion)
		mirror = "http://archive.ubuntu.com/ubuntu"
	}

	tmpDir, err := os.MkdirTemp("", "fw4ai-build-debian-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootfsDir := filepath.Join(tmpDir, "rootfs")

	// Run debootstrap.
	log.Printf("Image build [%s v%s]: running debootstrap (%s %s)", img.Name, img.OSVersion, codename, mirror)
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

	// Install kernel + bootloader + packages.
	log.Printf("Image build [%s v%s]: installing packages", img.Name, img.OSVersion)

	// Set DEBIAN_FRONTEND to avoid interactive prompts.
	debEnv := []string{"DEBIAN_FRONTEND=noninteractive"}

	basePkgs := []string{"linux-image-amd64", "extlinux", "syslinux-common", "ca-certificates", "systemd-sysv", "ifupdown"}
	allPkgs := append(basePkgs, img.Packages...)

	if err := runChrootEnv(rootfsDir, debEnv, "apt-get", "update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	if err := runChrootEnv(rootfsDir, debEnv, "apt-get", append([]string{"install", "-y"}, allPkgs...)...); err != nil {
		return fmt.Errorf("apt-get install: %w", err)
	}

	// Configure the system.
	log.Printf("Image build [%s v%s]: configuring system", img.Name, img.OSVersion)

	// fstab.
	fstab := "/dev/sda1\t/\text4\tdefaults,noatime\t0\t1\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/fstab"), []byte(fstab), 0o644)

	// Auto-login on tty1 via systemd.
	overrideDir := filepath.Join(rootfsDir, "etc/systemd/system/getty@tty1.service.d")
	os.MkdirAll(overrideDir, 0o755)
	override := "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %I $TERM\n"
	os.WriteFile(filepath.Join(overrideDir, "override.conf"), []byte(override), 0o644)

	// Network: auto eth0 via DHCP.
	interfaces := "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n"
	os.WriteFile(filepath.Join(rootfsDir, "etc/network/interfaces"), []byte(interfaces), 0o644)

	// Proxy configuration.
	proxyConf := fmt.Sprintf("export http_proxy=http://%s:8080\nexport https_proxy=http://%s:8080\n", serverIP, serverIP)
	os.WriteFile(filepath.Join(rootfsDir, "etc/profile.d/proxy.sh"), []byte(proxyConf), 0o644)

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
  APPEND root=/dev/sda1 ro quiet
`, kernelFile, initrdFile)
	os.WriteFile(filepath.Join(rootfsDir, "boot/extlinux.conf"), []byte(extlinuxConf), 0o644)

	// Run custom scripts.
	for i, script := range img.Scripts {
		log.Printf("Image build [%s v%s]: running custom script %d", img.Name, img.OSVersion, i+1)
		if err := runChrootEnv(rootfsDir, debEnv, "sh", "-c", script); err != nil {
			return fmt.Errorf("custom script %d: %w", i+1, err)
		}
	}

	// Export kernel + initrd for netboot/kexec use.
	log.Printf("Image build [%s v%s]: exporting kernel and initrd for netboot", img.Name, img.OSVersion)
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
	log.Printf("Image build [%s v%s]: creating rootfs tarball", img.Name, img.OSVersion)

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

	log.Printf("Image build [%s v%s]: build complete", img.Name, img.OSVersion)
	return nil
}

// run executes a command and returns an error if it fails.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runChroot runs a command inside a chroot.
func runChroot(rootfs, name string, args ...string) error {
	chrootArgs := append([]string{rootfs, name}, args...)
	cmd := exec.Command("chroot", chrootArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runChrootEnv runs a command inside a chroot with extra environment variables.
func runChrootEnv(rootfs string, env []string, name string, args ...string) error {
	// Use env to set variables, then chroot.
	// Build: env VAR1=val1 VAR2=val2 chroot rootfs name args...
	envArgs := append(env, "chroot", rootfs, name)
	envArgs = append(envArgs, args...)
	cmd := exec.Command("env", envArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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
