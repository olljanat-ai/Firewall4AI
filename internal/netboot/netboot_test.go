package netboot

import (
	"strings"
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

func TestGetNetbootURLsAlpine(t *testing.T) {
	urls := GetNetbootURLs(agent.OSAlpine, "3.23")
	if !strings.Contains(urls.Kernel, "alpine") || !strings.Contains(urls.Kernel, "3.23") {
		t.Fatalf("unexpected kernel URL: %s", urls.Kernel)
	}
	if !strings.Contains(urls.Initrd, "alpine") || !strings.Contains(urls.Initrd, "3.23") {
		t.Fatalf("unexpected initrd URL: %s", urls.Initrd)
	}
}

func TestGetNetbootURLsDebian(t *testing.T) {
	urls := GetNetbootURLs(agent.OSDebian, "13")
	if !strings.Contains(urls.Kernel, "trixie") {
		t.Fatalf("expected trixie in URL: %s", urls.Kernel)
	}
}

func TestGetNetbootURLsUbuntu(t *testing.T) {
	urls := GetNetbootURLs(agent.OSUbuntu, "24.04")
	if !strings.Contains(urls.Kernel, "noble") {
		t.Fatalf("expected noble in URL: %s", urls.Kernel)
	}
}

func TestGenerateIPXEScriptAlpine(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")
	a := &agent.Agent{
		ID:        "a1",
		Hostname:  "agent1",
		OS:        agent.OSAlpine,
		OSVersion: "3.23",
	}

	script := m.GenerateIPXEScript(a)
	if !strings.HasPrefix(script, "#!ipxe") {
		t.Fatal("missing iPXE shebang")
	}
	if !strings.Contains(script, "kernel") {
		t.Fatal("missing kernel line")
	}
	if !strings.Contains(script, "initrd") {
		t.Fatal("missing initrd line")
	}
	if !strings.Contains(script, "alpine_repo") {
		t.Fatal("missing alpine_repo parameter")
	}
	if !strings.Contains(script, "boot") {
		t.Fatal("missing boot command")
	}
}

func TestGenerateIPXEScriptDebian(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")
	a := &agent.Agent{
		ID:        "a1",
		Hostname:  "agent1",
		OS:        agent.OSDebian,
		OSVersion: "13",
	}

	script := m.GenerateIPXEScript(a)
	if !strings.Contains(script, "preseed") {
		t.Fatal("missing preseed URL")
	}
}

func TestGeneratePreseedDebian(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")
	a := &agent.Agent{
		ID:         "a1",
		Hostname:   "agent1",
		OS:         agent.OSDebian,
		OSVersion:  "13",
		DiskDevice: "/dev/sda",
		Packages:   []string{"curl", "vim"},
	}

	preseed := m.GeneratePreseed(a)
	if !strings.Contains(preseed, "agent1") {
		t.Fatal("missing hostname")
	}
	if !strings.Contains(preseed, "deb.debian.org") {
		t.Fatal("missing debian mirror")
	}
	if !strings.Contains(preseed, "/dev/sda") {
		t.Fatal("missing disk device")
	}
	if !strings.Contains(preseed, "curl vim") {
		t.Fatal("missing packages")
	}
	if !strings.Contains(preseed, "autologin root") {
		t.Fatal("missing auto-login setup")
	}
	if !strings.Contains(preseed, "root-login boolean true") {
		t.Fatal("missing root login")
	}
}

func TestGeneratePreseedUbuntu(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")
	a := &agent.Agent{
		ID:        "a1",
		Hostname:  "agent1",
		OS:        agent.OSUbuntu,
		OSVersion: "24.04",
	}

	preseed := m.GeneratePreseed(a)
	if !strings.Contains(preseed, "archive.ubuntu.com") {
		t.Fatal("missing ubuntu mirror")
	}
}

func TestGenerateAlpineAnswerFile(t *testing.T) {
	m := NewManager("/tmp/test", "10.255.255.1")
	a := &agent.Agent{
		ID:         "a1",
		Hostname:   "agent1",
		OS:         agent.OSAlpine,
		OSVersion:  "3.23",
		DiskDevice: "/dev/sda",
		Packages:   []string{"curl", "htop"},
	}

	answer := m.GenerateAlpineAnswerFile(a)
	if !strings.Contains(answer, "agent1") {
		t.Fatal("missing hostname")
	}
	if !strings.Contains(answer, "/dev/sda") {
		t.Fatal("missing disk device")
	}
	if !strings.Contains(answer, "3.23") {
		t.Fatal("missing version in repos")
	}
	if !strings.Contains(answer, "curl htop") {
		t.Fatal("missing packages")
	}
}

func TestDebianCodename(t *testing.T) {
	if c := debianCodename("13"); c != "trixie" {
		t.Fatalf("expected trixie, got %s", c)
	}
	if c := debianCodename("12"); c != "bookworm" {
		t.Fatalf("expected bookworm, got %s", c)
	}
}

func TestUbuntuCodename(t *testing.T) {
	if c := ubuntuCodename("24.04"); c != "noble" {
		t.Fatalf("expected noble, got %s", c)
	}
	if c := ubuntuCodename("22.04"); c != "jammy" {
		t.Fatalf("expected jammy, got %s", c)
	}
}
