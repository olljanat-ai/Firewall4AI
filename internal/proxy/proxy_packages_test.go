package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

func TestProxy_HTTPPackageRepoDetection(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}

	// Pre-approve the package so the request goes through.
	p.PackageApprovals.Check("debian:curl", "", "", "")
	p.PackageApprovals.Decide("debian:curl", "", "", "", approval.StatusApproved, "ok")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request a Debian package .deb file via plain HTTP.
	req := httptest.NewRequest("GET", backend.URL+"/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", nil)
	req.Host = "deb.debian.org"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for approved Debian package via HTTP, got %d", w.Code)
	}
}

func TestProxy_HTTPPackageRepoDetection_Unapproved(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}

	// Request a Debian package without approval — times out waiting → 407.
	req := httptest.NewRequest("GET", "http://deb.debian.org/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for unapproved Debian package via HTTP, got %d", w.Code)
	}
}

func TestProxy_HTTPPackageRepoMetadata_AutoApproved(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Metadata request (InRelease) — should be auto-approved without package approval.
	req := httptest.NewRequest("GET", backend.URL+"/debian/dists/bookworm/InRelease", nil)
	req.Host = "deb.debian.org"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for auto-approved Debian metadata via HTTP, got %d", w.Code)
	}
}

func TestProxy_LearningMode_Package(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.PackageApprovals = approval.NewManager()
	p.OSPackages = []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org"}},
	}
	p.SetLearningMode(true)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request a Debian package without explicit approval — learning mode should allow it.
	req := httptest.NewRequest("GET", backend.URL+"/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", nil)
	req.Host = "deb.debian.org"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("learning mode package: expected 200, got %d", w.Code)
	}

	// Verify the package shows as pending.
	pending := p.PackageApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "debian:curl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending approval for debian:curl")
	}
}

func TestProxy_LearningMode_Library(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.LibraryApprovals = approval.NewManager()
	p.CodeLibraries = []config.PackageRepoConfig{
		{Name: "Go Proxy", Type: "golang", Hosts: []string{"proxy.golang.org"}},
	}
	p.SetLearningMode(true)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Request a Go module without explicit approval — learning mode should allow it.
	req := httptest.NewRequest("GET", backend.URL+"/github.com/gorilla/mux/@v/v1.8.0.mod", nil)
	req.Host = "proxy.golang.org"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("learning mode library: expected 200, got %d", w.Code)
	}

	// Verify the library shows as pending.
	pending := p.LibraryApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "golang:github.com/gorilla/mux" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending approval for golang:github.com/gorilla/mux")
	}
}
