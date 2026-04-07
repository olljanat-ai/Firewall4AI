package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

func TestProxy_HelmChart_CertManager_Approved(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chart data"))
	}))
	defer backend.Close()

	p, _, _ := setupProxy(t)
	p.HelmChartApprovals = approval.NewManager()
	p.HelmRepos = []config.PackageRepoConfig{
		{Name: "Jetstack", Type: "helm", Hosts: []string{"charts.jetstack.io"}},
	}
	backendURL, _ := url.Parse(backend.URL)
	p.Transport = &testRedirectTransport{inner: backend.Client().Transport, targetHost: backendURL.Host}

	// Pre-approve cert-manager from Jetstack repo.
	p.HelmChartApprovals.Decide("helm:charts.jetstack.io/cert-manager", "", "", "", approval.StatusApproved, "")

	req, _ := http.NewRequest("GET", "https://charts.jetstack.io:443/charts/cert-manager-v1.16.2.tgz", nil)
	req.Host = "charts.jetstack.io"
	req.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(req, "10.0.0.1")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("approved cert-manager chart should return 200, got %d", resp.StatusCode)
	}
}

func TestProxy_HelmChart_CertManager_Denied(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.HelmChartApprovals = approval.NewManager()
	p.HelmRepos = []config.PackageRepoConfig{
		{Name: "Jetstack", Type: "helm", Hosts: []string{"charts.jetstack.io"}},
	}

	req, _ := http.NewRequest("GET", "https://charts.jetstack.io:443/charts/cert-manager-v1.16.2.tgz", nil)
	req.Host = "charts.jetstack.io"
	req.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(req, "10.0.0.1")

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("unapproved cert-manager chart should return 407 (pending timeout), got %d", resp.StatusCode)
	}

	// Verify pending entry was created.
	pending := p.HelmChartApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "helm:charts.jetstack.io/cert-manager" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected pending helm chart approval for helm:charts.jetstack.io/cert-manager")
	}
}

func TestProxy_HelmChart_IndexYaml_CreatesRepoEntry(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.HelmChartApprovals = approval.NewManager()
	p.HelmRepos = []config.PackageRepoConfig{
		{Name: "Jetstack", Type: "helm", Hosts: []string{"charts.jetstack.io"}},
	}

	req, _ := http.NewRequest("GET", "https://charts.jetstack.io:443/index.yaml", nil)
	req.Host = "charts.jetstack.io"
	req.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(req, "10.0.0.1")

	// index.yaml creates a pending repo-level entry (no longer auto-approved).
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("index.yaml should create pending entry and return 407, got %d", resp.StatusCode)
	}

	// Verify pending entry was created for the repo.
	pending := p.HelmChartApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "helm:charts.jetstack.io" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected pending helm chart approval for helm:charts.jetstack.io")
	}
}

func TestProxy_HelmChart_IndexYaml_ApprovedRepo(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("index data"))
	}))
	defer backend.Close()

	p, _, _ := setupProxy(t)
	p.HelmChartApprovals = approval.NewManager()
	p.HelmRepos = []config.PackageRepoConfig{
		{Name: "Jetstack", Type: "helm", Hosts: []string{"charts.jetstack.io"}},
	}
	backendURL, _ := url.Parse(backend.URL)
	p.Transport = &testRedirectTransport{inner: backend.Client().Transport, targetHost: backendURL.Host}

	// Pre-approve the repo.
	p.HelmChartApprovals.Decide("helm:charts.jetstack.io", "", "", "", approval.StatusApproved, "")

	req, _ := http.NewRequest("GET", "https://charts.jetstack.io:443/index.yaml", nil)
	req.Host = "charts.jetstack.io"
	req.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(req, "10.0.0.1")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("approved repo index.yaml should return 200, got %d", resp.StatusCode)
	}
}

func TestProxy_HelmChart_RepoApproval_CoversCharts(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chart data"))
	}))
	defer backend.Close()

	p, _, _ := setupProxy(t)
	p.HelmChartApprovals = approval.NewManager()
	p.HelmRepos = []config.PackageRepoConfig{
		{Name: "Jetstack", Type: "helm", Hosts: []string{"charts.jetstack.io"}},
	}
	backendURL, _ := url.Parse(backend.URL)
	p.Transport = &testRedirectTransport{inner: backend.Client().Transport, targetHost: backendURL.Host}

	// Approve the repo — this should cover all charts from it.
	p.HelmChartApprovals.Decide("helm:charts.jetstack.io", "", "", "", approval.StatusApproved, "")

	req, _ := http.NewRequest("GET", "https://charts.jetstack.io:443/charts/cert-manager-v1.16.2.tgz", nil)
	req.Host = "charts.jetstack.io"
	req.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(req, "10.0.0.1")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("chart from approved repo should return 200, got %d", resp.StatusCode)
	}
}

func TestProxy_HelmChart_LearningMode_CertManager(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("chart data"))
	}))
	defer backend.Close()

	p, _, _ := setupProxy(t)
	p.HelmChartApprovals = approval.NewManager()
	p.HelmRepos = []config.PackageRepoConfig{
		{Name: "Jetstack", Type: "helm", Hosts: []string{"charts.jetstack.io"}},
	}
	p.LearningMode = true
	backendURL, _ := url.Parse(backend.URL)
	p.Transport = &testRedirectTransport{inner: backend.Client().Transport, targetHost: backendURL.Host}

	req, _ := http.NewRequest("GET", "https://charts.jetstack.io:443/charts/cert-manager-v1.14.0.tgz", nil)
	req.Host = "charts.jetstack.io"
	req.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(req, "10.0.0.1")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("learning mode: cert-manager chart should be allowed, got %d", resp.StatusCode)
	}

	// Verify pending entry was created for tracking.
	pending := p.HelmChartApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "helm:charts.jetstack.io/cert-manager" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending helm chart approval for helm:charts.jetstack.io/cert-manager")
	}
}

func TestMatchHelmRef(t *testing.T) {
	tests := []struct {
		pattern string
		ref     string
		want    bool
	}{
		// Exact match.
		{"helm:charts.jetstack.io/cert-manager", "helm:charts.jetstack.io/cert-manager", true},
		{"helm:charts.jetstack.io", "helm:charts.jetstack.io", true},
		// Wildcard.
		{"helm:charts.jetstack.io/*", "helm:charts.jetstack.io/cert-manager", true},
		{"helm:charts.jetstack.io/*", "helm:charts.jetstack.io/nginx", true},
		{"helm:charts.jetstack.io/*", "helm:charts.bitnami.com/nginx", false},
		// Repo-level covers charts.
		{"helm:charts.jetstack.io", "helm:charts.jetstack.io/cert-manager", true},
		{"helm:charts.jetstack.io", "helm:charts.bitnami.com/nginx", false},
		// Chart doesn't cover repo.
		{"helm:charts.jetstack.io/cert-manager", "helm:charts.jetstack.io", false},
		// No match.
		{"helm:charts.jetstack.io/cert-manager", "helm:charts.jetstack.io/nginx", false},
	}
	for _, tt := range tests {
		got := matchHelmRef(tt.pattern, tt.ref)
		if got != tt.want {
			t.Errorf("matchHelmRef(%q, %q) = %v, want %v", tt.pattern, tt.ref, got, tt.want)
		}
	}
}
