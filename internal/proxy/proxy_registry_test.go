package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

func TestProxy_LearningMode_RegistryBlob(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("blob data"))
	}))
	defer backend.Close()

	p, _, _ := setupProxy(t)
	p.ImageApprovals = approval.NewManager()
	p.Registries = []config.RegistryConfig{
		{Name: "test-registry", Hosts: []string{"registry.example.com"}},
	}
	p.LearningMode = true
	p.Transport = backend.Client().Transport

	blobReq, _ := http.NewRequest("GET", "https://registry.example.com:443/v2/myapp/blobs/sha256:abc123", nil)
	blobReq.Host = "registry.example.com"
	blobReq.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(blobReq, "10.0.0.1")

	if resp.StatusCode == http.StatusForbidden {
		t.Error("learning mode: blob request should not be denied (got 403)")
	}

	// Verify a pending image approval was created.
	pending := p.ImageApprovals.ListPending()
	found := false
	for _, a := range pending {
		if a.Host == "test-registry/myapp" {
			found = true
			break
		}
	}
	if !found {
		t.Error("learning mode: expected pending image approval for test-registry/myapp")
	}
}

func TestProxy_LearningMode_RegistryBlob_DeniedWhenOff(t *testing.T) {
	p, _, _ := setupProxy(t)
	p.ImageApprovals = approval.NewManager()
	p.Registries = []config.RegistryConfig{
		{Name: "test-registry", Hosts: []string{"registry.example.com"}},
	}
	p.LearningMode = false // default-deny

	blobReq, _ := http.NewRequest("GET", "https://registry.example.com:443/v2/myapp/blobs/sha256:abc123", nil)
	blobReq.Host = "registry.example.com"
	blobReq.RemoteAddr = "10.0.0.1:12345"

	resp, _ := p.processRequest(blobReq, "10.0.0.1")

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("default-deny: blob request should be denied, got %d", resp.StatusCode)
	}
}
