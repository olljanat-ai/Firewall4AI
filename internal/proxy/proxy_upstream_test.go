package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUpstreamUntrustedCertificateAllowed verifies that a request to an
// upstream server whose certificate is not signed by a trusted CA (internal
// PKI, self-signed appliances) is forwarded instead of failing with
// "x509: certificate signed by unknown authority".
func TestUpstreamUntrustedCertificateAllowed(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer backend.Close()

	p, _, approvals := setupProxy(t)
	approvals.Decide("127.0.0.1", "", "", "", StatusApproved, "test")

	req, err := http.NewRequest("GET", backend.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	resp, _ := p.processRequest(req, "10.255.255.10")
	if resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 from upstream with untrusted certificate, got %d: %s", resp.StatusCode, body)
	}

	// The untrusted certificate must still be visible in the logs.
	var found bool
	for _, e := range p.Logger.Recent(0) {
		if strings.Contains(e.Detail, "untrusted upstream certificate accepted") {
			found = true
		}
	}
	if !found {
		t.Error("expected a log entry about the untrusted upstream certificate")
	}
}

func TestVerifyUpstreamCert(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	host := strings.TrimPrefix(backend.URL, "https://")
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test
	if err != nil {
		t.Fatalf("tls.Dial() error: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Self-signed test certificate: not trusted by the system store.
	if err := verifyUpstreamCert("127.0.0.1", state); err == nil {
		t.Error("verifyUpstreamCert() = nil for a self-signed certificate, want error")
	}

	// Hostname mismatch is reported as well.
	if err := verifyUpstreamCert("other.example.org", state); err == nil {
		t.Error("verifyUpstreamCert() = nil for a mismatched hostname, want error")
	}

	// A connection without any peer certificate is an error, not a panic.
	if err := verifyUpstreamCert("127.0.0.1", tls.ConnectionState{}); err == nil {
		t.Error("verifyUpstreamCert() = nil for a missing certificate, want error")
	}
}
