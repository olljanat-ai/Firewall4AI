package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

// receivedRequest records how a request arrived at the upstream server.
type receivedRequest struct {
	transferEncoding []string
	header           string
	contentLength    int64
	body             string
}

// upstreamRecorder starts a backend that records the framing of the request it
// receives, and returns it together with the host used for approvals.
func upstreamRecorder(t *testing.T) (*httptest.Server, *receivedRequest, string) {
	t.Helper()
	got := &receivedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.transferEncoding = r.TransferEncoding
		got.header = r.Header.Get("Transfer-Encoding")
		got.contentLength = r.ContentLength
		got.body = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host, _, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split backend host: %v", err)
	}
	return srv, got, host
}

// chunkedBody wraps a reader so that httptest.NewRequest reports an unknown
// content length, which makes net/http forward the request chunked.
type chunkedBody struct{ io.Reader }

// TestProxy_FullLogging_GETNotChunked guards the invariant that inspecting a
// request for the log never changes its framing: a bodyless GET must still
// reach the server without a Transfer-Encoding header, which servers such as
// Azure Blob Storage reject with `UnsupportedHeader`.
func TestProxy_FullLogging_GETNotChunked(t *testing.T) {
	p, _, approvals := setupProxy(t)
	backend, got, host := upstreamRecorder(t)

	approvals.Decide(host, "", "", "", approval.StatusApproved, "")
	approvals.SetLoggingMode(host, "", "", "", approval.LoggingModeFull)

	req := httptest.NewRequest("GET", backend.URL+"/tfstate/dev.tfstate", nil)
	resp, _ := p.processRequest(req, "10.255.255.10")
	if resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from upstream, got %d", resp.StatusCode)
	}
	if len(got.transferEncoding) != 0 || got.header != "" {
		t.Errorf("upstream saw Transfer-Encoding %v (header %q), want none", got.transferEncoding, got.header)
	}
}

// TestProxy_FullLogging_BodyNotTruncated verifies that capturing a request body
// for the log still forwards the whole body upstream, even when the body is
// larger than the amount kept for the log.
func TestProxy_FullLogging_BodyNotTruncated(t *testing.T) {
	p, _, approvals := setupProxy(t)
	backend, got, host := upstreamRecorder(t)

	config.SetMaxFullLogBody(1024)
	t.Cleanup(func() { config.SetMaxFullLogBody(0) })

	approvals.Decide(host, "", "", "", approval.StatusApproved, "")
	approvals.SetLoggingMode(host, "", "", "", approval.LoggingModeFull)

	payload := strings.Repeat("x", 4096)
	req := httptest.NewRequest("POST", backend.URL+"/upload", strings.NewReader(payload))
	resp, _ := p.processRequest(req, "10.255.255.10")
	if resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	if got.body != payload {
		t.Errorf("upstream received %d body bytes, want %d", len(got.body), len(payload))
	}
}

// TestProxy_ChunkedRequest_DefaultsToChunked documents the default: a request
// whose body length is unknown is forwarded with chunked Transfer-Encoding.
func TestProxy_ChunkedRequest_DefaultsToChunked(t *testing.T) {
	p, _, approvals := setupProxy(t)
	backend, got, host := upstreamRecorder(t)

	approvals.Decide(host, "", "", "", approval.StatusApproved, "")

	req := httptest.NewRequest("POST", backend.URL+"/upload", chunkedBody{strings.NewReader("payload")})
	resp, _ := p.processRequest(req, "10.255.255.10")
	if resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	if len(got.transferEncoding) == 0 {
		t.Fatalf("expected upstream to see chunked encoding by default, got %v", got.transferEncoding)
	}
	if got.body != "payload" {
		t.Errorf("upstream body = %q, want %q", got.body, "payload")
	}
}

// TestProxy_DisableTransferEncoding_PerURL verifies that a URL rule with
// disable_transfer_encoding forwards the request with an explicit
// Content-Length and no Transfer-Encoding header.
func TestProxy_DisableTransferEncoding_PerURL(t *testing.T) {
	p, _, approvals := setupProxy(t)
	backend, got, host := upstreamRecorder(t)

	approvals.Decide(host, "", "", "", approval.StatusApproved, "")
	approvals.SetDisableTransferEncoding(host, "", "", "", true)

	req := httptest.NewRequest("POST", backend.URL+"/upload", chunkedBody{strings.NewReader("payload")})
	resp, _ := p.processRequest(req, "10.255.255.10")
	if resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	if len(got.transferEncoding) != 0 || got.header != "" {
		t.Errorf("upstream saw Transfer-Encoding %v (header %q), want none", got.transferEncoding, got.header)
	}
	if got.contentLength != int64(len("payload")) {
		t.Errorf("upstream Content-Length = %d, want %d", got.contentLength, len("payload"))
	}
	if got.body != "payload" {
		t.Errorf("upstream body = %q, want %q", got.body, "payload")
	}
}

// TestProxy_DisableTransferEncoding_ScopedToPath verifies the setting only
// applies to the URLs covered by the rule that carries it.
func TestProxy_DisableTransferEncoding_ScopedToPath(t *testing.T) {
	p, _, approvals := setupProxy(t)
	backend, got, host := upstreamRecorder(t)

	approvals.Decide(host, "", "", "", approval.StatusApproved, "")
	approvals.Decide(host, "", "", "/tfstate/", approval.StatusApproved, "")
	approvals.SetDisableTransferEncoding(host, "", "", "/tfstate/", true)

	// Path covered by the rule: no chunked encoding.
	req := httptest.NewRequest("POST", backend.URL+"/tfstate/dev.tfstate", chunkedBody{strings.NewReader("state")})
	if resp, _ := p.processRequest(req, "10.255.255.10"); resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	if len(got.transferEncoding) != 0 {
		t.Errorf("upstream saw Transfer-Encoding %v for /tfstate/, want none", got.transferEncoding)
	}

	// Any other path keeps the default behaviour.
	req = httptest.NewRequest("POST", backend.URL+"/other", chunkedBody{strings.NewReader("state")})
	if resp, _ := p.processRequest(req, "10.255.255.10"); resp == nil {
		t.Fatal("processRequest() returned no response")
	}
	if len(got.transferEncoding) == 0 {
		t.Error("expected /other to keep chunked encoding")
	}
}

// TestStripRequestTransferEncoding_Wire checks the produced wire format
// directly, including that a bodyless request stays bodyless.
func TestStripRequestTransferEncoding_Wire(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req.Body = io.NopCloser(strings.NewReader("")) // as full logging used to leave it
	if err := stripRequestTransferEncoding(req); err != nil {
		t.Fatalf("stripRequestTransferEncoding() error: %v", err)
	}
	dump, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		t.Fatalf("DumpRequestOut() error: %v", err)
	}
	if strings.Contains(strings.ToLower(string(dump)), "transfer-encoding") {
		t.Errorf("request still carries Transfer-Encoding:\n%s", dump)
	}
}
