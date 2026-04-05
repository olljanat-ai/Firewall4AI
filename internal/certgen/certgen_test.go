package certgen

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA() error: %v", err)
	}
	if ca.Certificate == nil {
		t.Fatal("CA certificate should not be nil")
	}
	if ca.PrivateKey == nil {
		t.Fatal("CA private key should not be nil")
	}
	if len(ca.CertPEM) == 0 {
		t.Fatal("CA PEM should not be empty")
	}
	if !ca.Certificate.IsCA {
		t.Error("certificate should be a CA")
	}
	if ca.Certificate.Subject.CommonName != "Firewall4AI CA" {
		t.Errorf("expected CN 'Firewall4AI CA', got %q", ca.Certificate.Subject.CommonName)
	}
}

func TestLoadOrGenerateCA_Creates(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA() error: %v", err)
	}
	if ca.Certificate == nil {
		t.Fatal("should have generated a CA")
	}

	// Files should exist.
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Error("ca.crt should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Error("ca.key should exist")
	}
}

func TestLoadOrGenerateCA_Reloads(t *testing.T) {
	dir := t.TempDir()

	ca1, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCA() error: %v", err)
	}

	ca2, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCA() error: %v", err)
	}

	// Should load the same CA (same serial).
	if ca1.Certificate.SerialNumber.Cmp(ca2.Certificate.SerialNumber) != 0 {
		t.Error("reloaded CA should have the same serial number")
	}
}

func TestGenerateHostCert(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA() error: %v", err)
	}

	cert, err := ca.GenerateHostCert("example.com")
	if err != nil {
		t.Fatalf("GenerateHostCert() error: %v", err)
	}
	if cert == nil {
		t.Fatal("host cert should not be nil")
	}

	// Parse and verify.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("expected CN 'example.com', got %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("expected SAN 'example.com', got %v", leaf.DNSNames)
	}

	// Verify the cert is signed by our CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("cert should be signed by CA: %v", err)
	}
}

func TestGenerateHostCert_IP(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA() error: %v", err)
	}

	cert, err := ca.GenerateHostCert("192.168.1.1")
	if err != nil {
		t.Fatalf("GenerateHostCert(IP) error: %v", err)
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if len(leaf.IPAddresses) != 1 {
		t.Errorf("expected 1 IP SAN, got %d", len(leaf.IPAddresses))
	}
}

func TestGenerateHostCert_Cached(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA() error: %v", err)
	}

	cert1, _ := ca.GenerateHostCert("cached.example.com")
	cert2, _ := ca.GenerateHostCert("cached.example.com")

	// Should be the same pointer (cached).
	if cert1 != cert2 {
		t.Error("second call should return cached certificate")
	}
}

