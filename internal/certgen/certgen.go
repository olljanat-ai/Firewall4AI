// Package certgen handles automatic CA and per-host certificate generation
// for TLS MITM inspection.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA holds a certificate authority used to sign per-host certificates.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	CertPEM     []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrGenerateCA loads a CA from dataDir or generates a new one.
// The CA cert and key are persisted as ca.crt and ca.key in dataDir.
func LoadOrGenerateCA(dataDir string) (*CA, error) {
	certPath := filepath.Join(dataDir, "ca.crt")
	keyPath := filepath.Join(dataDir, "ca.key")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Try to load existing CA.
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return parseCA(certPEM, keyPEM)
	}

	// Generate new CA.
	ca, err := generateCA()
	if err != nil {
		return nil, err
	}

	// Persist.
	if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write ca.crt: %w", err)
	}
	keyPEM, err = marshalECPrivateKey(ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write ca.key: %w", err)
	}

	return ca, nil
}

func generateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Firewall4AI CA",
			Organization: []string{"Firewall4AI"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		cache:       make(map[string]*tls.Certificate),
	}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		cache:       make(map[string]*tls.Certificate),
	}, nil
}

// GenerateHostCert creates a TLS certificate for the given hostname,
// signed by this CA. Results are cached.
func (ca *CA) GenerateHostCert(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}

	cert, err := ca.generateHostCertLocked(host)
	if err != nil {
		return nil, err
	}
	ca.cache[host] = cert
	return cert, nil
}

func (ca *CA) generateHostCertLocked(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Firewall4AI"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Add as SAN.
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create host cert: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return tlsCert, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal EC key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
