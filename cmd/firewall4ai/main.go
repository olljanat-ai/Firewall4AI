package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/api"
	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/certgen"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
	"github.com/olljanat-ai/firewall4ai/internal/proxy"
	"github.com/olljanat-ai/firewall4ai/internal/store"
	"github.com/olljanat-ai/firewall4ai/web"
)

// Version is set at build time via ldflags.
var Version = "dev"

// storeData holds the persisted state.
type storeData struct {
	Skills         []auth.Skill             `json:"skills"`
	Approvals      []approval.HostApproval  `json:"approvals"`
	Creds          []credentials.Credential `json:"credentials"`
	ImageApprovals []approval.HostApproval  `json:"image_approvals"`
	Categories     []string                 `json:"categories"`
}

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("firewall4ai", Version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize store.
	dataStore, err := store.New[storeData](cfg.DataDir, "state.json", storeData{})
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}

	// Generate or load CA for TLS MITM inspection.
	ca, err := certgen.LoadOrGenerateCA(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}
	log.Printf("CA certificate: %s", filepath.Join(cfg.DataDir, "ca.crt"))
	log.Printf("Agents must trust this CA for HTTPS inspection to work")

	// Initialize components.
	skills := auth.NewSkillStore()
	approvals := approval.NewManager()
	imageApprovals := approval.NewManager()
	creds := credentials.NewManager()
	logger := proxylog.NewLogger(cfg.MaxLogEntries)

	// Load persisted state.
	state := dataStore.Get()
	skills.LoadSkills(state.Skills)
	approvals.LoadApprovals(state.Approvals)
	imageApprovals.LoadApprovals(state.ImageApprovals)
	creds.LoadCredentials(state.Creds)

	// Setup API handler early so we can load categories into it.
	apiHandler := &api.Handler{
		Skills:         skills,
		Approvals:      approvals,
		ImageApprovals: imageApprovals,
		Credentials:    creds,
		Logger:         logger,
		Version:        Version,
	}
	apiHandler.LoadCategories(state.Categories)

	// Save function persists current state.
	saveFunc := func() error {
		return dataStore.Update(func(d *storeData) {
			d.Skills = skills.ListSkills()
			d.Approvals = approvals.Export()
			d.ImageApprovals = imageApprovals.Export()
			d.Creds = creds.List()
			d.Categories = apiHandler.ListCategoriesSlice()
		})
	}
	apiHandler.SaveFunc = saveFunc

	// Setup proxy server with CA for MITM and registry awareness.
	p := proxy.New(skills, approvals, creds, logger)
	p.CA = ca
	p.ImageApprovals = imageApprovals
	p.Registries = cfg.Registries
	for _, reg := range cfg.Registries {
		log.Printf("Container registry %s: intercepting hosts %v", reg.Name, reg.Hosts)
	}
	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Setup admin API + UI server.
	adminMux := http.NewServeMux()
	apiHandler.RegisterRoutes(adminMux)

	// Serve CA certificate for download.
	adminMux.HandleFunc("GET /ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=firewall4ai-ca.crt")
		w.Write(ca.CertPEM)
	})

	// Serve embedded static files.
	staticFS, err := fs.Sub(web.StaticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to setup static files: %v", err)
	}
	adminMux.Handle("GET /", http.FileServer(http.FS(staticFS)))

	// Setup admin server TLS.
	adminTLSConfig, err := adminTLS(cfg, ca)
	if err != nil {
		log.Fatalf("Failed to setup admin TLS: %v", err)
	}

	adminServer := &http.Server{
		Addr:         cfg.AdminAddr,
		Handler:      adminMux,
		TLSConfig:    adminTLSConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Start proxy server.
	go func() {
		log.Printf("Proxy server listening on %s (HTTP proxy + transparent HTTP)", cfg.ListenAddr)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Start transparent TLS listener for iptables-redirected HTTPS traffic.
	transparentListener, err := net.Listen("tcp", cfg.TransparentTLSAddr)
	if err != nil {
		log.Fatalf("Failed to start transparent TLS listener: %v", err)
	}
	go func() {
		log.Printf("Transparent TLS listener on %s (iptables REDIRECT :443 -> %s)", cfg.TransparentTLSAddr, cfg.TransparentTLSAddr)
		p.ServeTransparentTLS(transparentListener)
	}()

	// Start admin server.
	go func() {
		log.Printf("Admin UI listening on https://localhost%s", cfg.AdminAddr)
		// Always use TLS for admin - either user-provided or auto-generated.
		if err := adminServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Admin server error: %v", err)
		}
	}()

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Save state before shutdown.
	if err := saveFunc(); err != nil {
		log.Printf("Error saving state on shutdown: %v", err)
	}

	transparentListener.Close()
	proxyServer.Shutdown(ctx)
	adminServer.Shutdown(ctx)
	log.Println("Stopped.")
}

// adminTLS returns a TLS config for the admin server. If the user provided
// cert/key files, those are used. Otherwise a self-signed certificate is
// auto-generated.
func adminTLS(cfg config.Config, ca *certgen.CA) (*tls.Config, error) {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load admin TLS cert: %w", err)
		}
		log.Printf("Admin UI using provided TLS certificate")
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	// Auto-generate a self-signed cert for admin UI.
	cert, err := certgen.GenerateAdminCert()
	if err != nil {
		return nil, fmt.Errorf("generate admin cert: %w", err)
	}
	log.Printf("Admin UI using auto-generated self-signed TLS certificate")
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
