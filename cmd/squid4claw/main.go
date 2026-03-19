package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olljanat-ai/squid4claw/internal/api"
	"github.com/olljanat-ai/squid4claw/internal/approval"
	"github.com/olljanat-ai/squid4claw/internal/auth"
	"github.com/olljanat-ai/squid4claw/internal/config"
	"github.com/olljanat-ai/squid4claw/internal/credentials"
	proxylog "github.com/olljanat-ai/squid4claw/internal/logging"
	"github.com/olljanat-ai/squid4claw/internal/proxy"
	"github.com/olljanat-ai/squid4claw/internal/store"
	"github.com/olljanat-ai/squid4claw/web"
)

// Version is set at build time via ldflags.
var Version = "dev"

// storeData holds the persisted state.
type storeData struct {
	Skills    []auth.Skill              `json:"skills"`
	Approvals []approval.HostApproval   `json:"approvals"`
	Creds     []credentials.Credential  `json:"credentials"`
}

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("squid4claw", Version)
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

	// Initialize components.
	skills := auth.NewSkillStore()
	approvals := approval.NewManager()
	creds := credentials.NewManager()
	logger := proxylog.NewLogger(cfg.MaxLogEntries)

	// Load persisted state.
	state := dataStore.Get()
	skills.LoadSkills(state.Skills)
	approvals.LoadApprovals(state.Approvals)
	creds.LoadCredentials(state.Creds)

	// Save function persists current state.
	saveFunc := func() error {
		return dataStore.Update(func(d *storeData) {
			d.Skills = skills.ListSkills()
			d.Approvals = approvals.Export()
			d.Creds = creds.List()
		})
	}

	// Setup proxy server.
	p := proxy.New(skills, approvals, creds, logger)
	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Setup admin API + UI server.
	adminMux := http.NewServeMux()
	apiHandler := &api.Handler{
		Skills:      skills,
		Approvals:   approvals,
		Credentials: creds,
		Logger:      logger,
		SaveFunc:    saveFunc,
	}
	apiHandler.RegisterRoutes(adminMux)

	// Serve embedded static files.
	staticFS, err := fs.Sub(web.StaticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to setup static files: %v", err)
	}
	adminMux.Handle("GET /", http.FileServer(http.FS(staticFS)))

	adminServer := &http.Server{
		Addr:         cfg.AdminAddr,
		Handler:      adminMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Start servers.
	go func() {
		log.Printf("Proxy server listening on %s", cfg.ListenAddr)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	go func() {
		log.Printf("Admin UI listening on %s", cfg.AdminAddr)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			if err := adminServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Admin server error: %v", err)
			}
		} else {
			if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Admin server error: %v", err)
			}
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

	proxyServer.Shutdown(ctx)
	adminServer.Shutdown(ctx)
	log.Println("Stopped.")
}
