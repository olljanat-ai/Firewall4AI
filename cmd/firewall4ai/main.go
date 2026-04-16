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

	"github.com/olljanat-ai/firewall4ai/internal/agent"
	"github.com/olljanat-ai/firewall4ai/internal/api"
	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/certgen"
	"github.com/olljanat-ai/firewall4ai/internal/config"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	"github.com/olljanat-ai/firewall4ai/internal/database"
	"github.com/olljanat-ai/firewall4ai/internal/dhcp"
	"github.com/olljanat-ai/firewall4ai/internal/dns"
	"github.com/olljanat-ai/firewall4ai/internal/image"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
	"github.com/olljanat-ai/firewall4ai/internal/netboot"
	"github.com/olljanat-ai/firewall4ai/internal/proxy"
	"github.com/olljanat-ai/firewall4ai/internal/secret"
	"github.com/olljanat-ai/firewall4ai/internal/store"
	"github.com/olljanat-ai/firewall4ai/internal/tftp"
	"github.com/olljanat-ai/firewall4ai/web"
)

// Version is set at build time via ldflags.
var Version = "dev"

// storeData holds the persisted state.
type storeData struct {
	Skills             []auth.Skill              `json:"skills"`
	Approvals          []approval.HostApproval   `json:"approvals"`
	Creds              []credentials.Credential  `json:"credentials"`
	ImageApprovals     []approval.HostApproval   `json:"image_approvals"`
	HelmChartApprovals []approval.HostApproval   `json:"helm_chart_approvals"`
	PackageApprovals   []approval.HostApproval   `json:"package_approvals"`
	LibraryApprovals   []approval.HostApproval   `json:"library_approvals"`
	Categories         []string                  `json:"categories"`
	LearningMode       bool                      `json:"learning_mode"`
	DisabledLanguages  []string                  `json:"disabled_languages"`
	DisabledDistros    []string                  `json:"disabled_distros"`
	MaxFullLogBody     int                       `json:"max_full_log_body"`
	Databases          []database.DatabaseConfig `json:"databases"`
	DiskImages         []image.DiskImage         `json:"disk_images"`
	Agents             []agent.Agent             `json:"agents"`
	DHCPLeases         []dhcp.Lease              `json:"dhcp_leases"`
	Keyboard           string                    `json:"keyboard"`
	Timezone           string                    `json:"timezone"`
	SSHAuthorizedKeys  map[string]string         `json:"ssh_authorized_keys"`
	Templates          []api.ApprovalTemplate    `json:"templates"`
	GitConfig          config.GitConfig          `json:"git_config"`
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

	// Initialize the master encryption key used to seal secret fields in
	// state.json. Must happen before the store is loaded so that previously
	// persisted ciphertext can be decrypted for the managers.
	if err := secret.Init(cfg.DataDir); err != nil {
		log.Fatalf("Failed to initialize secret store: %v", err)
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
	helmChartApprovals := approval.NewManager()
	packageApprovals := approval.NewManager()
	libraryApprovals := approval.NewManager()
	creds := credentials.NewManager()
	dbMgr := database.NewManager()
	logger := proxylog.NewPersistentLogger(cfg.MaxLogEntries, filepath.Join(cfg.DataDir, "logs"))
	agentMgr := agent.NewManager()

	// Network configuration.
	serverIP := net.ParseIP("10.255.255.1")
	internalIface := "eth1"

	// Initialize netboot manager (deploy boot system).
	netbootMgr := netboot.NewManager(cfg.DataDir, serverIP.String())
	if err := netbootMgr.EnsureTFTPDir(); err != nil {
		log.Printf("Warning: could not create TFTP directory: %v", err)
	}

	// Initialize image manager.
	imageMgr := image.NewManager(cfg.DataDir)

	// Initialize DHCP server.
	dhcpServer := dhcp.NewServer(
		serverIP,
		net.ParseIP("10.255.255.10"),
		net.ParseIP("10.255.255.254"),
		serverIP,
		net.CIDRMask(24, 32),
		[]net.IP{serverIP},
		internalIface,
	)

	// Initialize DNS server.
	dnsServer := dns.NewServer(":53", []string{"1.1.1.1", "1.0.0.1"})

	// Initialize TFTP server.
	tftpServer := tftp.NewServer(":69", netbootMgr.TFTPDir())

	// Load persisted state. Decrypt sealed secrets in place so that the
	// downstream managers only ever see plaintext values.
	state := dataStore.Get()
	openStateSecrets(&state)
	skills.LoadSkills(state.Skills)
	approvals.LoadApprovals(state.Approvals)
	imageApprovals.LoadApprovals(state.ImageApprovals)
	helmChartApprovals.LoadApprovals(state.HelmChartApprovals)
	packageApprovals.LoadApprovals(state.PackageApprovals)
	libraryApprovals.LoadApprovals(state.LibraryApprovals)
	creds.LoadCredentials(state.Creds)
	dbMgr.LoadConfigs(state.Databases)
	imageMgr.LoadImages(state.DiskImages)
	agentMgr.LoadAgents(state.Agents)
	dhcpServer.LoadLeases(state.DHCPLeases)

	// Restore learning mode from persisted state.
	if state.LearningMode {
		config.SetLearningMode(true)
	}

	// Restore disabled languages/distros from persisted state.
	if len(state.DisabledLanguages) > 0 {
		config.SetDisabledLanguages(state.DisabledLanguages)
	}
	if len(state.DisabledDistros) > 0 {
		config.SetDisabledDistros(state.DisabledDistros)
	}

	// Restore max full log body from persisted state.
	if state.MaxFullLogBody > 0 {
		config.SetMaxFullLogBody(state.MaxFullLogBody)
	}

	// Restore git config from persisted state.
	if state.GitConfig.Username != "" || state.GitConfig.Email != "" {
		config.SetGitConfig(state.GitConfig)
	}

	// Setup static DHCP leases and DNS entries for configured agents.
	for _, a := range agentMgr.List() {
		if a.IP != "" {
			dhcpServer.SetStaticLease(a.MAC, a.IP, a.Hostname)
		}
		if a.Hostname != "" && a.IP != "" {
			dnsServer.SetHost(a.Hostname, net.ParseIP(a.IP))
		}
	}

	// DHCP PXE provider: returns boot info for registered agents.
	dhcpServer.PXEProvider = func(mac string, clientArch uint16, isIPXE bool) *dhcp.PXEInfo {
		a, ok := agentMgr.GetByMAC(mac)
		if !ok {
			return nil // Not a registered agent, no PXE.
		}
		// Check if image boot files are ready.
		ver := a.ImageVersion
		if ver == 0 {
			if img, ok := imageMgr.Get(a.ImageID); ok {
				ver = img.LatestReadyVersion()
			}
		}
		if ver == 0 || !netbootMgr.HasImageBootFiles(a.ImageID, ver) {
			return nil // Image boot files not ready.
		}
		info := &dhcp.PXEInfo{
			TFTPServer: serverIP.String(),
			IPXEScript: fmt.Sprintf("http://%s/boot/ipxe?mac=${mac:hexhyp}", serverIP),
		}
		// Choose bootfile based on client architecture.
		if isIPXE {
			info.Bootfile = info.IPXEScript
		} else if clientArch == dhcp.ArchEFIx86_64 || clientArch == dhcp.ArchEFIBC || clientArch == dhcp.ArchEFIx86_64v {
			info.Bootfile = "ipxe.efi"
		} else {
			info.Bootfile = "undionly.kpxe"
		}
		return info
	}

	// DHCP lease change callback: persist leases.
	dhcpServer.OnLeaseChange = func(leases []dhcp.Lease) {
		dataStore.Update(func(d *storeData) {
			d.DHCPLeases = leases
		})
	}

	// Setup API handler.
	apiHandler := &api.Handler{
		Skills:             skills,
		Approvals:          approvals,
		ImageApprovals:     imageApprovals,
		HelmChartApprovals: helmChartApprovals,
		PackageApprovals:   packageApprovals,
		LibraryApprovals:   libraryApprovals,
		Credentials:        creds,
		DatabaseManager:    dbMgr,
		ImageManager:       imageMgr,
		Logger:             logger,
		Version:            Version,
		AgentManager:       agentMgr,
	}
	apiHandler.LoadCategories(state.Categories)
	apiHandler.LoadVMSettings(state.Keyboard, state.Timezone, state.SSHAuthorizedKeys)
	apiHandler.LoadTemplates(state.Templates)

	// Agent change callbacks.
	apiHandler.OnAgentChange = func(a *agent.Agent) {
		if a.IP != "" {
			dhcpServer.SetStaticLease(a.MAC, a.IP, a.Hostname)
			dnsServer.SetHost(a.Hostname, net.ParseIP(a.IP))
		}
	}
	apiHandler.OnAgentDelete = func(a *agent.Agent) {
		dhcpServer.RemoveLease(a.MAC)
		if a.Hostname != "" {
			dnsServer.RemoveHost(a.Hostname)
		}
	}
	apiHandler.GetLeaseIP = func(mac string) string {
		if l := dhcpServer.GetLeaseByMAC(mac); l != nil {
			return l.IP
		}
		return ""
	}
	apiHandler.GetDHCPLeases = func() []api.DHCPLeaseInfo {
		leases := dhcpServer.ExportLeases()
		out := make([]api.DHCPLeaseInfo, len(leases))
		for i, l := range leases {
			expiry := "permanent"
			if !l.Expiry.IsZero() {
				expiry = l.Expiry.Format(time.RFC3339)
			}
			out[i] = api.DHCPLeaseInfo{
				MAC:      l.MAC,
				IP:       l.IP,
				Hostname: l.Hostname,
				Expiry:   expiry,
			}
		}
		return out
	}

	// Image build callback.
	apiHandler.BuildImage = func(img *image.DiskImage, version int) {
		imageMgr.SetVersionStatus(img.ID, version, image.BuildStatusBuilding, "building rootfs")
		dataStore.Update(func(d *storeData) {
			d.DiskImages = imageMgr.ExportImages()
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		imageMgr.SetActiveBuildCancel(img.ID, version, cancel)
		defer imageMgr.SetActiveBuildCancel(img.ID, version, nil)

		bl := image.NewBuildLogger()
		imageMgr.SetActiveBuildLog(img.ID, version, bl)
		keyboard, tz := apiHandler.GetVMSettings()
		gitCfg := config.GetGitConfig()
		buildSettings := image.BuildSettings{Keyboard: keyboard, Timezone: tz, GitUsername: gitCfg.Username, GitEmail: gitCfg.Email}
		if err := imageMgr.BuildImage(ctx, img, version, serverIP.String(), buildSettings, bl); err != nil {
			if err == image.ErrBuildCanceled {
				log.Printf("Build canceled for image %s v%d", img.Name, version)
				imageMgr.SetVersionStatus(img.ID, version, image.BuildStatusCanceled, "build canceled by user")
			} else {
				log.Printf("Failed to build image %s v%d: %v", img.Name, version, err)
				imageMgr.SetVersionStatus(img.ID, version, image.BuildStatusError, err.Error())
			}
		} else {
			imageMgr.SetVersionStatus(img.ID, version, image.BuildStatusReady, "")
		}
		imageMgr.SetActiveBuildLog(img.ID, version, nil)
		imageMgr.SetVersionBuildLog(img.ID, version, bl.String())

		dataStore.Update(func(d *storeData) {
			d.DiskImages = imageMgr.ExportImages()
		})
	}

	// Save function persists current state.
	saveFunc := func() error {
		return dataStore.Update(func(d *storeData) {
			cfg := config.Get()
			d.Skills = skills.ListSkills()
			d.Approvals = approvals.Export()
			d.ImageApprovals = imageApprovals.Export()
			d.HelmChartApprovals = helmChartApprovals.Export()
			d.PackageApprovals = packageApprovals.Export()
			d.LibraryApprovals = libraryApprovals.Export()
			d.Creds = creds.List()
			d.Databases = dbMgr.List()
			d.Categories = apiHandler.ListCategoriesSlice()
			d.LearningMode = cfg.LearningMode
			d.DisabledLanguages = cfg.DisabledLanguages
			d.DisabledDistros = cfg.DisabledDistros
			d.MaxFullLogBody = cfg.MaxFullLogBody
			d.GitConfig = cfg.Git
			d.DiskImages = imageMgr.ExportImages()
			d.Agents = agentMgr.ExportAgents()
			d.DHCPLeases = dhcpServer.ExportLeases()
			keyboard, tz := apiHandler.GetVMSettings()
			d.Keyboard = keyboard
			d.Timezone = tz
			d.SSHAuthorizedKeys = apiHandler.GetSSHAuthorizedKeysMap()
			d.Templates = apiHandler.ExportTemplates()
			// Encrypt secret fields before the store serializes to disk.
			sealStateSecrets(d)
		})
	}
	apiHandler.SaveFunc = saveFunc
	apiHandler.GetBackupData = func() ([]byte, error) {
		// First save current state, then export.
		saveFunc()
		return dataStore.ExportJSON()
	}
	apiHandler.RestoreBackupData = func(data []byte) error {
		return dataStore.ImportJSON(data)
	}

	// Setup proxy server with CA for MITM and registry awareness.
	p := proxy.New(skills, approvals, creds, logger, ca)
	p.ImageApprovals = imageApprovals
	p.HelmChartApprovals = helmChartApprovals
	p.PackageApprovals = packageApprovals
	p.LibraryApprovals = libraryApprovals
	p.Registries = cfg.Registries
	p.HelmRepos = cfg.HelmRepos
	p.OSPackages = cfg.OSPackages
	p.CodeLibraries = cfg.CodeLibraries
	p.SetLearningMode(config.Get().LearningMode)
	if p.GetLearningMode() {
		log.Printf("Learning mode is ENABLED — all connections will be allowed by default")
	}
	p.OnActivity = func(sourceIP string) {
		agentMgr.SetLastSeen(sourceIP)
	}
	apiHandler.SetLearningModeFunc = func(enabled bool) {
		p.SetLearningMode(enabled)
		if enabled {
			log.Printf("Learning mode ENABLED — all connections will be allowed by default")
		} else {
			log.Printf("Learning mode DISABLED — returning to default-deny")
		}
	}
	apiHandler.SetDisabledLanguagesFunc = func(disabled []string) {
		log.Printf("Disabled languages updated: %v", disabled)
	}
	apiHandler.SetDisabledDistrosFunc = func(disabled []string) {
		log.Printf("Disabled distros updated: %v", disabled)
	}
	for _, reg := range cfg.Registries {
		log.Printf("Container registry %s: intercepting hosts %v", reg.Name, reg.Hosts)
	}
	for _, repo := range cfg.HelmRepos {
		log.Printf("Helm chart repo %s: intercepting hosts %v", repo.Name, repo.Hosts)
	}
	for _, repo := range cfg.OSPackages {
		log.Printf("OS package repo %s (%s): intercepting hosts %v", repo.Name, repo.Type, repo.Hosts)
	}
	for _, repo := range cfg.CodeLibraries {
		log.Printf("Code library repo %s (%s): intercepting hosts %v", repo.Name, repo.Type, repo.Hosts)
	}
	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  10 * time.Minute,
		WriteTimeout: 10 * time.Minute,
	}

	// Setup admin API + UI server.
	adminMux := http.NewServeMux()
	apiHandler.RegisterRoutes(adminMux)
	apiHandler.RegisterAgentMgmtRoutes(adminMux)
	apiHandler.RegisterImageMgmtRoutes(adminMux)
	apiHandler.RegisterTemplateRoutes(adminMux)

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

	// Setup admin server, optionally with TLS.
	var adminTLSConfig *tls.Config
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("Failed to load admin TLS cert: %v", err)
		}
		adminTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		log.Printf("Admin UI using provided TLS certificate")
	}

	eth0IP, err := getInterfaceIPv4("eth0")
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	adminServerPort := "80"
	if adminTLSConfig != nil {
		adminServerPort = "443"
	}
	adminServer := &http.Server{
		Addr:         eth0IP + ":" + adminServerPort,
		Handler:      adminMux,
		TLSConfig:    adminTLSConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Setup agent API server (available on agent network).
	agentAPIMux := http.NewServeMux()
	agentHandler := &api.AgentHandler{
		Approvals:          approvals,
		ImageApprovals:     imageApprovals,
		HelmChartApprovals: helmChartApprovals,
		PackageApprovals:   packageApprovals,
		LibraryApprovals:   libraryApprovals,
		Skills:             skills,
		CACertPEM:          ca.CertPEM,
		DatabaseManager:    dbMgr,
		AgentManager:       agentMgr,
		NetbootManager:     netbootMgr,
		ImageManager:       imageMgr,
		GetSSHKeys:         apiHandler.GetSSHAuthorizedKeys,
	}
	agentHandler.RegisterAgentRoutes(agentAPIMux)
	agentAPIServer := &http.Server{
		Addr:         cfg.AgentAPIAddr,
		Handler:      agentAPIMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Minute, // Longer timeout for image downloads.
	}

	// Start DHCP server.
	go func() {
		if err := dhcpServer.ListenAndServe(); err != nil {
			log.Printf("DHCP server error (non-fatal): %v", err)
		}
	}()

	// Start DNS server.
	go func() {
		if err := dnsServer.ListenAndServe(); err != nil {
			log.Printf("DNS server error (non-fatal): %v", err)
		}
	}()

	// Start TFTP server.
	go func() {
		if err := tftpServer.ListenAndServe(); err != nil {
			log.Printf("TFTP server error (non-fatal): %v", err)
		}
	}()

	// Start proxy server.
	go func() {
		log.Printf("Proxy server listening on %s (HTTP proxy + transparent HTTP)", cfg.ListenAddr)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Proxy server error (non-fatal in dev): %v", err)
		}
	}()

	// Start transparent TLS listener for iptables-redirected HTTPS traffic.
	transparentListener, err := net.Listen("tcp", cfg.TransparentTLSAddr)
	if err != nil {
		log.Printf("Warning: Failed to start transparent TLS listener (non-fatal in dev): %v", err)
		transparentListener = nil
	}
	if transparentListener != nil {
		go func() {
			log.Printf("Transparent TLS listener on %s (iptables REDIRECT :443 -> %s)", cfg.TransparentTLSAddr, cfg.TransparentTLSAddr)
			p.ServeTransparentTLS(transparentListener)
		}()
	}

	// Start admin server.
	go func() {
		if adminTLSConfig != nil {
			log.Printf("Admin UI listening on https://%s", adminServer.Addr)
			if err := adminServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Admin server error: %v", err)
			}
		} else {
			log.Printf("Admin UI listening on http://%s", adminServer.Addr)
			if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Admin server error: %v", err)
			}
		}
	}()

	// Start agent API server (plain HTTP on agent network).
	go func() {
		log.Printf("Agent API listening on http://%s", cfg.AgentAPIAddr)
		if err := agentAPIServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Agent API server error (non-fatal): %v", err)
		}
	}()

	log.Printf("Disk images: %d, Agents: %d", imageMgr.Count(), agentMgr.Count())

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

	dbMgr.Close()
	if transparentListener != nil {
		transparentListener.Close()
	}
	proxyServer.Shutdown(ctx)
	adminServer.Shutdown(ctx)
	agentAPIServer.Shutdown(ctx)
	log.Println("Stopped.")
}

func getInterfaceIPv4(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("could not find interface %q: %v", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("could not get addresses for %q: %v", ifaceName, err)
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		// Return first non-loopback IPv4
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for interface %q", ifaceName)
}
