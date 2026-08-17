// Command owner-exec runs the owner-authenticated exec daemon in one of two
// roles (inner / vm), selected entirely by its config file. See the repo
// README and spec/profile.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/imbue-ai/owner-exec/internal/config"
	"github.com/imbue-ai/owner-exec/internal/profile"
	"github.com/imbue-ai/owner-exec/internal/server"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to the TOML config file (required)")
	printVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Println(version)
		return
	}
	if *configPath == "" {
		log.Fatal("owner-exec: --config is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("owner-exec: %v", err)
	}
	if err := run(cfg); err != nil {
		log.Fatalf("owner-exec: %v", err)
	}
}

func run(cfg *config.File) error {
	hostKeyBytes, err := os.ReadFile(cfg.HostKeyPath)
	if err != nil {
		return fmt.Errorf("reading host key %s: %w", cfg.HostKeyPath, err)
	}
	signingKey, keyID, err := profile.LoadSigningKey(hostKeyBytes)
	if err != nil {
		return fmt.Errorf("loading host key: %w", err)
	}

	// The endpoint's accepted audiences, resolved per request so a re-share is
	// picked up without a restart. Both roles accept their fixed host-id-scoped
	// audience (container:<host-id> / vm:<host-id>). The inner role ADDITIONALLY
	// accepts the workspace share domain from share.env, so exec works whether
	// or not the workspace is shared; the vm role never does (its share.env
	// lives in the container it must not trust for this).
	fixedAudience := cfg.ResolvedFixedAudience()
	acceptedAudiencesResolver := func() []string {
		audiences := make([]string, 0, 2)
		if fixedAudience != "" {
			audiences = append(audiences, fixedAudience)
		}
		if cfg.Role == config.RoleInner {
			if shareDomain := config.ShareDomainAudience(cfg.ShareEnvPath); shareDomain != "" {
				audiences = append(audiences, shareDomain)
			}
		}
		return audiences
	}
	chromeOriginResolver := func() string {
		return config.ShareChromeOrigin(cfg.ShareEnvPath)
	}

	if cfg.RegisterPort {
		registerPort(cfg)
	}

	handler := server.New(&server.Config{
		AcceptedAudiencesResolver: acceptedAudiencesResolver,
		AuthorizedKeysPath:        cfg.AuthorizedKeysPath,
		RepoRoot:                  cfg.RepoRoot,
		HostSigningKey:            signingKey,
		HostKeyID:                 keyID,
		GrantsEnabled:             cfg.GrantsEnabled,
		ChromeOriginResolver:      chromeOriginResolver,
		Version:                   version,
		Role:                      string(cfg.Role),
		Now:                       time.Now,
	})

	listenAddr := net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", cfg.ListenPort))
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("owner-exec %s (role=%s) listening on %s", version, cfg.Role, listenAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// registerPort best-effort registers the listen port into apps.toml via
// forward_port.py (inner role). A hiccup must never take the daemon down: the
// row only affects forward/share routing, not the listener, and the next boot
// re-registers.
func registerPort(cfg *config.File) {
	if cfg.ForwardPortScript == "" || cfg.ServiceName == "" {
		log.Printf("owner-exec: port registration requested but forward_port_script/service_name unset; skipping")
		return
	}
	url := fmt.Sprintf("http://%s:%d", cfg.ListenHost, cfg.ListenPort)
	cmd := exec.Command("python3", cfg.ForwardPortScript, "--name", cfg.ServiceName, "--url", url)
	if _, err := os.Stat(cfg.RepoRoot); err == nil {
		cmd.Dir = cfg.RepoRoot
	}
	if err := cmd.Run(); err != nil {
		log.Printf("owner-exec: port registration failed (continuing without it): %v", err)
	}
}
