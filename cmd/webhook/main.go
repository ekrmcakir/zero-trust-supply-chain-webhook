package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/metrics"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/policy"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/verifier"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/webhook"
)

var (
	// Injected via ldflags
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func main() {
	var (
		configFile  = flag.String("config", "", "Path to YAML configuration file")
		tlsCertFile = flag.String("tls-cert-file", "", "Path to TLS certificate file")
		tlsKeyFile  = flag.String("tls-key-file", "", "Path to TLS private key file")
		port        = flag.Int("port", 0, "Webhook server port (overrides config)")
		metricsPort = flag.Int("metrics-port", 0, "Metrics port (overrides config)")
		showVersion = flag.Bool("version", false, "Print version information and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Zero-Trust Software Supply Chain Admission Webhook\nVersion:    %s\nGit Commit: %s\nBuild Date: %s\n", Version, GitCommit, BuildDate)
		os.Exit(0)
	}

	fmt.Printf("[INFO] Initializing Zero-Trust Supply Chain Webhook (v%s, commit: %s)...\n", Version, GitCommit)

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		fmt.Printf("[FATAL] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI overrides if specified
	if *tlsCertFile != "" {
		cfg.Server.TLSCertFile = *tlsCertFile
	}
	if *tlsKeyFile != "" {
		cfg.Server.TLSKeyFile = *tlsKeyFile
	}
	if *port > 0 {
		cfg.Server.Port = *port
	}
	if *metricsPort > 0 {
		cfg.Server.MetricsPort = *metricsPort
	}

	// Set initial metrics gauge
	if cfg.Policy.Mode == common.ModeEnforce {
		metrics.ActiveEnforcementMode.Set(1)
	} else {
		metrics.ActiveEnforcementMode.Set(0)
	}

	// Initialize Verification Cache
	cache := verifier.NewVerificationCache(cfg.Policy.Cosign.CacheTTL, cfg.Policy.Cosign.CacheMaxEntries)

	// Initialize Cosign Verifier
	cosignVerifier, err := verifier.NewCosignVerifier(&cfg.Policy.Cosign, cache)
	if err != nil {
		fmt.Printf("[FATAL] Failed to initialize Cosign verifier: %v\n", err)
		os.Exit(1)
	}

	// Initialize SBOM Verifier
	sbomVerifier := verifier.NewSBOMVerifier(&cfg.Policy.Attestations)

	// Initialize Policy Engine
	engine := policy.NewEngine(&cfg.Policy, cosignVerifier, sbomVerifier)

	// Initialize Webhook Handler & Server
	handler := webhook.NewHandler(engine)
	server := webhook.NewServer(&cfg.Server, handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Start(ctx); err != nil {
		fmt.Printf("[ERROR] Webhook server terminated with error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[INFO] Webhook server cleanly stopped.")
}
