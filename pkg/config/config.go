package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"gopkg.in/yaml.v3"
)

// ServerConfig defines the HTTP/TLS server settings
type ServerConfig struct {
	Port            int    `yaml:"port"`
	MetricsPort     int    `yaml:"metricsPort"`
	TLSCertFile     string `yaml:"tlsCertFile"`
	TLSKeyFile      string `yaml:"tlsKeyFile"`
	HealthCheckPath string `yaml:"healthCheckPath"`
	WebhookPath     string `yaml:"webhookPath"`
}

// CosignConfig defines image signature verification options
type CosignConfig struct {
	Enabled            bool          `yaml:"enabled"`
	PublicKeyPath      string        `yaml:"publicKeyPath"`
	PublicKeyInline    string        `yaml:"publicKeyInline"`
	KeylessEnabled     bool          `yaml:"keylessEnabled"`
	KeylessIssuer      string        `yaml:"keylessIssuer"`
	KeylessSubject     string        `yaml:"keylessSubject"`
	CacheTTL           time.Duration `yaml:"cacheTTL"`
	CacheMaxEntries    int           `yaml:"cacheMaxEntries"`
}

// AttestationPolicy defines requirements for SBOM and security scan attestations
type AttestationPolicy struct {
	RequireSBOM          bool `yaml:"requireSBOM"`
	RequireScan          bool `yaml:"requireScan"`
	MaxCriticalCVEs      int  `yaml:"maxCriticalCVEs"`
	MaxHighCVEs          int  `yaml:"maxHighCVEs"`
	DisallowUnscanned    bool `yaml:"disallowUnscanned"`
}

// PodSecurityPolicy defines baseline container hardening rules
type PodSecurityPolicy struct {
	Enabled               bool `yaml:"enabled"`
	DisallowPrivileged    bool `yaml:"disallowPrivileged"`
	RequireNonRoot        bool `yaml:"requireNonRoot"`
	RequireReadOnlyRootFS bool `yaml:"requireReadOnlyRootFS"`
	RequireDropAllCaps    bool `yaml:"requireDropAllCaps"`
	RequireResourceLimits bool `yaml:"requireResourceLimits"`
}

// SecurityPolicy defines the complete zero-trust policy spec
type SecurityPolicy struct {
	Mode                  common.Mode        `yaml:"mode"` // "enforce" or "audit"
	TrustedRegistries     []string           `yaml:"trustedRegistries"`
	DisallowLatestTag     bool               `yaml:"disallowLatestTag"`
	RequireDigest         bool               `yaml:"requireDigest"`
	ExcludedNamespaces    []string           `yaml:"excludedNamespaces"`
	Cosign                CosignConfig       `yaml:"cosign"`
	Attestations          AttestationPolicy  `yaml:"attestations"`
	PodSecurity           PodSecurityPolicy  `yaml:"podSecurity"`
}

// Config is the top-level configuration
type Config struct {
	Server ServerConfig   `yaml:"server"`
	Policy SecurityPolicy `yaml:"policy"`
}

// DefaultConfig returns safe, production-grade defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:            8443,
			MetricsPort:     9090,
			TLSCertFile:     "/etc/webhook/certs/tls.crt",
			TLSKeyFile:      "/etc/webhook/certs/tls.key",
			HealthCheckPath: "/healthz",
			WebhookPath:     "/validate",
		},
		Policy: SecurityPolicy{
			Mode: common.ModeEnforce,
			TrustedRegistries: []string{
				"ghcr.io/ekrmcakir/*",
				"*.dkr.ecr.*.amazonaws.com/*",
				"gcr.io/*",
			},
			DisallowLatestTag: true,
			RequireDigest:     false,
			ExcludedNamespaces: []string{
				"kube-system",
				"kube-public",
				"kube-node-lease",
				"zero-trust-system",
			},
			Cosign: CosignConfig{
				Enabled:         true,
				PublicKeyPath:   "/etc/cosign/cosign.pub",
				CacheTTL:        10 * time.Minute,
				CacheMaxEntries: 10000,
			},
			Attestations: AttestationPolicy{
				RequireSBOM:       true,
				RequireScan:       true,
				MaxCriticalCVEs:   0,
				MaxHighCVEs:       2,
				DisallowUnscanned: true,
			},
			PodSecurity: PodSecurityPolicy{
				Enabled:               true,
				DisallowPrivileged:    true,
				RequireNonRoot:        true,
				RequireReadOnlyRootFS: true,
				RequireDropAllCaps:    true,
				RequireResourceLimits: false,
			},
		},
	}
}

// LoadConfig loads configuration from a YAML file, falling back to defaults
func LoadConfig(filePath string) (*Config, error) {
	cfg := DefaultConfig()

	if filePath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config '%s': %w", filePath, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate checks configuration for logical correctness
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.Policy.Mode != common.ModeEnforce && c.Policy.Mode != common.ModeAudit {
		return fmt.Errorf("invalid policy mode '%s', must be 'enforce' or 'audit'", c.Policy.Mode)
	}
	return nil
}

// IsNamespaceExcluded checks if a namespace should bypass admission checks
func (p *SecurityPolicy) IsNamespaceExcluded(namespace string) bool {
	for _, ns := range p.ExcludedNamespaces {
		if strings.EqualFold(ns, namespace) {
			return true
		}
	}
	return false
}

// MatchesRegistry checks if an image reference matches the trusted registry list
func (p *SecurityPolicy) MatchesRegistry(image string) bool {
	if len(p.TrustedRegistries) == 0 {
		return true // No restriction if list is empty
	}

	for _, pattern := range p.TrustedRegistries {
		if matchWildcard(pattern, image) {
			return true
		}
	}
	return false
}

// matchWildcard implements simple wildcard matching for image registries
func matchWildcard(pattern, target string) bool {
	if pattern == "*" || pattern == target {
		return true
	}

	// Pattern like *.dkr.ecr.*.amazonaws.com/* or ghcr.io/ekrmcakir/*
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == target
	}

	curr := target
	if !strings.HasPrefix(curr, parts[0]) {
		return false
	}
	curr = curr[len(parts[0]):]

	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(curr, parts[i])
		if idx < 0 {
			return false
		}
		curr = curr[idx+len(parts[i]):]
	}

	return strings.HasSuffix(curr, parts[len(parts)-1])
}
