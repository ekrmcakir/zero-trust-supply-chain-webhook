package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, 8443, cfg.Server.Port)
	assert.Equal(t, common.ModeEnforce, cfg.Policy.Mode)
	assert.True(t, cfg.Policy.DisallowLatestTag)
	assert.True(t, cfg.Policy.Cosign.Enabled)
	assert.Equal(t, 10*time.Minute, cfg.Policy.Cosign.CacheTTL)
	assert.NoError(t, cfg.Validate())
}

func TestLoadConfig_ValidFile(t *testing.T) {
	yamlContent := `
server:
  port: 9443
  metricsPort: 9091
  tlsCertFile: "/certs/tls.crt"
  tlsKeyFile: "/certs/tls.key"
policy:
  mode: "audit"
  trustedRegistries:
    - "ghcr.io/ekrmcakir/*"
    - "myregistry.azurecr.io/*"
  disallowLatestTag: true
  requireDigest: true
  excludedNamespaces:
    - "kube-system"
  cosign:
    enabled: true
    publicKeyPath: "/keys/cosign.pub"
    cacheTTL: 5m
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configFile, []byte(yamlContent), 0600)
	require.NoError(t, err)

	cfg, err := LoadConfig(configFile)
	require.NoError(t, err)
	assert.Equal(t, 9443, cfg.Server.Port)
	assert.Equal(t, common.ModeAudit, cfg.Policy.Mode)
	assert.True(t, cfg.Policy.RequireDigest)
	assert.Equal(t, 5*time.Minute, cfg.Policy.Cosign.CacheTTL)
	assert.True(t, cfg.Policy.IsNamespaceExcluded("kube-system"))
	assert.False(t, cfg.Policy.IsNamespaceExcluded("default"))
}

func TestMatchesRegistry(t *testing.T) {
	policy := SecurityPolicy{
		TrustedRegistries: []string{
			"ghcr.io/ekrmcakir/*",
			"*.dkr.ecr.eu-west-1.amazonaws.com/*",
			"docker.io/myorg/trusted-*",
		},
	}

	tests := []struct {
		image    string
		expected bool
	}{
		{"ghcr.io/ekrmcakir/frontend:v1.0.0", true},
		{"ghcr.io/ekrmcakir/backend@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"ghcr.io/attacker/evil-app:v1.0.0", false},
		{"123456789012.dkr.ecr.eu-west-1.amazonaws.com/prod/api:v2.1", true},
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com/prod/api:v2.1", false},
		{"docker.io/myorg/trusted-service:1.0", true},
		{"docker.io/library/nginx:latest", false},
		{"evil.registry.com/malware:v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			res := policy.MatchesRegistry(tt.image)
			assert.Equal(t, tt.expected, res)
		})
	}
}
