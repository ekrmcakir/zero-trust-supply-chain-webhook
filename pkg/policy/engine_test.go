package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func setupTestEngine(t *testing.T, mode common.Mode) *Engine {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg := &config.SecurityPolicy{
		Mode: mode,
		TrustedRegistries: []string{
			"ghcr.io/ekrmcakir/*",
		},
		DisallowLatestTag: true,
		RequireDigest:     false,
		ExcludedNamespaces: []string{
			"kube-system",
		},
		Cosign: config.CosignConfig{
			Enabled:  true,
			CacheTTL: 5 * time.Minute,
		},
		Attestations: config.AttestationPolicy{
			RequireSBOM:     true,
			RequireScan:     true,
			MaxCriticalCVEs: 0,
			MaxHighCVEs:     1,
		},
		PodSecurity: config.PodSecurityPolicy{
			Enabled:               true,
			DisallowPrivileged:    true,
			RequireNonRoot:        true,
			RequireReadOnlyRootFS: true,
			RequireDropAllCaps:    true,
		},
	}

	cosignVerifier, err := verifier.NewCosignVerifier(&cfg.Cosign, verifier.NewVerificationCache(5*time.Minute, 100))
	require.NoError(t, err)
	cosignVerifier.SetPublicKey(&key.PublicKey)

	sbomVerifier := verifier.NewSBOMVerifier(&cfg.Attestations)

	return NewEngine(cfg, cosignVerifier, sbomVerifier)
}

func createCompliantPod(image string) *corev1.Pod {
	tTrue := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: image,
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:           &tTrue,
						ReadOnlyRootFilesystem: &tTrue,
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				},
			},
		},
	}
}

func TestEngine_Scenarios(t *testing.T) {
	engine := setupTestEngine(t, common.ModeEnforce)

	// 1. Excluded namespace bypass
	pod := createCompliantPod("docker.io/untrusted:v1")
	decision := engine.Evaluate(pod, "kube-system")
	assert.True(t, decision.Allowed)

	// 2. Untrusted registry blocked in default namespace
	decision = engine.Evaluate(pod, "default")
	assert.False(t, decision.Allowed)
	assert.Equal(t, common.ReasonUntrustedRegistry, decision.Reason)

	// 3. Mutable :latest tag blocked
	podLatest := createCompliantPod("ghcr.io/ekrmcakir/app:latest")
	decision = engine.Evaluate(podLatest, "default")
	assert.False(t, decision.Allowed)
	assert.Equal(t, common.ReasonMutableTag, decision.Reason)

	// 4. Compliant signed pod allowed
	podValid := createCompliantPod("ghcr.io/ekrmcakir/signed-app:v1.0.0")
	decision = engine.Evaluate(podValid, "default")
	assert.True(t, decision.Allowed)
	assert.Equal(t, common.ReasonAllowed, decision.Reason)

	// 5. Audit mode logs warning instead of blocking
	auditEngine := setupTestEngine(t, common.ModeAudit)
	decisionAudit := auditEngine.Evaluate(podLatest, "default")
	assert.True(t, decisionAudit.Allowed, "Audit mode must not block admission")
	assert.NotEmpty(t, decisionAudit.Warnings)
}
