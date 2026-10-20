package policy

import (
	"testing"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestPodSecurityValidator(t *testing.T) {
	tTrue := true
	cfg := &config.PodSecurityPolicy{
		Enabled:               true,
		DisallowPrivileged:    true,
		RequireNonRoot:        true,
		RequireReadOnlyRootFS: true,
		RequireDropAllCaps:    true,
	}

	validator := NewPodSecurityValidator(cfg)

	// 1. Privileged container should violate policy
	podSpecPriv := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "privileged-app",
				Image: "ghcr.io/ekrmcakir/app:v1",
				SecurityContext: &corev1.SecurityContext{
					Privileged:             &tTrue,
					RunAsNonRoot:           &tTrue,
					ReadOnlyRootFilesystem: &tTrue,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
			},
		},
	}

	violations := validator.ValidatePod(podSpecPriv)
	assert.NotEmpty(t, violations)
	assert.Equal(t, common.ReasonPrivilegedContainer, violations[0].Reason)

	// 2. Fully compliant container
	podSpecCompliant := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "secure-app",
				Image: "ghcr.io/ekrmcakir/app:v1",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot:           &tTrue,
					ReadOnlyRootFilesystem: &tTrue,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
			},
		},
	}

	violationsCompliant := validator.ValidatePod(podSpecCompliant)
	assert.Empty(t, violationsCompliant, "Fully hardened pod must have 0 violations")
}
