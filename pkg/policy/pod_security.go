package policy

import (
	"fmt"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	corev1 "k8s.io/api/core/v1"
)

// PodSecurityValidator checks Kubernetes pod specs against zero-trust hardening baselines
type PodSecurityValidator struct {
	cfg *config.PodSecurityPolicy
}

// NewPodSecurityValidator constructs a new PodSecurityValidator
func NewPodSecurityValidator(cfg *config.PodSecurityPolicy) *PodSecurityValidator {
	return &PodSecurityValidator{cfg: cfg}
}

// ValidatePod inspects all containers and pod-level security contexts
func (v *PodSecurityValidator) ValidatePod(podSpec *corev1.PodSpec) []common.PodSecurityViolation {
	if v.cfg == nil || !v.cfg.Enabled {
		return nil
	}

	var violations []common.PodSecurityViolation

	// Check pod-level runAsNonRoot
	podRunAsNonRoot := false
	if podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsNonRoot != nil && *podSpec.SecurityContext.RunAsNonRoot {
		podRunAsNonRoot = true
	}

	// Validate regular and init containers
	allContainers := append(podSpec.InitContainers, podSpec.Containers...)
	for _, c := range allContainers {
		sec := c.SecurityContext

		// 1. Disallow Privileged
		if v.cfg.DisallowPrivileged {
			if sec != nil && sec.Privileged != nil && *sec.Privileged {
				violations = append(violations, common.PodSecurityViolation{
					ContainerName: c.Name,
					Reason:        common.ReasonPrivilegedContainer,
					Message:       fmt.Sprintf("Container '%s' has privileged: true, which is forbidden in zero-trust environments", c.Name),
				})
			}
		}

		// 2. Require Non-Root
		if v.cfg.RequireNonRoot {
			containerRunAsNonRoot := false
			if sec != nil && sec.RunAsNonRoot != nil && *sec.RunAsNonRoot {
				containerRunAsNonRoot = true
			}
			if !containerRunAsNonRoot && !podRunAsNonRoot {
				violations = append(violations, common.PodSecurityViolation{
					ContainerName: c.Name,
					Reason:        common.ReasonRootUserDisallowed,
					Message:       fmt.Sprintf("Container '%s' must specify runAsNonRoot: true", c.Name),
				})
			}
		}

		// 3. Require Read-Only Root Filesystem
		if v.cfg.RequireReadOnlyRootFS {
			if sec == nil || sec.ReadOnlyRootFilesystem == nil || !*sec.ReadOnlyRootFilesystem {
				violations = append(violations, common.PodSecurityViolation{
					ContainerName: c.Name,
					Reason:        common.ReasonReadOnlyRootFSRequired,
					Message:       fmt.Sprintf("Container '%s' must enforce readOnlyRootFilesystem: true", c.Name),
				})
			}
		}

		// 4. Require Drop All Capabilities
		if v.cfg.RequireDropAllCaps {
			hasDropAll := false
			if sec != nil && sec.Capabilities != nil {
				for _, drop := range sec.Capabilities.Drop {
					if drop == "ALL" || drop == "all" {
						hasDropAll = true
						break
					}
				}
			}
			if !hasDropAll {
				violations = append(violations, common.PodSecurityViolation{
					ContainerName: c.Name,
					Reason:        common.ReasonCapabilitiesNotDropped,
					Message:       fmt.Sprintf("Container '%s' must drop all Linux capabilities (capabilities.drop: ['ALL'])", c.Name),
				})
			}
		}

		// 5. Require Resource Limits
		if v.cfg.RequireResourceLimits {
			if c.Resources.Limits == nil || c.Resources.Limits.Cpu().IsZero() || c.Resources.Limits.Memory().IsZero() {
				violations = append(violations, common.PodSecurityViolation{
					ContainerName: c.Name,
					Reason:        common.ReasonMissingLimits,
					Message:       fmt.Sprintf("Container '%s' must define explicit CPU and memory resource limits", c.Name),
				})
			}
		}
	}

	return violations
}
