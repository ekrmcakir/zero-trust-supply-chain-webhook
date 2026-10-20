package policy

import (
	"fmt"
	"strings"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/verifier"
	corev1 "k8s.io/api/core/v1"
)

// Decision encapsulates the aggregate admission decision for a pod
type Decision struct {
	Allowed   bool
	Reason    common.ValidationReason
	Message   string
	Warnings  []string
	AuditOnly bool
}

// Engine evaluates pod specifications against comprehensive zero-trust rules
type Engine struct {
	cfg          *config.SecurityPolicy
	cosign       *verifier.CosignVerifier
	sbom         *verifier.SBOMVerifier
	podSec       *PodSecurityValidator
}

// NewEngine constructs a new policy evaluation Engine
func NewEngine(cfg *config.SecurityPolicy, cosign *verifier.CosignVerifier, sbom *verifier.SBOMVerifier) *Engine {
	return &Engine{
		cfg:    cfg,
		cosign: cosign,
		sbom:   sbom,
		podSec: NewPodSecurityValidator(&cfg.PodSecurity),
	}
}

// Evaluate inspects a Pod and decides whether it is permitted to run
func (e *Engine) Evaluate(pod *corev1.Pod, namespace string) Decision {
	// 1. Check namespace exclusion
	if e.cfg.IsNamespaceExcluded(namespace) {
		return Decision{
			Allowed: true,
			Reason:  common.ReasonAllowed,
			Message: fmt.Sprintf("Namespace '%s' is explicitly excluded from zero-trust enforcement", namespace),
		}
	}

	isAudit := e.cfg.Mode == common.ModeAudit
	var warnings []string

	// 2. Evaluate all container images
	allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
	for _, c := range allContainers {
		image := c.Image

		// 2.1 Registry Whitelist check
		if !e.cfg.MatchesRegistry(image) {
			msg := fmt.Sprintf("Image '%s' is from an untrusted registry. Allowed registries: %v", image, e.cfg.TrustedRegistries)
			if isAudit {
				warnings = append(warnings, fmt.Sprintf("[AUDIT] %s", msg))
			} else {
				return Decision{
					Allowed: false,
					Reason:  common.ReasonUntrustedRegistry,
					Message: msg,
				}
			}
		}

		// 2.2 Disallow :latest tag
		if e.cfg.DisallowLatestTag {
			if strings.HasSuffix(image, ":latest") || (!strings.Contains(image, ":") && !strings.Contains(image, "@")) {
				msg := fmt.Sprintf("Image '%s' uses mutable or implicit ':latest' tag, which violates tag immutability policy", image)
				if isAudit {
					warnings = append(warnings, fmt.Sprintf("[AUDIT] %s", msg))
				} else {
					return Decision{
						Allowed: false,
						Reason:  common.ReasonMutableTag,
						Message: msg,
					}
				}
			}
		}

		// 2.3 Require digest pinning
		if e.cfg.RequireDigest && !strings.Contains(image, "@sha256:") {
			msg := fmt.Sprintf("Image '%s' does not specify cryptographic digest pinning (@sha256:...)", image)
			if isAudit {
				warnings = append(warnings, fmt.Sprintf("[AUDIT] %s", msg))
			} else {
				return Decision{
					Allowed: false,
					Reason:  common.ReasonMissingDigest,
					Message: msg,
				}
			}
		}

		// 2.4 Cosign signature verification
		if e.cosign != nil && e.cfg.Cosign.Enabled {
			res := e.cosign.Verify(image)
			if !res.Allowed {
				msg := fmt.Sprintf("Image '%s' failed Cosign verification: %s", image, res.Message)
				if isAudit {
					warnings = append(warnings, fmt.Sprintf("[AUDIT] %s", msg))
				} else {
					return Decision{
						Allowed: false,
						Reason:  res.Reason,
						Message: msg,
					}
				}
			}
		}

		// 2.5 SBOM and CVE attestation
		if e.sbom != nil && (e.cfg.Attestations.RequireSBOM || e.cfg.Attestations.RequireScan) {
			res := e.sbom.VerifyAttestation(image, nil)
			if !res.Allowed {
				msg := fmt.Sprintf("Image '%s' failed attestation check: %s", image, res.Message)
				if isAudit {
					warnings = append(warnings, fmt.Sprintf("[AUDIT] %s", msg))
				} else {
					return Decision{
						Allowed: false,
						Reason:  res.Reason,
						Message: msg,
					}
				}
			}
		}
	}

	// 3. Evaluate Pod Security Standards (hardening)
	if e.podSec != nil && e.cfg.PodSecurity.Enabled {
		violations := e.podSec.ValidatePod(&pod.Spec)
		if len(violations) > 0 {
			var msgs []string
			for _, v := range violations {
				msgs = append(msgs, v.Message)
			}
			fullMsg := fmt.Sprintf("Pod security hardening violations: %s", strings.Join(msgs, "; "))
			if isAudit {
				warnings = append(warnings, fmt.Sprintf("[AUDIT] %s", fullMsg))
			} else {
				return Decision{
					Allowed: false,
					Reason:  violations[0].Reason,
					Message: fullMsg,
				}
			}
		}
	}

	return Decision{
		Allowed:   true,
		Reason:    common.ReasonAllowed,
		Message:   "Pod passed all zero-trust supply chain and hardening checks",
		Warnings:  warnings,
		AuditOnly: isAudit,
	}
}
