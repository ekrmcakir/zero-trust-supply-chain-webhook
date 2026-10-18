package common

import (
	"time"
)

// Mode represents the enforcement mode of the admission controller
type Mode string

const (
	// ModeEnforce strictly blocks requests that fail validation
	ModeEnforce Mode = "enforce"
	// ModeAudit logs violations and metrics without blocking admission
	ModeAudit Mode = "audit"
)

// ValidationReason describes the specific policy verdict reason
type ValidationReason string

const (
	ReasonAllowed            ValidationReason = "ALLOWED"
	ReasonUntrustedRegistry  ValidationReason = "UNTRUSTED_REGISTRY"
	ReasonMutableTag         ValidationReason = "MUTABLE_TAG_DISALLOWED"
	ReasonMissingDigest      ValidationReason = "MISSING_CRYPTOGRAPHIC_DIGEST"
	ReasonMissingSignature   ValidationReason = "COSIGN_SIGNATURE_MISSING"
	ReasonInvalidSignature   ValidationReason = "COSIGN_SIGNATURE_INVALID"
	ReasonMissingAttestation ValidationReason = "ATTESTATION_MISSING"
	ReasonCVEThresholdExceed ValidationReason = "CVE_SEVERITY_THRESHOLD_EXCEEDED"
	ReasonPrivilegedContainer ValidationReason = "POD_SECURITY_PRIVILEGED_DISALLOWED"
	ReasonRootUserDisallowed ValidationReason = "POD_SECURITY_ROOT_USER_DISALLOWED"
	ReasonMissingLimits      ValidationReason = "POD_SECURITY_MISSING_RESOURCE_LIMITS"
)

// VerificationResult holds the fine-grained outcome of a supply-chain check
type VerificationResult struct {
	Allowed     bool              `json:"allowed"`
	Reason      ValidationReason  `json:"reason"`
	Message     string            `json:"message"`
	Image       string            `json:"image"`
	Digest      string            `json:"digest,omitempty"`
	SignatureID string            `json:"signature_id,omitempty"`
	Signer      string            `json:"signer,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	AuditOnly   bool              `json:"audit_only"`
	Attestations []AttestationMeta `json:"attestations,omitempty"`
}

// AttestationMeta represents verified metadata attached to an image
type AttestationMeta struct {
	PredicateType string `json:"predicate_type"`
	IssuedAt      string `json:"issued_at,omitempty"`
	CriticalCVEs  int    `json:"critical_cves"`
	HighCVEs      int    `json:"high_cves"`
	PassesScan    bool   `json:"passes_scan"`
}

// PodSecurityViolation represents a violation of Pod Security Standards
type PodSecurityViolation struct {
	ContainerName string           `json:"container_name"`
	Reason        ValidationReason `json:"reason"`
	Message       string           `json:"message"`
}
