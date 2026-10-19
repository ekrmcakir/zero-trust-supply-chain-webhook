package verifier

import (
	"encoding/json"
	"testing"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSBOMVerifier_ThresholdChecks(t *testing.T) {
	policy := &config.AttestationPolicy{
		RequireSBOM:     true,
		RequireScan:     true,
		MaxCriticalCVEs: 0,
		MaxHighCVEs:     1,
	}

	verifier := NewSBOMVerifier(policy)

	// 1. Create a clean scan statement (0 Critical, 0 High)
	cleanPredicate := VulnPredicate{}
	cleanPredicate.Summary.Critical = 0
	cleanPredicate.Summary.High = 0
	cleanPredicateBytes, err := json.Marshal(cleanPredicate)
	require.NoError(t, err)

	stmt := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://in-toto.io/attestation/vuln/v0.1",
		Predicate:     cleanPredicateBytes,
	}
	stmtBytes, err := json.Marshal(stmt)
	require.NoError(t, err)

	res := verifier.VerifyAttestation("ghcr.io/ekrmcakir/secure-app:v1.0", stmtBytes)
	assert.True(t, res.Allowed)
	assert.Equal(t, common.ReasonAllowed, res.Reason)

	// 2. Create a vulnerable scan statement (1 Critical CVE)
	dirtyPredicate := VulnPredicate{}
	dirtyPredicate.Summary.Critical = 1
	dirtyPredicate.Summary.High = 0
	dirtyBytes, err := json.Marshal(dirtyPredicate)
	require.NoError(t, err)

	stmtDirty := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://in-toto.io/attestation/vuln/v0.1",
		Predicate:     dirtyBytes,
	}
	stmtDirtyBytes, err := json.Marshal(stmtDirty)
	require.NoError(t, err)

	resDirty := verifier.VerifyAttestation("ghcr.io/ekrmcakir/vulnerable-app:v1.0", stmtDirtyBytes)
	assert.False(t, resDirty.Allowed)
	assert.Equal(t, common.ReasonCVEThresholdExceed, resDirty.Reason)
}
