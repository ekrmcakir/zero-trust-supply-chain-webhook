package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSupplyChainError(t *testing.T) {
	err := NewSupplyChainError(ReasonUntrustedRegistry, "docker.io/malicious/app:v1", "Registry not whitelisted")
	assert.NotNil(t, err)
	assert.Equal(t, ReasonUntrustedRegistry, err.Reason)
	assert.Equal(t, "docker.io/malicious/app:v1", err.Image)
	assert.Contains(t, err.Error(), "[UNTRUSTED_REGISTRY]")
	assert.Contains(t, err.Error(), "Registry not whitelisted")
}
