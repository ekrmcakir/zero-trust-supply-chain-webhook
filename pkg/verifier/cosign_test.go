package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCosignVerifier_CryptographicVerification(t *testing.T) {
	// Generate an ephemeral ECDSA P-256 keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	verifier, err := NewCosignVerifier(&config.CosignConfig{
		Enabled:  true,
		CacheTTL: 5 * time.Minute,
	}, NewVerificationCache(5*time.Minute, 100))
	require.NoError(t, err)

	verifier.SetPublicKey(&privKey.PublicKey)

	// Create test payload
	payload, err := CreateSimpleCosignPayload("ghcr.io/ekrmcakir/my-app", "sha256:112233445566778899")
	require.NoError(t, err)

	// Sign payload with private key
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	require.NoError(t, err)

	sigBytes, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	require.NoError(t, err)

	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// 1. Verify valid signature
	valid, err := verifier.VerifyRawSignature(payload, sigB64)
	require.NoError(t, err)
	assert.True(t, valid, "Valid signature must pass verification")

	// 2. Verify tampered payload
	tamperedPayload := append(payload, []byte("tamper")...)
	valid, err = verifier.VerifyRawSignature(tamperedPayload, sigB64)
	require.NoError(t, err)
	assert.False(t, valid, "Tampered payload must fail verification")

	// 3. Verify with wrong key
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier.SetPublicKey(&otherKey.PublicKey)

	valid, err = verifier.VerifyRawSignature(payload, sigB64)
	require.NoError(t, err)
	assert.False(t, valid, "Signature verified with mismatched key must fail")
}

func TestCosignVerifier_VerifyImageRef(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cache := NewVerificationCache(5*time.Minute, 100)
	verifier, err := NewCosignVerifier(&config.CosignConfig{
		Enabled: true,
	}, cache)
	require.NoError(t, err)
	verifier.SetPublicKey(&privKey.PublicKey)

	// Signed image reference
	res := verifier.Verify("ghcr.io/ekrmcakir/signed-app:v1.0.0")
	assert.True(t, res.Allowed)
	assert.Equal(t, common.ReasonAllowed, res.Reason)

	// Unsigned image reference
	resUnsigned := verifier.Verify("ghcr.io/ekrmcakir/unsigned-app:v1.0.0")
	assert.False(t, resUnsigned.Allowed)
	assert.Equal(t, common.ReasonMissingSignature, resUnsigned.Reason)
}
