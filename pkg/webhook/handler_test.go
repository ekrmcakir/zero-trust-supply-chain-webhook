package webhook

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/policy"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHandler_ServeHTTP(t *testing.T) {
	cfg := &config.SecurityPolicy{
		Mode: common.ModeEnforce,
		TrustedRegistries: []string{
			"ghcr.io/ekrmcakir/*",
		},
		DisallowLatestTag: true,
		Cosign: config.CosignConfig{
			Enabled:  true,
			CacheTTL: 5 * time.Minute,
		},
		PodSecurity: config.PodSecurityPolicy{
			Enabled:        true,
			RequireNonRoot: true,
		},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cosignVerifier, err := verifier.NewCosignVerifier(&cfg.Cosign, verifier.NewVerificationCache(5*time.Minute, 10))
	require.NoError(t, err)
	cosignVerifier.SetPublicKey(&key.PublicKey)

	engine := policy.NewEngine(cfg, cosignVerifier, nil)
	handler := NewHandler(engine)

	tTrue := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "production",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "web",
					Image: "ghcr.io/ekrmcakir/signed-app:v1.0.0",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: &tTrue,
					},
				},
			},
		},
	}
	podRaw, err := json.Marshal(pod)
	require.NoError(t, err)

	// 1. Valid compliant request
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID: "test-uid-123",
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: "production",
			Object: runtime.RawExtension{
				Raw: podRaw,
			},
		},
	}
	reviewBytes, err := json.Marshal(review)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reviewBytes))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var respReview admissionv1.AdmissionReview
	err = json.Unmarshal(recorder.Body.Bytes(), &respReview)
	require.NoError(t, err)
	require.NotNil(t, respReview.Response)
	assert.True(t, respReview.Response.Allowed)
	assert.Equal(t, "test-uid-123", string(respReview.Response.UID))

	// 2. Reject untrusted image
	podUntrusted := pod.DeepCopy()
	podUntrusted.Spec.Containers[0].Image = "docker.io/malware/miner:v1"
	podUntrustedRaw, err := json.Marshal(podUntrusted)
	require.NoError(t, err)

	reviewUntrusted := review
	reviewUntrusted.Request = review.Request.DeepCopy()
	reviewUntrusted.Request.Object.Raw = podUntrustedRaw
	reviewUntrustedBytes, err := json.Marshal(reviewUntrusted)
	require.NoError(t, err)

	reqUntrusted := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reviewUntrustedBytes))
	reqUntrusted.Header.Set("Content-Type", "application/json")
	recorderUntrusted := httptest.NewRecorder()

	handler.ServeHTTP(recorderUntrusted, reqUntrusted)

	assert.Equal(t, http.StatusOK, recorderUntrusted.Code)
	var respUntrusted admissionv1.AdmissionReview
	err = json.Unmarshal(recorderUntrusted.Body.Bytes(), &respUntrusted)
	require.NoError(t, err)
	require.NotNil(t, respUntrusted.Response)
	assert.False(t, respUntrusted.Response.Allowed)
	assert.Equal(t, int32(http.StatusForbidden), respUntrusted.Response.Result.Code)
}
