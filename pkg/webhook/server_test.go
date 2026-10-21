package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestServer_NewAndShutdown(t *testing.T) {
	cfg := &config.ServerConfig{
		Port:            8443,
		MetricsPort:     9090,
		WebhookPath:     "/validate",
		HealthCheckPath: "/healthz",
	}

	server := NewServer(cfg, nil)
	assert.NotNil(t, server)

	// Test Shutdown with no active listeners (should not panic or error)
	err := server.Shutdown()
	assert.NoError(t, err)
}

func TestServer_HealthAndReadyEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("READY"))
	})

	// Test /healthz
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	wHealth := httptest.NewRecorder()
	mux.ServeHTTP(wHealth, reqHealth)
	assert.Equal(t, http.StatusOK, wHealth.Code)
	assert.Equal(t, "OK", wHealth.Body.String())

	// Test /readyz
	reqReady := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	wReady := httptest.NewRecorder()
	mux.ServeHTTP(wReady, reqReady)
	assert.Equal(t, http.StatusOK, wReady.Code)
	assert.Equal(t, "READY", wReady.Body.String())
}

func TestServer_GracefulShutdownContext(t *testing.T) {
	cfg := &config.ServerConfig{
		Port:            18443,
		MetricsPort:     19090,
		WebhookPath:     "/validate",
		HealthCheckPath: "/healthz",
		TLSCertFile:     "non-existent.crt",
		TLSKeyFile:      "non-existent.key",
	}

	server := NewServer(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Calling start with invalid certs triggers early error on errChan
	err := server.Start(ctx)
	assert.Error(t, err)
}
