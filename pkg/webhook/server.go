package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/config"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server coordinates the TLS webhook server and HTTP metrics server
type Server struct {
	cfg           *config.ServerConfig
	handler       *Handler
	webhookServer *http.Server
	metricsServer *http.Server
}

// NewServer creates a new Server instance
func NewServer(cfg *config.ServerConfig, handler *Handler) *Server {
	return &Server{
		cfg:     cfg,
		handler: handler,
	}
}

// Start launches both the HTTPS webhook server and HTTP metrics server
func (s *Server) Start(ctx context.Context) error {
	// Webhook mux
	webhookMux := http.NewServeMux()
	webhookMux.Handle(s.cfg.WebhookPath, s.handler)
	webhookMux.HandleFunc(s.cfg.HealthCheckPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	webhookMux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("READY"))
	})

	// Modern TLS 1.3 / 1.2 configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	s.webhookServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.cfg.Port),
		Handler:      webhookMux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Metrics & Visual Dashboard mux
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/", s.serveDashboard)
	metricsMux.HandleFunc("/dashboard", s.serveDashboard)
	if s.handler != nil {
		metricsMux.Handle("/api/validate", s.handler)
	}
	s.metricsServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.cfg.MetricsPort),
		Handler:      metricsMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	errChan := make(chan error, 2)

	// Start metrics server
	go func() {
		fmt.Printf("[INFO] Starting Prometheus metrics server on :%d/metrics\n", s.cfg.MetricsPort)
		if err := s.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("metrics server error: %w", err)
		}
	}()

	// Start webhook HTTPS server
	go func() {
		fmt.Printf("[INFO] Starting Zero-Trust Admission Webhook on :%d%s (TLS)\n", s.cfg.Port, s.cfg.WebhookPath)
		if err := s.webhookServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("webhook TLS server error: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("[INFO] Received shutdown signal, stopping servers...")
		return s.Shutdown()
	case err := <-errChan:
		return err
	}
}

// Shutdown gracefully terminates all listeners
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.webhookServer != nil {
		_ = s.webhookServer.Shutdown(ctx)
	}
	if s.metricsServer != nil {
		_ = s.metricsServer.Shutdown(ctx)
	}
	return nil
}
