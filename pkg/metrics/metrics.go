package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ValidationsTotal counts all admission validation attempts
	ValidationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "supply_chain",
			Subsystem: "admission",
			Name:      "validations_total",
			Help:      "Total number of pod admission validations performed by the zero-trust webhook",
		},
		[]string{"verdict", "reason", "namespace"},
	)

	// ValidationDuration records the execution latency of admission checks
	ValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "supply_chain",
			Subsystem: "admission",
			Name:      "validation_duration_seconds",
			Help:      "Duration in seconds of the zero-trust admission validation pipeline",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"mode"},
	)

	// ViolationsTotal counts supply chain violations by type
	ViolationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "supply_chain",
			Subsystem: "policy",
			Name:      "violations_total",
			Help:      "Total count of zero-trust policy violations detected",
		},
		[]string{"violation_type", "namespace"},
	)

	// CosignCacheHits tracks LRU cache hits for image signature verification
	CosignCacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "supply_chain",
			Subsystem: "cache",
			Name:      "cosign_hits_total",
			Help:      "Total count of Cosign signature verification cache hits",
		},
	)

	// CosignCacheMisses tracks LRU cache misses
	CosignCacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "supply_chain",
			Subsystem: "cache",
			Name:      "cosign_misses_total",
			Help:      "Total count of Cosign signature verification cache misses",
		},
	)

	// ActiveEnforcementMode indicates current mode (1 = enforce, 0 = audit)
	ActiveEnforcementMode = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "supply_chain",
			Subsystem: "policy",
			Name:      "enforcement_mode",
			Help:      "Current enforcement mode: 1 for enforce, 0 for audit",
		},
	)
)
