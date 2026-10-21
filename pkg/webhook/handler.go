package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/metrics"
	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/policy"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

// Handler processes Kubernetes admission reviews
type Handler struct {
	engine *policy.Engine
}

// NewHandler constructs a new webhook Handler
func NewHandler(engine *policy.Engine) *Handler {
	return &Handler{engine: engine}
}

// ServeHTTP handles the /validate endpoint
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, "invalid HTTP method, only POST is accepted", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "invalid Content-Type, expected application/json", http.StatusBadRequest)
		return
	}

	// Protect against oversized payloads (max 1MB for admission review)
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body (max 1MB allowed): %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var admissionReview admissionv1.AdmissionReview
	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReview); err != nil {
		http.Error(w, fmt.Sprintf("failed to deserialize AdmissionReview: %v", err), http.StatusBadRequest)
		return
	}

	req := admissionReview.Request
	if req == nil {
		http.Error(w, "missing AdmissionRequest inside review", http.StatusBadRequest)
		return
	}

	// Process admission decision
	resp := h.handleAdmissionRequest(req)
	resp.UID = req.UID

	responseReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: resp,
	}

	respBytes, err := json.Marshal(responseReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal admission response: %v", err), http.StatusInternalServerError)
		return
	}

	modeLabel := "enforce"
	verdictLabel := "rejected"
	if resp.Allowed {
		verdictLabel = "admitted"
	}

	metrics.ValidationsTotal.WithLabelValues(verdictLabel, string(resp.Result.Reason), req.Namespace).Inc()
	metrics.ValidationDuration.WithLabelValues(modeLabel).Observe(time.Since(start).Seconds())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (h *Handler) handleAdmissionRequest(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Only inspect Pod resources (or workloads creating pods)
	if req.Kind.Kind != "Pod" {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Status: "Success",
				Reason: metav1.StatusReason(common.ReasonAllowed),
			},
		}
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("Failed to unmarshal raw object into corev1.Pod: %v", err),
				Code:    http.StatusBadRequest,
			},
		}
	}

	namespace := req.Namespace
	if namespace == "" {
		namespace = pod.Namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	decision := h.engine.Evaluate(&pod, namespace)

	if !decision.Allowed {
		metrics.ViolationsTotal.WithLabelValues(string(decision.Reason), namespace).Inc()
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("[Zero-Trust Policy Violation] %s", decision.Message),
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			},
		}
	}

	return &admissionv1.AdmissionResponse{
		Allowed:  true,
		Warnings: decision.Warnings,
		Result: &metav1.Status{
			Status:  "Success",
			Message: decision.Message,
			Reason:  metav1.StatusReason(common.ReasonAllowed),
			Code:    http.StatusOK,
		},
	}
}
