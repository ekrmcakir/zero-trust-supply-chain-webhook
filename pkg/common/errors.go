package common

import (
	"fmt"
)

// SupplyChainError represents a structured error in the supply chain verification flow
type SupplyChainError struct {
	Reason  ValidationReason
	Image   string
	Details string
}

func (e *SupplyChainError) Error() string {
	return fmt.Sprintf("[%s] validation failed for image '%s': %s", e.Reason, e.Image, e.Details)
}

// NewSupplyChainError creates a new SupplyChainError
func NewSupplyChainError(reason ValidationReason, image string, details string) *SupplyChainError {
	return &SupplyChainError{
		Reason:  reason,
		Image:   image,
		Details: details,
	}
}
