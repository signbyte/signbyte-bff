// Package request holds the Portal-API request body structs.
package request

import (
	"azugo.io/azugo"
)

// LoginStart begins a login. ACRValues optionally asks the Auth Service to force
// a specific login method, in its own method names (eparakstsMobile, eidScan,
// webEid); empty lets the Auth Service present its default chooser.
type LoginStart struct {
	ACRValues string `json:"acr_values,omitempty"`
}

// StepUp asks to elevate the current session to a stronger login method.
type StepUp struct {
	Method string `json:"method" validate:"required,oneof=webEid eidScan eparakstsMobile"`
}

// Validate implements azugo.Validator.
func (r *StepUp) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
