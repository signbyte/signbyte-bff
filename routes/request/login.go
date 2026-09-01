// Package request holds the Portal-API request body structs.
package request

import (
	"encoding/json"

	"azugo.io/azugo"
)

// LoginStart begins a login. ACRValues optionally asks the Auth Service to force
// a specific login method (the app supplies the method-specific value); empty
// lets the Auth Service present its default chooser.
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

// WebEIDComplete finishes an eID-card login. State is the flow handle from the
// start step; AuthToken is the opaque card authentication token produced in the
// browser, forwarded verbatim to the Auth Service.
type WebEIDComplete struct {
	State     string          `json:"state" validate:"required"`
	AuthToken json.RawMessage `json:"authToken" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *WebEIDComplete) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
