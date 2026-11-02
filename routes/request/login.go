// Package request holds the Portal-API request body structs.
package request

// LoginStart begins a login. ACRValues optionally asks the Auth Service to force
// a specific login method, in its own method names (eparakstsMobile, eidScan,
// webEid); empty lets the Auth Service present its default chooser.
type LoginStart struct {
	ACRValues string `json:"acr_values,omitempty"`
}
