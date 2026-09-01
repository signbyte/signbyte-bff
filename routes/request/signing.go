package request

import "azugo.io/azugo"

// ClientSignatureValue is one in-browser (card) signature for a document.
type ClientSignatureValue struct {
	DocumentID     string `json:"documentId" validate:"required"`
	SignatureValue string `json:"signatureValue" validate:"required"`
}

// ClientSignature carries the in-browser card signature(s) back to a job.
type ClientSignature struct {
	Signatures []ClientSignatureValue `json:"signatures" validate:"required,min=1,dive"`
}

// Validate implements azugo.Validator.
func (r *ClientSignature) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
