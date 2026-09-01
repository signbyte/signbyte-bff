package request

import "azugo.io/azugo"

// CreateEnvelope requests a new signing envelope. The owner is derived from the
// session identity by the envelope service and is never supplied by the app. The
// optional documents and slots seed the envelope at creation.
type CreateEnvelope struct {
	Title       string      `json:"title,omitempty" validate:"omitempty"`
	OrderPolicy string      `json:"orderPolicy,omitempty" validate:"omitempty,oneof=parallel sequential"`
	Profile     string      `json:"profile,omitempty" validate:"omitempty"`
	Documents   []string    `json:"documents,omitempty" validate:"omitempty,dive,required"`
	Slots       []SlotEntry `json:"slots,omitempty" validate:"omitempty,dive"`
}

// SlotEntry is one signer slot supplied at envelope creation.
type SlotEntry struct {
	OrderIndex  int    `json:"orderIndex"`
	Role        string `json:"role,omitempty"`
	Flow        string `json:"flow,omitempty"`
	RequiredLoa string `json:"requiredLoa,omitempty"`
	IdentityRef string `json:"identityRef,omitempty"`
}

// Validate implements azugo.Validator.
func (r *CreateEnvelope) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// AttachDocument attaches an existing document to an envelope.
type AttachDocument struct {
	DocumentID string `json:"documentId" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *AttachDocument) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// AddSlot adds a signer slot to an envelope.
type AddSlot struct {
	OrderIndex  int    `json:"orderIndex" validate:"required"`
	Role        string `json:"role,omitempty"`
	Flow        string `json:"flow,omitempty"`
	RequiredLoa string `json:"requiredLoa,omitempty"`
	IdentityRef string `json:"identityRef,omitempty"`
}

// Validate implements azugo.Validator.
func (r *AddSlot) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// SignSlot is the per-slot signing trigger: it names the document to sign, the
// signing flow, and the signature format. The flow must be one the user's login
// method permits — the orchestrator enforces that binding and rejects a mismatch.
// SigningCertificate/AuthCertificate carry the card certificates for the in-browser
// (webEid) flow; redirect flows omit them.
type SignSlot struct {
	DocumentID         string `json:"documentId" validate:"required"`
	Flow               string `json:"flow" validate:"required"`
	SigFormat          string `json:"sigFormat" validate:"required"`
	SigningCertificate string `json:"signingCertificate,omitempty"`
	AuthCertificate    string `json:"authCertificate,omitempty"`
	// SealID picks which of the person's seals signs (the cloudEseal flow,
	// when they hold several — the ids come from the session's /me seals).
	// Empty with a single seal is fine; the signing provider then resolves it.
	SealID string `json:"sealId,omitempty"`
}

// Validate implements azugo.Validator.
func (r *SignSlot) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
