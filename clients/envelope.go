package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
)

// Envelope is the client for the envelope service — the platform's owner of a
// signing envelope: its documents, its ordered signer slots, and its lifecycle
// (draft, sent, completed, cancelled). The Portal-API drives it on the user's
// behalf, so the envelope service owner-filters on the user subject and the
// user's own envelopes are reachable.
type Envelope struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewEnvelope builds an envelope-service client over the given outbound doer.
func NewEnvelope(d Doer, baseURL, audience string) *Envelope {
	return &Envelope{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const (
	scopeEnvRead       = "envelopes:read"
	scopeEnvWrite      = "envelopes:write"
	scopeEnvTransition = "envelopes:transition"
)

// CreateInput requests a new envelope. The owner is derived from the delegated
// token subject by the envelope service and is never supplied here. The optional
// documents and slots seed the envelope at creation.
type CreateInput struct {
	Title       string      `json:"title,omitempty"`
	OrderPolicy string      `json:"orderPolicy,omitempty"`
	Profile     string      `json:"profile,omitempty"`
	Documents   []string    `json:"documents,omitempty"`
	Slots       []SlotInput `json:"slots,omitempty"`
}

// SlotInput describes one signer slot to add to an envelope.
type SlotInput struct {
	OrderIndex  int    `json:"orderIndex"`
	Role        string `json:"role,omitempty"`
	Flow        string `json:"flow,omitempty"`
	RequiredLoa string `json:"requiredLoa,omitempty"`
	IdentityRef string `json:"identityRef,omitempty"`
}

// Created is the answer to creating an envelope.
type Created struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Version int      `json:"version"`
	SlotIDs []string `json:"slotIds,omitempty"`
}

// Summary is one envelope as it appears in a listing. CreatedAt is when it began;
// SlotCount/SignedCount give "n of N signed", and YourTurn is true when it is the owner's
// turn to sign one of their own slots — together they drive the dashboard's progress badge.
type Summary struct {
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Status      string `json:"status"`
	OrderPolicy string `json:"orderPolicy,omitempty"`
	Version     int    `json:"version"`
	CreatedAt   string `json:"createdAt,omitempty"`
	// UpdatedAt is the envelope's last mutation — send, a slot signing,
	// decline, completion — so the dashboard can order by last action.
	UpdatedAt string `json:"updatedAt,omitempty"`
	// DocIDs are the envelope's attached document ids — what lets a dashboard
	// composer subtract envelope-covered chains from the standalone-document list.
	DocIDs      []string `json:"docIds,omitempty"`
	SlotCount   int      `json:"slotCount"`
	SignedCount int      `json:"signedCount"`
	YourTurn    bool     `json:"yourTurn"`
	// RetentionUntil is when the SOONEST of the envelope's documents auto-deletes.
	// The envelope service does not know it — documents and their retention live in
	// the document service — so it is filled in by whoever composes a view that
	// carries both, and is absent otherwise. Without it an envelope row can state no
	// time-to-live at all, which reads as "this is kept forever" for exactly the
	// documents a workflow has touched.
	RetentionUntil string `json:"retentionUntil,omitempty"`
}

// List is a page of envelopes plus the cursor for the next page.
type ListResult struct {
	Envelopes  []Summary `json:"envelopes"`
	NextCursor string    `json:"nextCursor,omitempty"`
}

// SigningTask is one envelope awaiting the user's signature as an invited co-signer: the
// envelope summary, the user's own slot, and whether it is their turn to sign under the
// envelope's ordering policy. The owner subject is never carried.
type SigningTask struct {
	Envelope   Summary `json:"envelope"`
	SlotID     string  `json:"slotId"`
	OrderIndex int     `json:"orderIndex"`
	SlotStatus string  `json:"slotStatus"`
	SlotFlow   string  `json:"slotFlow,omitempty"`
	YourTurn   bool    `json:"yourTurn"`
}

// SigningTasksResult is a page of the user's signer inbox plus the cursor for the next
// page.
type SigningTasksResult struct {
	Tasks      []SigningTask `json:"tasks"`
	NextCursor string        `json:"nextCursor,omitempty"`
}

// EnvelopeView is the envelope header in the detailed view. CreatedAt is when the
// envelope began (RFC3339), shown on the tracking page.
type EnvelopeView struct {
	ID          string `json:"id"`
	Owner       string `json:"owner,omitempty"`
	Title       string `json:"title,omitempty"`
	Status      string `json:"status"`
	OrderPolicy string `json:"orderPolicy,omitempty"`
	Version     int    `json:"version"`
	CreatedAt   string `json:"createdAt,omitempty"`
}

// Slot is one signer slot in the detailed view. IdentityRef (the invited signer's
// eIDAS code) is read from the envelope service so the BFF can tell which slot is the
// viewing user's own — it is NEVER forwarded to the app (the BFF emits a derived
// `you` flag instead, keeping other signers' identity codes server-side).
type Slot struct {
	ID           string `json:"id"`
	OrderIndex   int    `json:"orderIndex"`
	Role         string `json:"role,omitempty"`
	Flow         string `json:"flow,omitempty"`
	RequiredLoa  string `json:"requiredLoa,omitempty"`
	Status       string `json:"status,omitempty"`
	JobID        string `json:"jobId,omitempty"`
	SignatureID  string `json:"signatureId,omitempty"`
	SignedDocRef string `json:"signedDocRef,omitempty"`
	IdentityRef  string `json:"identityRef,omitempty"`
	// SignerName is the display name of the person filling this slot, captured from their
	// own authenticated session on their first open. Empty until they participate.
	SignerName string `json:"signerName,omitempty"`
}

// DocRef is one document attached to an envelope. Filename is resolved by the BFF from
// the document service for display (the envelope service holds only the id + hash); it is
// best-effort — empty when the lookup fails, and the app falls back to the id.
type DocRef struct {
	DocumentID  string `json:"documentId"`
	ContentHash string `json:"contentHash,omitempty"`
	Filename    string `json:"filename,omitempty"`
}

// Detail is the detailed envelope view: the header, its slots, and its documents.
type Detail struct {
	Envelope  EnvelopeView `json:"envelope"`
	Slots     []Slot       `json:"slots"`
	Documents []DocRef     `json:"documents"`
}

// transition is the uniform answer to a lifecycle transition.
type Transition struct {
	ID      string `json:"id"`
	Status  string `json:"status,omitempty"`
	Version int    `json:"version,omitempty"`
}

// Create makes a new envelope for the user.
func (c *Envelope) Create(ctx context.Context, obo OnBehalf, in CreateInput) (*Created, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	url := c.baseURL + "/api/v1/envelopes"

	var out Created
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// List returns a page of the user's envelopes.
func (c *Envelope) List(ctx context.Context, obo OnBehalf, limit int, cursor string) (*ListResult, error) {
	url := c.baseURL + "/api/v1/envelopes"
	q := make([]string, 0, 2)
	if limit > 0 {
		q = append(q, fmt.Sprintf("limit=%d", limit))
	}
	if cursor != "" {
		q = append(q, "cursor="+cursor)
	}
	if len(q) > 0 {
		url += "?" + strings.Join(q, "&")
	}

	var out ListResult
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// FindForDocument returns the envelopes covering one document that the user may
// see — as owner, or as a matched participant on a non-draft envelope — newest
// first. Lets the document hub resolve "which envelope carries this document?".
func (c *Envelope) FindForDocument(ctx context.Context, obo OnBehalf, documentID string) (*ListResult, error) {
	url := c.baseURL + "/api/v1/envelopes?documentId=" + neturl.QueryEscape(documentID)

	var out ListResult
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SigningTasks returns the user's signer inbox — envelopes awaiting their signature as an
// invited co-signer (not the ones they own). The envelope service keys this on the user's
// authenticated identity, which the on-behalf delegated token carries.
func (c *Envelope) SigningTasks(ctx context.Context, obo OnBehalf, limit int, cursor string) (*SigningTasksResult, error) {
	url := c.baseURL + "/api/v1/signing-tasks"
	q := make([]string, 0, 2)
	if limit > 0 {
		q = append(q, fmt.Sprintf("limit=%d", limit))
	}
	if cursor != "" {
		q = append(q, "cursor="+cursor)
	}
	if len(q) > 0 {
		url += "?" + strings.Join(q, "&")
	}

	var out SigningTasksResult
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Get returns the detailed view of an envelope (header, slots, documents).
func (c *Envelope) Get(ctx context.Context, obo OnBehalf, id string) (*Detail, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s", c.baseURL, id)

	var out Detail
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// AttachDocument attaches an existing document to an envelope.
func (c *Envelope) AttachDocument(ctx context.Context, obo OnBehalf, id, documentID string) (*DocRef, error) {
	body, err := json.Marshal(struct {
		DocumentID string `json:"documentId"`
	}{DocumentID: documentID})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/envelopes/%s/documents", c.baseURL, id)

	var out struct {
		EnvelopeID  string `json:"envelopeId"`
		DocumentID  string `json:"documentId"`
		ContentHash string `json:"contentHash,omitempty"`
	}
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &DocRef{DocumentID: out.DocumentID, ContentHash: out.ContentHash}, nil
}

// AddSlot adds a signer slot to an envelope.
func (c *Envelope) AddSlot(ctx context.Context, obo OnBehalf, id string, in SlotInput) (string, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/v1/envelopes/%s/slots", c.baseURL, id)

	var out struct {
		ID string `json:"id"`
	}
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return "", err
	}

	return out.ID, nil
}

// Send moves an envelope out of draft into the active signing lifecycle.
func (c *Envelope) Send(ctx context.Context, obo OnBehalf, id string) (*Transition, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s/send", c.baseURL, id)

	var out Transition
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvTransition, http.MethodPost, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Cancel cancels an envelope.
func (c *Envelope) Cancel(ctx context.Context, obo OnBehalf, id string) (*Transition, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s/cancel", c.baseURL, id)

	var out Transition
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvTransition, http.MethodPost, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Reopen takes a completed envelope back to draft so a further signature joins the
// workflow that already covers the container, instead of a second envelope being minted
// over the same chain. The caller then adds the new slot and sends — the send is what
// re-grants chain access, so reopening alone never opens signing.
func (c *Envelope) Reopen(ctx context.Context, obo OnBehalf, id string) (*Transition, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s/reopen", c.baseURL, id)

	var out Transition
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvTransition, http.MethodPost, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// SlotEligible reports whether a slot may begin signing now (its turn has come
// under the envelope's ordering policy).
func (c *Envelope) SlotEligible(ctx context.Context, obo OnBehalf, id, slotID string) (bool, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s/slots/%s/eligible", c.baseURL, id, slotID)

	var out struct {
		Eligible bool `json:"eligible"`
	}
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return false, err
	}

	return out.Eligible, nil
}

// SetSlotJob records the signing job that backs a slot, so the envelope view can
// later reconcile that slot's live signing state.
func (c *Envelope) SetSlotJob(ctx context.Context, obo OnBehalf, id, slotID, jobID string) error {
	body, err := json.Marshal(struct {
		JobID string `json:"jobId"`
	}{JobID: jobID})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/envelopes/%s/slots/%s/job", c.baseURL, id, slotID)

	return doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvTransition, http.MethodPost, url, obo, body, "application/json", nil)
}

// CaptureSignerName records the viewing user's display name on their own slot, so every
// party can be shown who is who. The name is supplied from the user's authenticated
// session; the envelope service enforces write-once and that a caller may only name their
// own slot. Best-effort — a failure must not fail the envelope view.
func (c *Envelope) CaptureSignerName(ctx context.Context, obo OnBehalf, id, slotID, name string) error {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/envelopes/%s/slots/%s/name", c.baseURL, id, slotID)

	return doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvTransition, http.MethodPost, url, obo, body, "application/json", nil)
}

// DeclineSlot records that the signer for a slot declined to sign.
func (c *Envelope) DeclineSlot(ctx context.Context, obo OnBehalf, id, slotID string) (*Transition, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s/slots/%s/decline", c.baseURL, id, slotID)

	var out Transition
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvTransition, http.MethodPost, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}
