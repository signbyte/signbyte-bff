package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	answer "github.com/gmb-lib/go-validation-answer"
)

// Signflow is the client for the signing orchestrator — it conducts a signing job
// per document/flow, owns the signature record, and answers validation. The
// Portal-API drives it on the user's behalf; the orchestrator in turn reaches the
// document service on the same user's behalf, so the user's own document is
// reachable across both hops.
type Signflow struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewSignflow builds a signing-orchestrator client over the given outbound doer.
func NewSignflow(d Doer, baseURL, audience string) *Signflow {
	return &Signflow{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const (
	scopeSigCreate = "signatures:create"
	scopeSigRead   = "signatures:read"
	scopeSigWrite  = "signatures:write"
)

// BeginInput starts a signing for an envelope slot; the document id is the
// user's own document. A solo self-sign is a one-slot envelope, so every
// signing carries real envelope + slot ids.
type BeginInput struct {
	EnvelopeID string `json:"envelopeId"`
	SlotID     string `json:"slotId"`
	Flow       string `json:"flow"`
	SigFormat  string `json:"sigFormat"`
	DocumentID string `json:"documentId"`
	// SigningCertificate and AuthCertificate carry certificates for the
	// signing act: the card certificates for the in-browser (webEid) flow, or
	// the login-captured identity certificates for a redirect flow (so the
	// provider skips re-resolving them). Public certificates, request-scoped —
	// never held or logged. Empty means the provider resolves its own.
	SigningCertificate string `json:"signingCertificate,omitempty"`
	AuthCertificate    string `json:"authCertificate,omitempty"`
	// SignIdentityID names the provider-side sign identity the certificates
	// belong to (captured at login); with it and both certificates present the
	// provider can skip its identity-resolution leg entirely.
	SignIdentityID string `json:"signIdentityId,omitempty"`
	// SealID picks which seal signs (cloudEseal with several seals).
	SealID string `json:"sealId,omitempty"`
	// PostAuthRedirect and AuthErrorRedirect are the URLs the signing provider
	// returns the browser to after a redirect flow authorizes (or fails). The BFF
	// synthesizes them from its own configured app origin (never from client input),
	// with a "{jobId}" placeholder the provider substitutes. Empty for the
	// in-browser flow.
	PostAuthRedirect  string `json:"postAuthRedirect,omitempty"`
	AuthErrorRedirect string `json:"authErrorRedirect,omitempty"`
}

// DigestRef is one per-document digest the in-browser client must sign.
type DigestRef struct {
	DocumentID      string `json:"documentId"`
	Digest          string `json:"digest"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
}

// Job is the uniform signing-lifecycle answer. AuthorizeURL is set for remote
// flows that need a user redirect; SignAlgorithm + Documents are set for the
// in-browser flow (the digests to sign on the card); VerificationCode,
// VerificationMessage + SigningDeadline are set during the device-push
// confirmation window (eID Scan) — the code and prompt the user matches on their
// phone before authorizing, and the confirm-by deadline (epoch ms);
// ContainerID/SignatureID are set on completion.
type Job struct {
	JobID               string      `json:"jobId"`
	State               string      `json:"state"`
	AuthorizeURL        string      `json:"authorizeUrl,omitempty"`
	SignAlgorithm       string      `json:"signAlgorithm,omitempty"`
	VerificationCode    string      `json:"verificationCode,omitempty"`
	VerificationMessage string      `json:"verificationMessage,omitempty"`
	SigningDeadline     int64       `json:"signingDeadline,omitempty"`
	Documents           []DigestRef `json:"documents,omitempty"`
	ContainerID         string      `json:"containerId,omitempty"`
	SignatureID         string      `json:"signatureId,omitempty"`
}

// ClientSignature is one in-browser (card) signature value for a document.
type ClientSignature struct {
	DocumentID     string `json:"documentId"`
	SignatureValue string `json:"signatureValue"`
}

// SignatureInfo is one signature within a validated document — a container can
// hold several (parallel co-signatures). The shape is the shared
// validation-answer library's, so the BFF relays exactly what the orchestrator
// serves — it never interprets the report.
type SignatureInfo = answer.Signature

// Validation is the normalized validation answer for a validated signature or
// document (the shared wire shape; signatureId / documentId carry the caller
// context). The BFF relays it verbatim. The serial is masked by the UI, never
// an audited disclosure.
type Validation = answer.Validation

// BeginSigning starts a signing job for the user's document.
func (c *Signflow) BeginSigning(ctx context.Context, obo OnBehalf, in BeginInput) (*Job, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	url := c.baseURL + "/api/v1/signings"

	var out Job
	if err := doJSONOnBehalf(ctx, c.doer, "signflow", c.audience, scopeSigCreate, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Status reconciles + returns the job's current state. A positive wait turns the
// call into a long-poll: signflow holds the request up to that many seconds until the
// job's state changes (the SPA uses this for the post-approval "finalizing" wait so it
// answers the moment the seal lands, rather than tight-looping). wait <= 0 returns at
// once. This is a slow-operation call: the first ready turn runs the whole finalize
// downstream — assemble, record, and a full validation round (tens of seconds) — so
// the default service-call ceiling would abandon a signing that goes on to succeed.
func (c *Signflow) Status(ctx context.Context, obo OnBehalf, jobID string, wait int) (*Job, error) {
	url := fmt.Sprintf("%s/api/v1/signings/%s/status", c.baseURL, jobID)
	if wait > 0 {
		url += fmt.Sprintf("?wait=%d", wait)
	}

	var out Job
	if err := doJSONOnBehalfSlow(ctx, c.doer, "signflow", c.audience, scopeSigRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Abandon releases a signing attempt's chain lock WITHOUT declining the slot — the
// signer cancelled at the provider or picked the wrong method and will retry, so a
// waiting co-signer isn't left blocked on a dead attempt. Returns nil on success (204).
func (c *Signflow) Abandon(ctx context.Context, obo OnBehalf, jobID string) error {
	url := fmt.Sprintf("%s/api/v1/signings/%s/abandon", c.baseURL, jobID)

	return doJSONOnBehalf(ctx, c.doer, "signflow", c.audience, scopeSigWrite, http.MethodPost, url, obo, nil, "", nil)
}

// ChainFree long-polls whether an envelope's chain is free to sign (no active-signer
// lock). wait <= 0 returns at once; the caller re-calls to keep waiting. Envelope ids
// are ULIDs (URL-safe), so they embed directly.
func (c *Signflow) ChainFree(ctx context.Context, obo OnBehalf, envelopeID string, wait int) (bool, error) {
	url := fmt.Sprintf("%s/api/v1/chain-free?envelopeId=%s", c.baseURL, envelopeID)
	if wait > 0 {
		url += fmt.Sprintf("&wait=%d", wait)
	}

	var out struct {
		Free bool `json:"free"`
	}
	if err := doJSONOnBehalf(ctx, c.doer, "signflow", c.audience, scopeSigRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return false, err
	}

	return out.Free, nil
}

// SubmitClientSignature hands the in-browser card signature(s) back to the job.
func (c *Signflow) SubmitClientSignature(ctx context.Context, obo OnBehalf, jobID string, sigs []ClientSignature) (*Job, error) {
	body, err := json.Marshal(struct {
		Signatures []ClientSignature `json:"signatures"`
	}{Signatures: sigs})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/signings/%s/client-signature", c.baseURL, jobID)

	var out Job
	if err := doJSONOnBehalf(ctx, c.doer, "signflow", c.audience, scopeSigWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ArchivedDocument is a signed document refreshed with a qualified archive
// timestamp: the SAME document id, now pointing at the archived bytes.
type ArchivedDocument struct {
	DocumentID  string `json:"documentId"`
	ContentHash string `json:"contentHash"`
	Mime        string `json:"mime"`
	Size        int64  `json:"size"`
}

// ArchiveTimestamp asks the signing orchestrator to refresh a signed document
// with a qualified archive timestamp (B-LT → B-LTA) on the user's behalf. The
// document keeps its id — the bytes are replaced in place. authCert is the
// signed-in user's authentication certificate: the timestamp request is made
// in the acting user's name (public certificate, request-scoped, never logged).
func (c *Signflow) ArchiveTimestamp(ctx context.Context, obo OnBehalf, documentID, authCert string) (*ArchivedDocument, error) {
	body, err := json.Marshal(struct {
		DocumentID      string `json:"documentId"`
		AuthCertificate string `json:"authCertificate,omitempty"`
	}{DocumentID: documentID, AuthCertificate: authCert})
	if err != nil {
		return nil, err
	}

	url := c.baseURL + "/api/v1/archive-timestamps"

	var out ArchivedDocument
	if err := doJSONOnBehalfSlow(ctx, c.doer, "signflow", c.audience, scopeSigWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ValidateDocument validates a signed document on demand (an uploaded
// already-signed file, or any signed head) on the user's behalf and returns the
// normalized answer. Nothing is persisted server-side — this is repeatable
// evidence-on-request.
func (c *Signflow) ValidateDocument(ctx context.Context, obo OnBehalf, documentID string) (*Validation, error) {
	body, err := json.Marshal(struct {
		DocumentID string `json:"documentId"`
	}{DocumentID: documentID})
	if err != nil {
		return nil, err
	}

	url := c.baseURL + "/api/v1/document-validations"

	var out Validation
	if err := doJSONOnBehalfSlow(ctx, c.doer, "signflow", c.audience, scopeSigRead, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Validate validates (or re-validates) a recorded signature.
func (c *Signflow) Validate(ctx context.Context, obo OnBehalf, signatureID string) (*Validation, error) {
	body, err := json.Marshal(struct {
		SignatureID string `json:"signatureId"`
	}{SignatureID: signatureID})
	if err != nil {
		return nil, err
	}

	url := c.baseURL + "/api/v1/validations"

	var out Validation
	if err := doJSONOnBehalfSlow(ctx, c.doer, "signflow", c.audience, scopeSigRead, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}
