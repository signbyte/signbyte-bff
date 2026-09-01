package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Documents is the client for the document service — the platform's owner of
// document bytes, canonical hashes, and lifecycle. The Portal-API forwards the
// user's upload, reads metadata, streams downloads, and deletes, all on the user's
// behalf so the document service owner-filters on the user subject.
type Documents struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewDocuments builds a document-service client over the given outbound doer.
func NewDocuments(d Doer, baseURL, audience string) *Documents {
	return &Documents{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const (
	scopeDocRead  = "documents:read"
	scopeDocWrite = "documents:write"
)

// Meta is the document-metadata projection surfaced to the app.
type Meta struct {
	ID                string `json:"id"`
	Filename          string `json:"filename"`
	Mime              string `json:"mime"`
	ContentHash       string `json:"contentHash"`
	Size              int64  `json:"size"`
	PreservationClass string `json:"preservationClass"`
	// Kind and Status ride through from the document service on a metadata read,
	// so the app can tell a signed artifact (e.g. an uploaded already-signed
	// container staged as an annex) from an unsigned draft without a second call.
	Kind   string `json:"kind,omitempty"`
	Status string `json:"status,omitempty"`
	// HasSignatures is set on an upload response: a structural detection only
	// (not a cryptographic verification) of whether the uploaded file already
	// carried a signature. Absent (false) for a metadata read of an existing
	// document.
	HasSignatures bool `json:"hasSignatures,omitempty"`
	// InnerFiles lists a container's data objects (name / media type / size) —
	// "what's inside" a bundle, for the wizard's staged list + Review. Empty for a
	// plain source; carries no bytes (extracted on demand for preview/download).
	InnerFiles []InnerFile `json:"innerFiles,omitempty"`
}

// InnerFile is one data object inside an ASiC-E container — its in-container name,
// media type, and size (the cheap "what's inside" listing; bytes fetched on demand).
type InnerFile struct {
	Name      string `json:"name"`
	MediaType string `json:"mediaType,omitempty"`
	Size      int64  `json:"size,omitempty"`
}

// DocSummary is one document as it appears in a listing. It is a deliberately
// narrow projection of the document service's row: the owner subject, storage
// refs, and other internal bookkeeping are dropped so they never reach the
// browser. The fields kept are what the library view renders — name, type, size,
// lifecycle status, and the retention horizon that drives the time-to-live display.
type DocSummary struct {
	ID                string    `json:"id"`
	Filename          string    `json:"filename"`
	Mime              string    `json:"mime"`
	Size              int64     `json:"size"`
	Status            string    `json:"status"`
	PreservationClass string    `json:"preservationClass"`
	RetentionUntil    time.Time `json:"retentionUntil"`
	CreatedAt         time.Time `json:"createdAt"`
}

// DocList is a page of the user's documents.
type DocList struct {
	Documents []DocSummary `json:"documents"`
	Count     int          `json:"count"`
}

// ChainRow is one document chain projected to its single live head — the signed
// artifact where one exists, else the uploaded source. The dashboard's
// "always latest" row: a chain never appears as its source next to its signed
// result. Narrow like DocSummary: internal bookkeeping never reaches the browser.
type ChainRow struct {
	ChainRootID string `json:"chainRootId"`
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	Filename    string `json:"filename,omitempty"`
	Mime        string `json:"mime"`
	Size        int64  `json:"size"`
	// HasSignatures reports the head carries signatures (including a file that
	// arrived already signed); PlatformSigned reports the head was produced by a
	// signing here — false on a pre-signed upload, so a chain with
	// HasSignatures && !PlatformSigned is a workflow draft that can be validated
	// or co-signed as-is.
	HasSignatures  bool `json:"hasSignatures"`
	PlatformSigned bool `json:"platformSigned"`
	// ResultFrozen: a signing workflow over the chain is in progress — the
	// signed result is download-locked until the workflow's terminal
	// transition, and the dashboard renders the row as in-signing rather than
	// draft/completed.
	ResultFrozen   bool      `json:"resultFrozen,omitempty"`
	RetentionUntil time.Time `json:"retentionUntil"`
	ChainCreatedAt time.Time `json:"chainCreatedAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	// PreservationClass is none|b_lt|preservation — 'preservation' once the
	// container has been archive-timestamped (B-LTA). Passed through to the SPA so
	// the activity trail can show "archived" as a durable fact.
	PreservationClass string `json:"preservationClass"`
	// InnerFiles lists the head container's data objects. Carried by the
	// single-chain read only, so a document screen learns what is inside in the
	// same call; the dashboard listing leaves it empty.
	InnerFiles []InnerFile `json:"innerFiles,omitempty"`
}

// ChainList is a page of the user's document chains.
type ChainList struct {
	Chains []ChainRow `json:"chains"`
	Count  int        `json:"count"`
}

// ListChains fetches a page of the user's documents collapsed to one live-head
// row per chain (the document service's chains view), keyset paginated by chain
// root id.
func (c *Documents) ListChains(ctx context.Context, obo OnBehalf, limit int, after string) (*ChainList, error) {
	u := c.baseURL + "/api/v1/documents"

	q := url.Values{}
	q.Set("view", "chains")
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if after != "" {
		q.Set("after", after)
	}
	u += "?" + q.Encode()

	var out ChainList
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, u, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// GetChain fetches ONE document chain as its live head, addressed by any id in
// it. The document screen reads this instead of looking its document up in the
// dashboard listing: the listing legitimately omits chains (it collapses a chain
// into the workflow that covers it, and it pages), and a chain's own facts must
// not depend on that.
func (c *Documents) GetChain(ctx context.Context, obo OnBehalf, id string) (*ChainRow, error) {
	u := c.baseURL + "/api/v1/documents/" + url.PathEscape(id) + "/chain"

	var out ChainRow
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, u, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// HistoryRow is one terminal chain in the user's history: storage destroyed,
// only the record remaining for the platform's bounded keep window.
type HistoryRow struct {
	ChainRootID    string    `json:"chainRootId"`
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Status         string    `json:"status"`
	Filename       string    `json:"filename,omitempty"`
	Mime           string    `json:"mime"`
	Size           int64     `json:"size"`
	HasSignatures  bool      `json:"hasSignatures"`
	PlatformSigned bool      `json:"platformSigned"`
	ChainCreatedAt time.Time `json:"chainCreatedAt"`
	DestroyedAt    time.Time `json:"destroyedAt"`
}

// HistoryList is a page of the user's history records.
type HistoryList struct {
	Chains []HistoryRow `json:"chains"`
	Count  int          `json:"count"`
}

// ListHistory fetches a page of the user's terminal-chain records, keyset
// paginated by chain root id.
func (c *Documents) ListHistory(ctx context.Context, obo OnBehalf, limit int, after string) (*HistoryList, error) {
	u := c.baseURL + "/api/v1/history"

	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if after != "" {
		q.Set("after", after)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	var out HistoryList
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, u, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DeleteHistory removes one of the user's history records early.
func (c *Documents) DeleteHistory(ctx context.Context, obo OnBehalf, chainRootID string) error {
	url := fmt.Sprintf("%s/api/v1/history/%s", c.baseURL, chainRootID)

	return doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodDelete, url, obo, nil, "", nil)
}

// Upload forwards the user's multipart upload to the document service and returns
// the stored document's metadata. The body is the verbatim multipart payload and
// contentType carries its boundary.
func (c *Documents) Upload(ctx context.Context, obo OnBehalf, contentType string, body []byte) (*Meta, error) {
	url := c.baseURL + "/api/v1/documents"

	var out Meta
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodPost, url, obo, body, contentType, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Bundle packages 2+ of the user's unsigned uploads into ONE unsigned ASiC-E
// bundle — the multi-document set's single row and chain root — in the given
// (sender-set) order. The loose uploads are absorbed by the document service,
// so after this call the returned id is the set's only handle.
func (c *Documents) Bundle(ctx context.Context, obo OnBehalf, sourceIDs []string) (*Meta, error) {
	url := c.baseURL + "/api/v1/documents/bundle"

	body, err := json.Marshal(map[string]any{"sourceIds": sourceIDs})
	if err != nil {
		return nil, fmt.Errorf("clients: marshal bundle request: %w", err)
	}

	var out Meta
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// BundleEntry is one entry of a rebundle request, in final order: an existing inner
// file kept by name, or a newly staged loose source added (and absorbed) by id.
type BundleEntry struct {
	Name     string `json:"name,omitempty"`
	SourceID string `json:"sourceId,omitempty"`
}

// Rebundle rebuilds an UNSIGNED bundle from the given entries in final order — a
// draft edit (add / remove / reorder inner files). Existing inner files are kept by
// name; newly staged loose sources are added by id and absorbed. Returns the updated
// bundle row.
func (c *Documents) Rebundle(ctx context.Context, obo OnBehalf, id string, entries []BundleEntry) (*Meta, error) {
	url := fmt.Sprintf("%s/api/v1/documents/%s/rebundle", c.baseURL, id)

	body, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		return nil, fmt.Errorf("clients: marshal rebundle request: %w", err)
	}

	var out Meta
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodPost, url, obo, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// List fetches a page of the user's documents (keyset paginated by the document
// service: limit caps the page, after is the id to continue past). Zero values
// let the document service apply its defaults.
func (c *Documents) List(ctx context.Context, obo OnBehalf, limit int, after string) (*DocList, error) {
	u := c.baseURL + "/api/v1/documents"

	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if after != "" {
		q.Set("after", after)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	var out DocList
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, u, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Metadata fetches a document's metadata.
func (c *Documents) Metadata(ctx context.Context, obo OnBehalf, id string) (*Meta, error) {
	url := fmt.Sprintf("%s/api/v1/documents/%s", c.baseURL, id)

	var out Meta
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Content streams a document's bytes back as a raw response (status + headers +
// body), so the caller can relay the content type and filename to the browser.
func (c *Documents) Content(ctx context.Context, obo OnBehalf, id string) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/documents/%s/content", c.baseURL, id)

	resp, err := doOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, url, obo, nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "document", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp, nil
}

// ExtractObject streams one named inner file out of an ASiC-E container as a raw
// response (status + headers + body), so the caller can relay it to the browser or
// re-stage it. A multi-file bundle absorbs its originals, so the container is the
// only home of an inner file. It declares the review purpose (conduit=review): the
// user retrieving an original to review or re-stage keeps working while the chain's
// signed result is download-frozen mid-workflow — only an inner original is ever
// returned this way, never the signed container.
func (c *Documents) ExtractObject(ctx context.Context, obo OnBehalf, id, name string) (*Response, error) {
	reqURL := fmt.Sprintf("%s/api/v1/documents/%s/data-objects/%s?conduit=review", c.baseURL, id, url.PathEscape(name))

	resp, err := doOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, reqURL, obo, nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "document", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp, nil
}

// Delete removes a document (manual delete before its retention window lapses).
func (c *Documents) Delete(ctx context.Context, obo OnBehalf, id string) error {
	url := fmt.Sprintf("%s/api/v1/documents/%s", c.baseURL, id)

	return doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodDelete, url, obo, nil, "", nil)
}
