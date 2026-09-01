package clients

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// ServiceDoer issues a background DPoP request as this service's OWN identity
// with a per-call overall timeout. Used only where no user exists on the path
// (the public verify proxy); every user-facing composition stays on the
// on-behalf Doer. *authclient.Client satisfies it; tests inject a stub.
type ServiceDoer interface {
	DoServiceWithTimeout(ctx context.Context, timeout time.Duration, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// verifyCallTimeout is the per-call ceiling for the public verify's upstream
// validation. The work legitimately runs tens of seconds for long-term
// archival material (~16–40s observed; the signing service's own upstream hop
// is 30s with one retry), so this must comfortably outlast that worst case.
const verifyCallTimeout = 90 * time.Second

// scopeVerifyRead is the scope the verify proxy requests toward the signing
// service — validation is a read of the provider's judgment, nothing more.
const scopeVerifyRead = "signatures:read"

// Verify is the client for the public verify flow: it forwards an uploaded,
// already-gated signed document to the signing service's validation endpoint
// and returns the provider's verbatim report. It holds no state and persists
// nothing — the flow is a stateless proxy by design.
type Verify struct {
	doer     ServiceDoer
	baseURL  string
	audience string
}

// NewVerify builds a verify client over the given service-identity doer.
func NewVerify(d ServiceDoer, baseURL, audience string) *Verify {
	return &Verify{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

// VerifyResult is the provider's answer to one validation upload: the verbatim
// report (or the provider's error body) under its status code, plus the
// transient provider session id — evidence linking this request to the
// provider-side processing.
type VerifyResult struct {
	StatusCode int
	Report     []byte
	SessionID  string
}

// Validate uploads the file to the signing service's validation endpoint and
// returns the provider's verbatim answer. The caller normalizes the report;
// this client does not interpret it. The provider picks its processing path
// from the filename extension, so the caller supplies the original name.
func (c *Verify) Validate(ctx context.Context, filename string, data []byte) (*VerifyResult, error) {
	body, contentType, err := multipartUpload("file", filename, data)
	if err != nil {
		return nil, fmt.Errorf("verify: build multipart: %w", err)
	}

	hdr := http.Header{}
	hdr.Set("Content-Type", contentType)

	url := c.baseURL + "/api/v1/validations"

	resp, err := c.doer.DoServiceWithTimeout(ctx, verifyCallTimeout, c.audience, scopeVerifyRead, http.MethodPost, url, hdr, body)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	return &VerifyResult{
		StatusCode: resp.StatusCode,
		Report:     resp.Body,
		SessionID:  resp.Header.Get("X-Validation-Session"),
	}, nil
}

// multipartUpload builds a single-file multipart/form-data body and its
// Content-Type.
func multipartUpload(field, filename string, data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}
