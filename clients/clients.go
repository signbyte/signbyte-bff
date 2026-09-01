// Package clients holds the outbound HTTP clients the Portal-API uses to compose
// the domain services on behalf of the logged-in user. Every call goes out on the
// user's behalf via token exchange — the service it reaches owner-filters on the
// user subject, so the user's own data is reachable, and a call without a subject
// token fails closed rather than falling back to this service's own identity.
// Calls are issued through the shared auth client; tests inject a stub doer.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// Doer issues a background DPoP request on behalf of an end user via token
// exchange. The WithTimeout variant carries a per-call overall timeout for
// operations that legitimately outlast the client's default ceiling (a
// long-term-archival validation runs tens of seconds upstream).
// *authclient.Client satisfies it; tests inject a stub.
type Doer interface {
	DoServiceOnBehalf(ctx context.Context, audience, scope, subjectSub, subjectToken, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
	DoServiceOnBehalfWithTimeout(ctx context.Context, timeout time.Duration, audience, scope, subjectSub, subjectToken, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// slowOpTimeout is the per-call ceiling for the validate and archive-timestamp
// compositions. The work behind them (a long-term-archival validation checks
// the archive-timestamp chain plus long-term revocation material) legitimately
// runs tens of seconds, and the orchestrator beneath this hop allows its own
// provider call 90s — this outer ceiling must outlast that, where the default
// service-call timeout would abandon a request that goes on to succeed.
const slowOpTimeout = 120 * time.Second

// OnBehalf carries the end-user identity a call acts for: the user's subject and
// the user's token to exchange. A call without a token cannot reach user-owned data
// — the client fails closed rather than acting as this service's own identity.
type OnBehalf struct {
	Sub   string
	Token string
	// Binding scopes the delegated-token cache (which keys on the subject) to the
	// login method + assurance the token is bound to. A delegated token bakes in
	// those claims, and a person's subject is stable across login methods, so
	// without this a re-login as the same person with a different method would reuse
	// a cached token carrying the OLD method — and the downstream login⇒flow binding
	// check then rejects it. Binding never changes Sub (the downstream/audit
	// identity); empty falls back to subject-only cache keying.
	Binding string
}

// cacheSub returns the value used as the delegated-token cache key: the subject,
// plus the login binding when present, so cached tokens never cross login methods.
// Sub itself is left untouched (it is the audited actor + downstream identity).
func (o OnBehalf) cacheSub() string {
	if o.Binding == "" {
		return o.Sub
	}

	return o.Sub + "|" + o.Binding
}

// Response is a raw upstream response (used where the body is bytes, not JSON, and
// the caller needs the status + selected headers, e.g. a document download).
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// HTTPError is returned when a service responds with a non-2xx status; it carries
// the status so callers can map it onto their own response.
type HTTPError struct {
	Service    string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: upstream status %d: %s", e.Service, e.StatusCode, e.Body)
}

// doOnBehalf issues a request on behalf of the end user and returns the raw
// response. It fails closed when no subject token is present.
func doOnBehalf(ctx context.Context, d Doer, service, audience, scope, method, url string, obo OnBehalf, reqBody []byte, contentType string) (*Response, error) {
	if obo.Token == "" {
		return nil, fmt.Errorf("%s: missing on-behalf-of subject token", service)
	}

	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}

	resp, err := d.DoServiceOnBehalf(ctx, audience, scope, obo.cacheSub(), obo.Token, method, url, hdr, reqBody)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", service, err)
	}

	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: resp.Body}, nil
}

// doJSONOnBehalf is doOnBehalf that requires a 2xx and, when out is non-nil,
// decodes the JSON body into it.
func doJSONOnBehalf(ctx context.Context, d Doer, service, audience, scope, method, url string, obo OnBehalf, reqBody []byte, contentType string, out any) error {
	resp, err := doOnBehalf(ctx, d, service, audience, scope, method, url, obo, reqBody, contentType)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Service: service, StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", service, err)
		}
	}

	return nil
}

// doJSONOnBehalfSlow is doJSONOnBehalf under the slow-operation per-call
// timeout, for the validate/archive compositions whose upstream work
// legitimately outlasts the default service-call ceiling. It fails closed when
// no subject token is present.
func doJSONOnBehalfSlow(ctx context.Context, d Doer, service, audience, scope, method, url string, obo OnBehalf, reqBody []byte, contentType string, out any) error {
	if obo.Token == "" {
		return fmt.Errorf("%s: missing on-behalf-of subject token", service)
	}

	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}

	resp, err := d.DoServiceOnBehalfWithTimeout(ctx, slowOpTimeout, audience, scope, obo.cacheSub(), obo.Token, method, url, hdr, reqBody)
	if err != nil {
		return fmt.Errorf("%s: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Service: service, StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", service, err)
		}
	}

	return nil
}
