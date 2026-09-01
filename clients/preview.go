package clients

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
)

// Preview is the client for the preview/render service — the platform's safe,
// review-only document renderer. The Portal-API forwards the user's preview
// request on the user's behalf, so the preview service reads the user's own
// document (it in turn reads the document service on behalf of the same user).
type Preview struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewPreview builds a preview-service client over the given outbound doer.
func NewPreview(d Doer, baseURL, audience string) *Preview {
	return &Preview{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const scopePreviewRead = "preview:read"

// Manifest fetches the preview manifest for a document. The manifest is JSON; a
// non-previewable document is still a 2xx (a typed renderable:false body), so the
// caller relays the body verbatim and only a transport/authorization failure is an
// error here.
func (c *Preview) Manifest(ctx context.Context, obo OnBehalf, id string) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/previews/%s", c.baseURL, id)

	return c.get(ctx, obo, url)
}

// Page fetches one rendered, inert page image (raw bytes) so the caller can relay
// the content type to the browser.
func (c *Preview) Page(ctx context.Context, obo OnBehalf, id string, n int) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/previews/%s/pages/%d", c.baseURL, id, n)

	return c.get(ctx, obo, url)
}

// Text fetches the extracted plain-text layer (JSON).
func (c *Preview) Text(ctx context.Context, obo OnBehalf, id string) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/previews/%s/text", c.baseURL, id)

	return c.get(ctx, obo, url)
}

// InnerManifest fetches the preview manifest for one inner file of an ASiC-E
// container. An inner file has no document id of its own — it is addressed by
// (container id, inner name); a non-previewable inner file is still a 2xx typed
// renderable:false body, relayed verbatim.
func (c *Preview) InnerManifest(ctx context.Context, obo OnBehalf, id, name string) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/previews/%s/data-objects/%s", c.baseURL, id, neturl.PathEscape(name))

	return c.get(ctx, obo, url)
}

// InnerPage fetches one rendered, inert page image of one inner file of a container.
func (c *Preview) InnerPage(ctx context.Context, obo OnBehalf, id, name string, n int) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/previews/%s/data-objects/%s/pages/%d", c.baseURL, id, neturl.PathEscape(name), n)

	return c.get(ctx, obo, url)
}

// InnerText fetches the extracted plain-text layer of one inner file of a container.
func (c *Preview) InnerText(ctx context.Context, obo OnBehalf, id, name string) (*Response, error) {
	url := fmt.Sprintf("%s/api/v1/previews/%s/data-objects/%s/text", c.baseURL, id, neturl.PathEscape(name))

	return c.get(ctx, obo, url)
}

// get issues an on-behalf GET and returns the raw response, mapping a non-2xx
// status onto an HTTPError the caller can translate.
func (c *Preview) get(ctx context.Context, obo OnBehalf, url string) (*Response, error) {
	resp, err := doOnBehalf(ctx, c.doer, "preview", c.audience, scopePreviewRead, http.MethodGet, url, obo, nil, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "preview", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp, nil
}
