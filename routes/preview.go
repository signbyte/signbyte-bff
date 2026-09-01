package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	pkweb "github.com/gmb-lib/go-platform-kit/web"

	"github.com/signbyte/signbyte-bff/clients"
)

// previewManifest relays the review-only preview manifest for the user's document,
// fetched on the user's behalf. It records the interactive preview access (the
// person opened a view of their document) — the human reveal the background
// renderer cannot characterize. A non-previewable document is a 2xx manifest with
// renderable:false, relayed verbatim.
//
// @operationId PortalPreviewManifest
// @title Document preview manifest
// @route /api/portal/v1/documents/{id}/preview [get].
func (r *router) previewManifest(ctx *azugo.Context) {
	if !r.previewReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	id := ctx.Params.String("id")
	resp, err := r.Preview().Manifest(ctx, obo, id)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	// Record the user-facing preview access once, when the preview is opened.
	// Routine and fail-open — never blocks the view.
	r.Audit().DocumentPreviewed(ctx, obo.Sub, id)

	relayJSON(ctx, resp)
}

// previewPage relays one rendered, inert page image for the user's document.
//
// @operationId PortalPreviewPage
// @title Rendered page image
// @route /api/portal/v1/documents/{id}/preview/pages/{n} [get].
func (r *router) previewPage(ctx *azugo.Context) {
	if !r.previewReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	n, err := ctx.Params.Int("n")
	if err != nil {
		ctx.Error(err)

		return
	}

	resp, err := r.Preview().Page(ctx, obo, ctx.Params.String("id"), n)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		ctx.Header.Set("Content-Type", ct)
	}
	ctx.Header.Set("Cache-Control", "no-store")
	ctx.Raw(resp.Body)
}

// previewText relays the extracted plain-text layer for the user's document.
//
// @operationId PortalPreviewText
// @title Document text layer
// @route /api/portal/v1/documents/{id}/preview/text [get].
func (r *router) previewText(ctx *azugo.Context) {
	if !r.previewReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	resp, err := r.Preview().Text(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	relayJSON(ctx, resp)
}

// previewInnerManifest relays the preview manifest for one inner file of the user's
// ASiC-E container, fetched on the user's behalf. A multi-file bundle absorbs its
// originals, so an inner file has no id of its own — it is addressed by (container
// id, inner name). Records the interactive preview access against the container.
//
// @operationId PortalPreviewInnerManifest
// @title Inner-file preview manifest
// @route /api/portal/v1/documents/{id}/data-objects/{name}/preview [get].
func (r *router) previewInnerManifest(ctx *azugo.Context) {
	if !r.previewReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	id := ctx.Params.String("id")
	resp, err := r.Preview().InnerManifest(ctx, obo, id, pkweb.PathParam(ctx, "name"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	r.Audit().DocumentPreviewed(ctx, obo.Sub, id)

	relayJSON(ctx, resp)
}

// previewInnerPage relays one rendered, inert page image of one inner file.
//
// @operationId PortalPreviewInnerPage
// @title Rendered inner-file page image
// @route /api/portal/v1/documents/{id}/data-objects/{name}/preview/pages/{n} [get].
func (r *router) previewInnerPage(ctx *azugo.Context) {
	if !r.previewReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	n, err := ctx.Params.Int("n")
	if err != nil {
		ctx.Error(err)

		return
	}

	resp, err := r.Preview().InnerPage(ctx, obo, ctx.Params.String("id"), pkweb.PathParam(ctx, "name"), n)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		ctx.Header.Set("Content-Type", ct)
	}
	ctx.Header.Set("Cache-Control", "no-store")
	ctx.Raw(resp.Body)
}

// previewInnerText relays the plain-text layer of one inner file.
//
// @operationId PortalPreviewInnerText
// @title Inner-file text layer
// @route /api/portal/v1/documents/{id}/data-objects/{name}/preview/text [get].
func (r *router) previewInnerText(ctx *azugo.Context) {
	if !r.previewReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	resp, err := r.Preview().InnerText(ctx, obo, ctx.Params.String("id"), pkweb.PathParam(ctx, "name"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	relayJSON(ctx, resp)
}

// previewReady guards the preview routes until the preview service is wired.
func (r *router) previewReady(ctx *azugo.Context) bool {
	if r.Preview() == nil {
		ctx.Error(pkerrors.NewProblem("err:preview:notConfigured",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithDetail("preview not configured")))

		return false
	}

	return true
}

// relayJSON relays a JSON upstream response (status + body) to the browser.
func relayJSON(ctx *azugo.Context, resp *clients.Response) {
	ctx.Header.Set("Content-Type", "application/json")
	ctx.StatusCode(resp.StatusCode)
	ctx.Raw(resp.Body)
}
