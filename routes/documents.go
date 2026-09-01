package routes

import (
	"bytes"
	"io"
	"mime/multipart"

	"github.com/signbyte/signbyte-bff/asclient"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/routes/response"

	"azugo.io/azugo"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	pkweb "github.com/gmb-lib/go-platform-kit/web"
	"github.com/valyala/fasthttp"
)

// uploadDocument forwards the user's upload to the document service on the user's
// behalf, so the stored document is owned by the user.
//
// @operationId PortalUploadDocument
// @title Upload a document
// @route /api/portal/v1/documents [post].
func (r *router) uploadDocument(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	// The upload is multipart/form-data; read the file + the caller's fields and
	// re-encode them for the document service (the framework parses multipart into
	// the form, so the raw body is not forwardable verbatim).
	fh, err := ctx.Form.File("file")
	if err != nil {
		ctx.Error(err) // ParamRequiredError → 400 when the file part is absent

		return
	}
	data, err := readUpload(fh)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	fields := map[string]string{}
	if pc := ctx.Form.StringOptional("preservation_class"); pc != nil {
		fields["preservation_class"] = *pc
	}
	if m := ctx.Form.StringOptional("mime"); m != nil {
		fields["mime"] = *m
	}

	body, contentType, err := encodeUpload("file", fh.Filename, data, fields)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	meta, err := r.Documents().Upload(ctx, obo, contentType, body)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(meta)
}

// readUpload reads an uploaded file part fully into memory.
func readUpload(fh *multipart.FileHeader) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return io.ReadAll(f)
}

// encodeUpload builds a single-file multipart/form-data body plus the extra text
// fields the document service expects, and returns it with its Content-Type.
func encodeUpload(field, filename string, data []byte, fields map[string]string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", err
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}

// listDocuments returns a page of the caller's own documents for the library view.
//
// @operationId PortalListDocuments
// @title List documents
// @route /api/portal/v1/documents [get].
func (r *router) listDocuments(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	limit := 0
	if l, err := ctx.Query.IntOptional("limit"); err == nil && l != nil {
		limit = *l
	}
	after := ""
	if a := ctx.Query.StringOptional("after"); a != nil {
		after = *a
	}

	out, err := r.Documents().List(ctx, obo, limit, after)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// getDocument returns a document's metadata (the user's own document).
//
// @operationId PortalGetDocument
// @title Document metadata
// @route /api/portal/v1/documents/{id} [get].
func (r *router) getDocument(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	meta, err := r.Documents().Metadata(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(meta)
}

// getDocumentChain returns ONE document chain as its live head — what the
// document screen states about it: signed here or merely uploaded signed, its
// preservation class, its retention horizon, whether a signing workflow has the
// result frozen, and what is inside the container.
//
// It is addressed by any id in the chain (its root or its head), and it answers
// independently of the dashboard listing. That independence is the point: the
// listing collapses a chain into the envelope that covers it and it pages, so a
// screen that took its facts from the listing lost them the moment a workflow
// touched the document — and rendered a completed signing as an unsigned draft.
//
// @operationId PortalGetDocumentChain
// @title Document chain
// @route /api/portal/v1/documents/{id}/chain [get].
func (r *router) getDocumentChain(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	chain, err := r.Documents().GetChain(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(chain)
}

// downloadDocument streams a document's bytes to the browser, relaying the content
// type and filename from the document service.
//
// @operationId PortalDownloadDocument
// @title Download a document
// @route /api/portal/v1/documents/{id}/download [get].
func (r *router) downloadDocument(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	resp, err := r.Documents().Content(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	// Record the user-facing personal-data access: the person retrieved their
	// document's bytes through the browser. Routine and fail-open — never blocks the
	// download.
	r.Audit().DocumentDownloaded(ctx, obo.Sub, ctx.Params.String("id"))

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		ctx.Header.Set("Content-Type", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		ctx.Header.Set("Content-Disposition", cd)
	}
	// Guaranteed at this boundary too, not just relayed: the browser must
	// honour the declared Content-Type rather than sniff its way into
	// rendering an uploaded file as active script content.
	ctx.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Raw(resp.Body)
}

// deleteDocument removes the user's document before its retention window lapses.
//
// @operationId PortalDeleteDocument
// @title Delete a document
// @success 200 OK response.OK "Deleted"
// @route /api/portal/v1/documents/{id} [delete].
func (r *router) deleteDocument(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	if err := r.Documents().Delete(ctx, obo, ctx.Params.String("id")); err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(&response.OK{OK: true})
}

// archiveTimestamp refreshes the user's signed document with a qualified
// archive timestamp (B-LT → B-LTA), via the signing orchestrator on the user's
// behalf. The document keeps its id — its bytes are replaced in place with the
// archived form, so the dashboard row and the hub simply show the refreshed head.
//
// @operationId PortalArchiveTimestamp
// @title Add an archive timestamp to a signed document
// @route /api/portal/v1/documents/{id}/archive-timestamp [post].
func (r *router) archiveTimestamp(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	// The timestamp request is made in the acting user's name: their
	// authentication certificate rides along — the login-captured one, or the
	// card login's for an eID-card session.
	authCert := ""
	if _, sess := sessionFromCtx(ctx); sess != nil {
		if sess.Capabilities != nil && sess.Capabilities.AuthCertificate != "" {
			authCert = sess.Capabilities.AuthCertificate
		} else {
			authCert = sess.SigningAuthCert
		}
	}
	// No captured certificate on this session (an older session, a lost cache,
	// a login whose capture failed): the fallback is to CAPTURE one — the app
	// sends the user through a re-authentication (the step-up flow, same
	// method), whose completion re-captures the session's capabilities; this
	// call then succeeds on retry. Refused here, precisely, before any
	// upstream traffic.
	if authCert == "" {
		ctx.Error(pkerrors.NewProblem("err:signing:authCertificateRequired",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithDetail("no authentication certificate is captured on this session; re-authenticate and retry")))

		return
	}

	out, err := r.Signflow().ArchiveTimestamp(ctx, obo, ctx.Params.String("id"), authCert)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// validateDocument validates the user's signed document on demand (an uploaded
// already-signed file, or any signed head) and relays the normalized answer.
// Nothing is persisted — repeatable evidence-on-request.
//
// @operationId PortalValidateDocument
// @title Validate a signed document on demand
// @route /api/portal/v1/documents/{id}/validate [post].
func (r *router) validateDocument(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	// Render-recent: a repeat Validate press within the window serves the
	// just-produced answer; ?force=1 runs a fresh upstream round.
	key := answerKey(obo.Sub, "doc", ctx.Params.String("id"))
	if r.serveCachedAnswer(ctx, key) {
		return
	}

	out, err := r.Signflow().ValidateDocument(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	r.storeAnswer(ctx, key, out)
	ctx.JSON(out)
}

// listHistory returns the user's history — terminal chains whose storage is
// destroyed, listed as records for the platform's bounded keep window.
//
// @operationId PortalListHistory
// @title List history records
// @route /api/portal/v1/history [get].
func (r *router) listHistory(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	limit := 0
	if l, err := ctx.Query.IntOptional("limit"); err == nil && l != nil {
		limit = *l
	}
	after := ""
	if a := ctx.Query.StringOptional("after"); a != nil {
		after = *a
	}

	out, err := r.Documents().ListHistory(ctx, obo, limit, after)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// deleteHistory removes one of the user's history records early.
//
// @operationId PortalDeleteHistory
// @title Remove a history record
// @route /api/portal/v1/history/{chainRoot} [delete].
func (r *router) deleteHistory(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	if err := r.Documents().DeleteHistory(ctx, obo, ctx.Params.String("chainRoot")); err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(&response.OK{OK: true})
}

// bundleRequest is the eager-bundle input: the staged loose source ids in final
// (sender-set) order — that order is the container's inner-file order.
type bundleRequest struct {
	SourceIDs []string `json:"sourceIds"`
}

// rebundleRequest is the draft-edit input: the bundle's entries in final order (an
// existing inner file by name, or a newly staged loose source by id).
type rebundleRequest struct {
	Entries []clients.BundleEntry `json:"entries"`
}

// bundleDocuments packages the user's staged loose uploads into ONE unsigned ASiC-E
// bundle on the user's behalf — the eager draft-save commit point. The whole set
// signs together under one signature, and (because the set is a container from the
// moment it is staged) an abandoned wizard leaves one bundle row rather than a pile
// of loose drafts. The loose sources are absorbed by the document service.
//
// @operationId PortalBundleDocuments
// @title Bundle staged documents
// @route /api/portal/v1/documents/bundle [post].
func (r *router) bundleDocuments(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	var req bundleRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	meta, err := r.Documents().Bundle(ctx, obo, req.SourceIDs)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(meta)
}

// rebundleDocument rebuilds the user's unsigned bundle from the given entries in
// final order — a draft edit (add / remove / reorder inner files) on the user's
// behalf. Existing inner files are kept by name; newly staged loose sources are
// added by id and absorbed.
//
// @operationId PortalRebundleDocument
// @title Rebundle an unsigned bundle
// @route /api/portal/v1/documents/{id}/rebundle [post].
func (r *router) rebundleDocument(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	var req rebundleRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	meta, err := r.Documents().Rebundle(ctx, obo, ctx.Params.String("id"), req.Entries)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(meta)
}

// extractDataObject streams one named inner file out of the user's ASiC-E container
// on the user's behalf. A multi-file bundle absorbs its originals, so the container
// is an inner file's only home — this is how the wizard re-stages a file when a
// bundle dissolves back to a single natively-signed PDF, and how an original is
// pulled on demand. The document service records the personal-data access.
//
// @operationId PortalExtractDataObject
// @title Extract one inner file
// @route /api/portal/v1/documents/{id}/data-objects/{name} [get].
func (r *router) extractDataObject(ctx *azugo.Context) {
	if !r.documentsReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	resp, err := r.Documents().ExtractObject(ctx, obo, ctx.Params.String("id"), pkweb.PathParam(ctx, "name"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		ctx.Header.Set("Content-Type", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		ctx.Header.Set("Content-Disposition", cd)
	}
	// Honour the declared type rather than sniff an uploaded file into active content.
	ctx.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Raw(resp.Body)
}

// documentsReady guards the document routes until the document service is wired.
func (r *router) documentsReady(ctx *azugo.Context) bool {
	if r.Documents() == nil {
		ctx.Error(pkerrors.NewProblem("err:document:notConfigured",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithDetail("document composition not configured")))

		return false
	}

	return true
}

// onBehalf builds the delegation context for the current session, refreshing the
// access token first if it is near expiry. On failure it writes the response and
// returns false.
func (r *router) onBehalf(ctx *azugo.Context) (clients.OnBehalf, bool) {
	sid, sess := sessionFromCtx(ctx)

	token, err := r.freshToken(ctx, sid, sess)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:unauthorized",
			pkerrors.WithDetail("session could not be refreshed")))

		return clients.OnBehalf{}, false
	}

	return clients.OnBehalf{
		Sub:   sess.Subject,
		Token: token,
		// Scope the delegated-token cache to the session's login binding so a
		// re-login as the same person with a different method never reuses a token
		// carrying the old method (which signflow's login⇒flow gate would reject).
		Binding: asclient.LoginBindingFromToken(token),
	}, true
}
