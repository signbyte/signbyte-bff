package routes

import (
	"strings"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signbyte-bff/asclient"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/routes/request"
	"github.com/signbyte/signbyte-bff/session"
)

// createEnvelope creates a signing envelope on the user's behalf. The envelope
// service derives the owner from the delegated identity; the app supplies the
// title, ordering policy, and any initial documents and slots.
//
// @operationId PortalCreateEnvelope
// @title Create an envelope
// @route /api/portal/v1/envelopes [post].
func (r *router) createEnvelope(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	var req request.CreateEnvelope
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	// A multi-document set becomes ONE unsigned ASiC-E bundle at this commit
	// point (the document service absorbs the loose uploads), so the envelope
	// holds a single document ref and every signer signs the whole set. One
	// document keeps today's plain path — no bundle.
	docs := req.Documents
	if len(docs) >= 2 {
		bundle, err := r.Documents().Bundle(ctx, obo, docs)
		if err != nil {
			r.relayErr(ctx, err)

			return
		}
		docs = []string{bundle.ID}
	}

	in := clients.CreateInput{
		Title:       req.Title,
		OrderPolicy: req.OrderPolicy,
		Profile:     req.Profile,
		Documents:   docs,
	}
	for _, s := range req.Slots {
		in.Slots = append(in.Slots, clients.SlotInput{
			OrderIndex:  s.OrderIndex,
			Role:        s.Role,
			Flow:        s.Flow,
			RequiredLoa: s.RequiredLoa,
			IdentityRef: s.IdentityRef,
		})
	}

	out, err := r.Envelope().Create(ctx, obo, in)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(out)
}

// listEnvelopes returns a page of the user's envelopes.
//
// @operationId PortalListEnvelopes
// @title List envelopes
// @route /api/portal/v1/envelopes [get].
func (r *router) listEnvelopes(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	// ?documentId= turns the listing into a targeted lookup: the envelopes covering
	// that one document which the user may see (owner or matched participant) —
	// how the document hub resolves the envelope carrying a document.
	if d := ctx.Query.StringOptional("documentId"); d != nil && *d != "" {
		out, err := r.Envelope().FindForDocument(ctx, obo, *d)
		if err != nil {
			r.relayErr(ctx, err)

			return
		}
		ctx.JSON(out)

		return
	}

	limit := 0
	if l, err := ctx.Query.IntOptional("limit"); err == nil && l != nil {
		limit = *l
	}
	cursor := ""
	if c := ctx.Query.StringOptional("cursor"); c != nil {
		cursor = *c
	}

	out, err := r.Envelope().List(ctx, obo, limit, cursor)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// listSigningTasks returns the user's signer inbox — the envelopes awaiting their
// signature as an invited co-signer (not the ones they own). Surfaced on Home as
// "Awaiting your signature". The envelope service matches the user to the slots invited
// to their authenticated identity, so this returns only envelopes they are a party to.
//
// @operationId PortalListSigningTasks
// @title Signer inbox
// @route /api/portal/v1/signing-tasks [get].
func (r *router) listSigningTasks(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
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
	cursor := ""
	if c := ctx.Query.StringOptional("cursor"); c != nil {
		cursor = *c
	}

	out, err := r.Envelope().SigningTasks(ctx, obo, limit, cursor)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// getEnvelope returns the composed envelope view: the envelope service's header,
// slots, and documents, with each slot that has a backing signing job enriched
// with that job's live signing state. A slot whose live state cannot be read is
// left without it rather than failing the whole view.
//
// @operationId PortalGetEnvelope
// @title Envelope detail
// @route /api/portal/v1/envelopes/{id} [get].
func (r *router) getEnvelope(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	detail, err := r.Envelope().Get(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	// The viewer's eIDAS code, to mark their own slot. The composed view is read by
	// both the owner and an invited co-signer (a different person), so "you" must be
	// resolved against the viewer's identity, not assumed to be the owner.
	viewerSerial := asclient.SerialFromToken(obo.Token)
	// The owner may see the identity codes they entered for the invited signers; any other
	// viewer (a co-signer) never sees another party's code.
	isOwnerViewer := detail.Envelope.Owner == obo.Sub

	slots := make([]composedSlot, len(detail.Slots))
	for i, s := range detail.Slots {
		slots[i] = composedSlot{Slot: s}
		// Durable container reference: the signed_doc_ref the envelope already records for
		// a signed slot. The live job below refines it while signing is in flight, but the
		// download affordance must outlive the job — so seed it from the persisted ref, or a
		// completed envelope loses its download once the signing job is gone.
		slots[i].ContainerID = s.SignedDocRef
		// The viewer's own slot: an invited signer matched by eIDAS code, or — for the
		// owner — their own (identity-code-less) slot.
		slots[i].You = (s.IdentityRef != "" && s.IdentityRef == viewerSerial) ||
			(s.IdentityRef == "" && detail.Envelope.Owner == obo.Sub)
		// Drop other signers' identity codes unless the viewer is the owner (who entered
		// them) — a co-signer must never receive another party's code.
		if !isOwnerViewer {
			slots[i].IdentityRef = ""
		}
		if s.JobID == "" || r.Signflow() == nil {
			continue
		}
		job, err := r.Signflow().Status(ctx, obo, s.JobID, 0)
		if err != nil {
			// The slot's live state is unavailable right now; the envelope and the
			// rest of the slots are still returned. The signing service also reports
			// completion through its own callback, so this is not the only path.
			ctx.Log().Debug("slot live signing state unavailable")

			continue
		}
		slots[i].State = job.State
		if job.SignatureID != "" {
			slots[i].SignatureID = job.SignatureID
		}
		// Refine with the live job's container only when it has one; never blank the
		// durable ref seeded above (a job mid-flight or with no container yet must not
		// erase the download affordance of an already-signed slot).
		if job.ContainerID != "" {
			slots[i].ContainerID = job.ContainerID
		}
	}

	// Capture the viewer's own name from their authenticated identity (server-side, never
	// client-supplied) the first time they open the envelope, so every party is shown who
	// is who. Inject it into this response and persist it (write-once) for others' future
	// opens. Best-effort — a failure never blocks the view.
	for i := range slots {
		if !slots[i].You || slots[i].SignerName != "" {
			continue
		}
		if name := r.viewerName(ctx); name != "" {
			slots[i].SignerName = name
			if err := r.Envelope().CaptureSignerName(ctx, obo, ctx.Params.String("id"), slots[i].ID, name); err != nil {
				ctx.Log().Debug("capture signer name failed")
			}
		}

		break
	}

	// Resolve each attached document's filename for display. The envelope service holds
	// only the document id + content hash, so the name comes from the document service.
	// Best-effort per document: a lookup miss leaves the filename empty and the app falls
	// back to showing the id, rather than failing the whole view.
	docs := detail.Documents
	if r.Documents() != nil {
		docs = make([]clients.DocRef, len(detail.Documents))
		for i, d := range detail.Documents {
			docs[i] = d
			meta, err := r.Documents().Metadata(ctx, obo, d.DocumentID)
			if err != nil {
				ctx.Log().Debug("document filename unavailable")

				continue
			}
			docs[i].Filename = meta.Filename
		}
	}

	ctx.JSON(composedDetail{
		Envelope:  detail.Envelope,
		Slots:     slots,
		Documents: docs,
	})
}

// composedSlot is a slot enriched with the live signing state of its backing job.
type composedSlot struct {
	clients.Slot
	State       string `json:"state,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
	// You marks the viewing user's own slot — the invited signer matched by their
	// eIDAS code, or the owner's slot — so the app shows "your turn" and the sign
	// action against the right slot rather than assuming the viewer is the owner.
	You bool `json:"you"`
}

// composedDetail is the envelope view returned to the app.
type composedDetail struct {
	Envelope  clients.EnvelopeView `json:"envelope"`
	Slots     []composedSlot       `json:"slots"`
	Documents []clients.DocRef     `json:"documents"`
}

// viewerName resolves the logged-in user's display name from their authenticated identity
// (server-side, never client-supplied) — the name captured onto their envelope slot.
// Best-effort: returns "" on any failure so it never blocks the envelope view.
func (r *router) viewerName(ctx *azugo.Context) string {
	if r.AuthService() == nil {
		return ""
	}
	sid, sess := sessionFromCtx(ctx)
	if sess == nil {
		return ""
	}
	token, err := r.freshToken(ctx, sid, sess)
	if err != nil {
		return ""
	}
	key, err := session.ParseKey(sess.Key)
	if err != nil {
		return ""
	}
	id, err := r.AuthService().Identity(ctx, key, token)
	if err != nil || id == nil {
		return ""
	}
	if name := strings.TrimSpace(id.Name); name != "" {
		return name
	}

	return strings.TrimSpace(id.GivenName + " " + id.FamilyName)
}

// attachEnvelopeDocument attaches an existing document to an envelope.
//
// @operationId PortalAttachEnvelopeDocument
// @title Attach a document
// @route /api/portal/v1/envelopes/{id}/documents [post].
func (r *router) attachEnvelopeDocument(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	var req request.AttachDocument
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	out, err := r.Envelope().AttachDocument(ctx, obo, ctx.Params.String("id"), req.DocumentID)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(out)
}

// addEnvelopeSlot adds a signer slot to an envelope.
//
// @operationId PortalAddEnvelopeSlot
// @title Add a slot
// @route /api/portal/v1/envelopes/{id}/slots [post].
func (r *router) addEnvelopeSlot(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	var req request.AddSlot
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	id, err := r.Envelope().AddSlot(ctx, obo, ctx.Params.String("id"), clients.SlotInput{
		OrderIndex:  req.OrderIndex,
		Role:        req.Role,
		Flow:        req.Flow,
		RequiredLoa: req.RequiredLoa,
		IdentityRef: req.IdentityRef,
	})
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(map[string]string{"id": id})
}

// sendEnvelope moves an envelope out of draft into the active signing lifecycle.
//
// @operationId PortalSendEnvelope
// @title Send an envelope
// @route /api/portal/v1/envelopes/{id}/send [post].
func (r *router) sendEnvelope(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	out, err := r.Envelope().Send(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// cancelEnvelope cancels an envelope.
//
// @operationId PortalCancelEnvelope
// @title Cancel an envelope
// @route /api/portal/v1/envelopes/{id}/cancel [post].
func (r *router) cancelEnvelope(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	out, err := r.Envelope().Cancel(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// reopenEnvelope takes a completed envelope back to draft for a further signature, so
// the envelope stays the chain's workflow home instead of a new one being minted over
// the same container each time it is signed.
//
// @operationId PortalReopenEnvelope
// @title Reopen a completed envelope for a further signature
// @route /api/portal/v1/envelopes/{id}/reopen [post].
func (r *router) reopenEnvelope(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	out, err := r.Envelope().Reopen(ctx, obo, ctx.Params.String("id"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// declineEnvelopeSlot records that the signer for a slot declined to sign.
//
// @operationId PortalDeclineEnvelopeSlot
// @title Decline a slot
// @route /api/portal/v1/envelopes/{id}/slots/{slot}/decline [post].
func (r *router) declineEnvelopeSlot(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	out, err := r.Envelope().DeclineSlot(ctx, obo, ctx.Params.String("id"), ctx.Params.String("slot"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(out)
}

// signEnvelopeSlot begins signing for one slot on the user's behalf. The slot
// must be eligible to sign now (under the envelope's ordering policy an earlier
// slot may need to be signed first); otherwise the trigger is refused. On a
// successful start the resulting job is recorded against the slot so the envelope
// view can later reconcile the slot's live signing state. The returned job
// carries the redirect a remote flow needs.
//
// @operationId PortalSignEnvelopeSlot
// @title Sign an envelope slot
// @route /api/portal/v1/envelopes/{id}/slots/{slot}/sign [post].
func (r *router) signEnvelopeSlot(ctx *azugo.Context) {
	if !r.envelopeReady(ctx) || !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	id := ctx.Params.String("id")
	slot := ctx.Params.String("slot")

	var req request.SignSlot
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	// The in-browser flow needs both card certificates. The signing certificate is a
	// PIN-less card read the app supplies; the authentication certificate is reused
	// from the card login (captured in the session) so the card is not authenticated
	// a second time at signing — falling back to an app-supplied one if present.
	authCert := req.AuthCertificate
	_, sess := sessionFromCtx(ctx)
	if authCert == "" && sess != nil {
		authCert = sess.SigningAuthCert
	}

	// Redirect flows: thread the login-captured identity so the signing
	// provider skips its own identity-resolution leg (one identification per
	// session). Best-effort — whatever is missing, the provider resolves
	// itself; the request never fails over absent capabilities.
	var signingCert, signIdentityID string
	if sess != nil && sess.Capabilities != nil && req.Flow != flowWebEid {
		caps := sess.Capabilities
		switch req.Flow {
		case flowEseal:
			// The seal IS the signing identity. With a seal id picked, use
			// that seal's captured identity; a session with exactly one seal
			// needs no pick.
			seals := caps.Seals
			if req.SealID == "" && len(seals) == 1 {
				signIdentityID, signingCert = seals[0].ID, seals[0].Certificate
			}
			for _, s := range seals {
				if s.ID == req.SealID {
					signIdentityID, signingCert = s.ID, s.Certificate

					break
				}
			}
		default:
			signIdentityID, signingCert = caps.SignIdentityID, caps.SigningCertificate
		}
		if authCert == "" {
			authCert = caps.AuthCertificate
		}
	}
	if req.Flow == flowWebEid && (req.SigningCertificate == "" || authCert == "") {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("a signing certificate is required for the webEid flow; the authentication certificate comes from your card login")))

		return
	}

	eligible, err := r.Envelope().SlotEligible(ctx, obo, id, slot)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}
	if !eligible {
		ctx.Error(pkerrors.NewProblem("err:envelope:notEligible",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithDetail("an earlier slot must be signed first")))

		return
	}

	// A redirect flow leaves the page to the signing provider; supply the URLs the
	// provider returns the browser to so the app resumes on this slot's signing screen
	// and polls to completion. The in-browser flow never leaves the page, so it gets
	// none. The targets are built from this service's own config — never from client
	// input.
	var postAuthRedirect, authErrorRedirect string
	if req.Flow != flowWebEid {
		postAuthRedirect, authErrorRedirect = r.Config().SigningSlotReturnURLs(id, slot)
	}

	// The in-browser flow's signing certificate is the app-supplied card read;
	// a redirect flow's is the login-captured one (when present).
	if signingCert == "" {
		signingCert = req.SigningCertificate
	}

	job, err := r.Signflow().BeginSigning(ctx, obo, clients.BeginInput{
		EnvelopeID:         id,
		SlotID:             slot,
		Flow:               req.Flow,
		SigFormat:          req.SigFormat,
		DocumentID:         req.DocumentID,
		SigningCertificate: signingCert,
		AuthCertificate:    authCert,
		SignIdentityID:     signIdentityID,
		SealID:             req.SealID,
		PostAuthRedirect:   postAuthRedirect,
		AuthErrorRedirect:  authErrorRedirect,
	})
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	// Record the job on the slot so the envelope view can reconcile its live state.
	// Best effort: a failure here does not lose the job, since the signing service
	// also reports completion through its own callback.
	if err := r.Envelope().SetSlotJob(ctx, obo, id, slot, job.JobID); err != nil {
		ctx.Log().Warn("recording signing job on slot failed")
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(job)
}

// envelopeReady guards the envelope routes until the envelope service is wired.
func (r *router) envelopeReady(ctx *azugo.Context) bool {
	if r.Envelope() == nil {
		ctx.Error(pkerrors.NewProblem("err:envelope:notConfigured",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithDetail("envelope composition not configured")))

		return false
	}

	return true
}
