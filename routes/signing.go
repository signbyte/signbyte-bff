package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/routes/request"
)

// flowWebEid is the in-browser card flow: the SPA reads the card certificates and
// signs the digests the orchestrator returns.
const (
	flowWebEid = "webEid"
	// flowEseal is the organisation e-seal flow's wire name across the signing
	// pipeline (the seal rides eParaksts Mobile server-side signing).
	flowEseal = "eparakstsMobileEseal"
)

// maxStatusWait caps the status long-poll window the SPA can request, so one held
// request can never tie up a worker indefinitely. The SPA loops short long-polls
// rather than asking for one long hold.
const maxStatusWait = 10

// signingStatus polls a job to completion.
//
// @operationId PortalSigningStatus
// @title Signing status
// @route /api/portal/v1/signings/{jobId}/status [get].
func (r *router) signingStatus(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	// An optional ?wait=<seconds> turns this into a long-poll (clamped) so the SPA's
	// post-approval wait answers the instant the seal lands instead of tight-looping.
	wait := 0
	if w, err := ctx.Query.IntOptional("wait"); err == nil && w != nil {
		wait = *w
		if wait > maxStatusWait {
			wait = maxStatusWait
		}
	}

	job, err := r.Signflow().Status(ctx, obo, ctx.Params.String("jobId"), wait)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(job)
}

// clientSignature submits the in-browser (card) signature back to a job.
//
// @operationId PortalClientSignature
// @title Submit client signature
// @route /api/portal/v1/signings/{jobId}/client-signature [post].
func (r *router) clientSignature(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	var req request.ClientSignature
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	sigs := make([]clients.ClientSignature, len(req.Signatures))
	for i, s := range req.Signatures {
		sigs[i] = clients.ClientSignature{DocumentID: s.DocumentID, SignatureValue: s.SignatureValue}
	}

	job, err := r.Signflow().SubmitClientSignature(ctx, obo, ctx.Params.String("jobId"), sigs)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(job)
}

// abandonSigning releases a signing attempt's chain lock without declining the slot —
// the user cancelled at the provider or picked the wrong method and will retry, so a
// waiting co-signer is unblocked at once instead of waiting out the lock's TTL.
//
// @operationId PortalAbandonSigning
// @title Abandon a signing attempt
// @route /api/portal/v1/signings/{jobId}/abandon [post].
func (r *router) abandonSigning(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	if err := r.Signflow().Abandon(ctx, obo, ctx.Params.String("jobId")); err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// chainFree long-polls whether an envelope's PDF chain is free to sign (no other party
// is mid-signing), so a blocked co-signer waits for a live signal instead of a
// misleading countdown or tight polling.
//
// @operationId PortalChainFree
// @title Wait until the signing chain is free
// @route /api/portal/v1/chain-free [get].
func (r *router) chainFree(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	envelopeID, _ := ctx.Query.String("envelopeId")
	if envelopeID == "" {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("envelopeId is required")))

		return
	}

	wait := 0
	if w, err := ctx.Query.IntOptional("wait"); err == nil && w != nil {
		wait = *w
		if wait > maxStatusWait {
			wait = maxStatusWait
		}
	}

	free, err := r.Signflow().ChainFree(ctx, obo, envelopeID, wait)
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	ctx.JSON(map[string]bool{"free": free})
}

// signatureValidation returns the normalized validation answer for a recorded
// signature.
//
// @operationId PortalSignatureValidation
// @title Signature validation
// @route /api/portal/v1/signatures/{sigId}/validation [get].
func (r *router) signatureValidation(ctx *azugo.Context) {
	if !r.signingReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	// Render-recent: the post-sign fetch of a just-produced answer is a cache
	// hit rather than a fresh upstream validation round; ?force=1 re-validates.
	key := answerKey(obo.Sub, "sig", ctx.Params.String("sigId"))
	if r.serveCachedAnswer(ctx, key) {
		return
	}

	out, err := r.Signflow().Validate(ctx, obo, ctx.Params.String("sigId"))
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	r.storeAnswer(ctx, key, out)
	ctx.JSON(out)
}

// signingReady guards the signing routes until the orchestrator is wired.
func (r *router) signingReady(ctx *azugo.Context) bool {
	if r.Signflow() == nil {
		ctx.Error(pkerrors.NewProblem("err:signing:notConfigured",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithDetail("signing composition not configured")))

		return false
	}

	return true
}
