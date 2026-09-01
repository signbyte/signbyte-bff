// Package routes registers the Portal-API (BFF) HTTP surface: the browser-facing
// session/identity endpoints (and, in later increments, the composed document,
// envelope, and signing endpoints). The single-page app talks only to this
// service.
package routes

import (
	"errors"
	"net/url"

	"azugo.io/azugo"
	azugocfg "azugo.io/azugo/config"
	"azugo.io/azugo/middleware"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-sec-events/secevents"

	portalapi "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
)

type router struct {
	*portalapi.App

	// verifyGate caps concurrent public verify requests per client IP.
	verifyGate *inflightGate
}

// Init registers all routes. The public edge is the cookie session: anonymous
// login endpoints establish it; the rest require a valid session cookie and, on
// state-changing requests, a matching anti-forgery token.
func Init(a *portalapi.App) error {
	r := &router{App: a, verifyGate: newInflightGate(a.Config().VerifyConcurrentPerIP)}

	// Public liveness/readiness.
	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	v1 := a.Group("/api/portal/v1")

	// Session establishment (anonymous): start a login, land the callback.
	v1.Post("/login/start", r.loginStart)
	v1.Get("/login/callback", r.loginCallback)

	// eID-card login (anonymous): the card handshake runs in the browser, proxied
	// here so the app talks only to this service. Start issues the card challenge;
	// complete redeems the card token and establishes the session.
	v1.Post("/login/webeid/start", r.loginWebEIDStart)
	v1.Post("/login/webeid/complete", r.loginWebEIDComplete)

	// Public verify (anonymous by design): anyone may check a signed document
	// without an account. No session/CSRF — the anonymous-abuse gap is closed
	// by a per-client-IP token bucket here plus the in-handler concurrency gate
	// and size caps; everything else on this surface stays session-gated.
	pub := v1.Group("")
	// Outside the limiter on purpose: it sees the refusal the limiter wrote and
	// records it as a typed security event (the edge's anonymous-abuse signal).
	pub.Use(r.edgeBlockEvents())
	pub.Use(middleware.RateLimit(&azugocfg.RateLimit{
		Enabled:  true,
		Strategy: "token-bucket",
		Rate:     a.Config().VerifyRatePerMinute / 60,
		Burst:    a.Config().VerifyRateBurst,
	},
		middleware.RateLimitName("verify"),
		middleware.RateLimitKeyGenerator(func(ctx *azugo.Context) (string, error) {
			// An unresolvable address still gets limited — everyone without an
			// address shares one bucket rather than bypassing the limiter.
			if ip := verifyClientIP(ctx); ip != "" {
				return ip, nil
			}

			return "unknown", nil
		})))
	pub.Post("/verify", r.verifyDocument)

	// Authenticated by the session cookie.
	authed := v1.Group("")
	authed.Use(r.requireSession())
	authed.Get("/me", r.me)
	authed.Post("/session/refresh", r.refresh)
	authed.Post("/logout", r.logout)
	authed.Post("/step-up", r.stepUp)

	// Document composition (on the user's behalf).
	authed.Get("/dashboard", r.dashboard)
	authed.Get("/history", r.listHistory)
	authed.Delete("/history/{chainRoot}", r.deleteHistory)

	authed.Post("/documents", r.uploadDocument)
	authed.Get("/documents", r.listDocuments)
	authed.Get("/documents/{id}", r.getDocument)
	authed.Get("/documents/{id}/chain", r.getDocumentChain)
	authed.Get("/documents/{id}/download", r.downloadDocument)
	authed.Delete("/documents/{id}", r.deleteDocument)
	authed.Post("/documents/{id}/archive-timestamp", r.archiveTimestamp)
	authed.Post("/documents/{id}/validate", r.validateDocument)

	// Multi-file bundle lifecycle (on the user's behalf): eager-bundle staged
	// uploads into one unsigned ASiC-E (the draft-save commit point), rebundle on a
	// draft edit, and extract one inner file (re-stage / download an original).
	authed.Post("/documents/bundle", r.bundleDocuments)
	authed.Post("/documents/{id}/rebundle", r.rebundleDocument)
	authed.Get("/documents/{id}/data-objects/{name}", r.extractDataObject)

	// Review-only preview (on the user's behalf): the manifest, the inert page
	// images, and the text layer. The manifest fetch records the interactive
	// preview access.
	authed.Get("/documents/{id}/preview", r.previewManifest)
	authed.Get("/documents/{id}/preview/pages/{n}", r.previewPage)
	authed.Get("/documents/{id}/preview/text", r.previewText)

	// The same preview surface for one inner file of an ASiC-E container.
	authed.Get("/documents/{id}/data-objects/{name}/preview", r.previewInnerManifest)
	authed.Get("/documents/{id}/data-objects/{name}/preview/pages/{n}", r.previewInnerPage)
	authed.Get("/documents/{id}/data-objects/{name}/preview/text", r.previewInnerText)

	// Signing composition (on the user's behalf): the job status poll, the
	// in-browser card-signature submit, abandon, and the validation answer. Signing
	// always begins through an envelope slot (POST /envelopes/{id}/slots/{slot}/sign)
	// — a solo self-sign is a one-slot envelope, the same path as co-signing.
	authed.Get("/signings/{jobId}/status", r.signingStatus)
	authed.Post("/signings/{jobId}/client-signature", r.clientSignature)
	authed.Post("/signings/{jobId}/abandon", r.abandonSigning)
	authed.Get("/signatures/{sigId}/validation", r.signatureValidation)
	// A blocked co-signer's "wait until the other party finishes" long-poll (PDF co-sign).
	authed.Get("/chain-free", r.chainFree)

	// Envelope composition (on the user's behalf): create + list + the composed
	// detail view, attach documents, add slots, the lifecycle transitions, and the
	// per-slot signing trigger that begins signing for a slot once it is eligible.
	authed.Post("/envelopes", r.createEnvelope)
	authed.Get("/envelopes", r.listEnvelopes)
	// The signer inbox — envelopes awaiting the user's signature as an invited co-signer.
	authed.Get("/signing-tasks", r.listSigningTasks)
	authed.Get("/envelopes/{id}", r.getEnvelope)
	authed.Post("/envelopes/{id}/documents", r.attachEnvelopeDocument)
	authed.Post("/envelopes/{id}/slots", r.addEnvelopeSlot)
	authed.Post("/envelopes/{id}/send", r.sendEnvelope)
	authed.Post("/envelopes/{id}/cancel", r.cancelEnvelope)
	authed.Post("/envelopes/{id}/reopen", r.reopenEnvelope)
	authed.Post("/envelopes/{id}/slots/{slot}/decline", r.declineEnvelopeSlot)
	authed.Post("/envelopes/{id}/slots/{slot}/sign", r.signEnvelopeSlot)

	return nil
}

// edgeBlockEvents wraps the public (anonymous) group from OUTSIDE the rate
// limiter and records a rate-limit refusal as a typed security event. A plain
// request log line cannot be triaged as abuse; the typed event can — and this
// edge is the only place that sees the anonymous surface at all. Emission is
// best-effort and happens after the response is already written, so it can
// never change what the caller receives.
func (r *router) edgeBlockEvents() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			next(ctx)

			if ctx.Response().StatusCode() != fasthttp.StatusTooManyRequests {
				return
			}

			sec := r.SecEvents()
			if sec == nil {
				return
			}
			if err := sec.EdgeBlock(ctx, secevents.Edge{
				IP:     verifyClientIP(ctx),
				Rule:   "verify_rate_limit",
				Reason: "public verify rate limit exceeded",
			}); err != nil {
				ctx.Log().Error("secevents edge-block emit failed", zap.Error(err))
			}
		}
	}
}

// relayErr renders the error the BFF returns for a failed on-behalf call to an
// upstream service. It decodes the downstream problem envelope and preserves the
// terminal code, source, and trace id — appending this service to the internal hop
// chain and choosing the outer status deliberately — so the caller sees the real,
// traceable cause instead of an opaque gateway error. A client-actionable status is
// relayed unchanged (a 404 stays a 404); a downstream server error or an unreachable
// upstream becomes a gateway error (502) that still carries the terminal envelope. It
// never collapses a parsed downstream error into a bare 502.
func (r *router) relayErr(ctx *azugo.Context, err error) {
	var he *clients.HTTPError
	if errors.As(err, &he) {
		outer := he.StatusCode
		if outer >= fasthttp.StatusInternalServerError {
			outer = fasthttp.StatusBadGateway
		}

		down, _ := pkerrors.ParseProblem([]byte(he.Body))
		ctx.Error(pkerrors.Relay(down, r.AppName, outer))

		return
	}

	// No HTTP response at all — a genuine transport failure (upstream unreachable);
	// log the cause off the wire.
	ctx.Log().Error("upstream call failed", zap.Error(err))
	ctx.Error(pkerrors.Relay(nil, r.AppName, fasthttp.StatusBadGateway))
}

// redirectWithError sends the browser back to the app entry point with a generic
// error marker (never an internal detail).
func (r *router) redirectWithError(ctx *azugo.Context, marker string) {
	ctx.StatusCode(fasthttp.StatusFound)
	// PostLoginURL is the SPA origin (cross-origin) — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(r.Config().PostLoginURL + "?error=" + url.QueryEscape(marker))
}
