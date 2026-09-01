package routes

import (
	"encoding/json"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signbyte-bff/asclient"
	"github.com/signbyte/signbyte-bff/routes/request"
	"github.com/signbyte/signbyte-bff/routes/response"
	"github.com/signbyte/signbyte-bff/session"
)

// loginWebEIDStart begins an eID-card login. Unlike the redirect methods there is
// no browser navigation: this mints the per-session key + proof-key, asks the Auth
// Service for a card challenge, parks the flow, and hands the challenge nonce back
// to the app. The app signs the nonce with the card (in the browser) and posts the
// token to the completion endpoint. Anonymous.
//
// @operationId PortalWebEIDStart
// @title Begin eID-card login
// @route /api/portal/v1/login/webeid/start [post].
func (r *router) loginWebEIDStart(ctx *azugo.Context) {
	key, err := asclient.GenerateKey()
	if err != nil {
		r.fail(ctx, err)

		return
	}
	keyEnc, err := session.MarshalKey(key)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	verifier, challenge, err := asclient.PKCE()
	if err != nil {
		r.fail(ctx, err)

		return
	}
	spaState, err := asclient.RandomToken(24)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	nonce, flow, err := r.AuthService().WebEIDChallenge(ctx, challenge, spaState)
	if err != nil {
		ctx.Log().Warn("web eid challenge failed")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return
	}

	// Park the flow under the Auth Service's handle so the completion can redeem it
	// with the same key the issued token will be bound to.
	if err := r.Sessions().PutFlow(ctx, flow, &session.Flow{Key: keyEnc, Verifier: verifier}); err != nil {
		r.fail(ctx, err)

		return
	}

	ctx.JSON(&response.WebEIDChallenge{Nonce: nonce, State: flow})
}

// loginWebEIDComplete finishes an eID-card login: it redeems the card token for an
// authorization code, exchanges that for a key-bound token, and establishes the
// cookie session. Returns JSON (no navigation); the app then loads the session.
// Anonymous (the single-use flow handle is the guard).
//
// @operationId PortalWebEIDComplete
// @title Complete eID-card login
// @success 200 OK response.OK "Logged in"
// @route /api/portal/v1/login/webeid/complete [post].
func (r *router) loginWebEIDComplete(ctx *azugo.Context) {
	var req request.WebEIDComplete
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	flow, err := r.Sessions().TakeFlow(ctx, req.State)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:flowExpired",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("login flow expired or unknown")))

		return
	}

	key, err := session.ParseKey(flow.Key)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	code, err := r.AuthService().WebEIDLogin(ctx, req.State, req.AuthToken)
	if err != nil {
		ctx.Log().Warn("web eid login failed")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return
	}

	tokens, err := r.AuthService().ExchangeCode(ctx, key, code, flow.Verifier)
	if err != nil {
		ctx.Log().Warn("token exchange failed")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return
	}

	// Capture the card's authentication certificate from the login token, so signing
	// can reuse it as the finalize auth certificate without a second card auth — the
	// login already proved possession of this card.
	if err := r.establishSession(ctx, flow.Key, tokens, authCertFromToken(req.AuthToken)); err != nil {
		r.fail(ctx, err)

		return
	}

	ctx.JSON(&response.OK{OK: true})
}

// authCertFromToken extracts the Web eID authentication certificate (the login
// token's unverifiedCertificate, base64 DER) so it can be reused as the signing
// finalize auth certificate. Returns "" when the token is not the expected shape;
// signing then falls back to a client-supplied auth certificate.
func authCertFromToken(raw json.RawMessage) string {
	var t struct {
		UnverifiedCertificate string `json:"unverifiedCertificate"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return ""
	}

	return t.UnverifiedCertificate
}
