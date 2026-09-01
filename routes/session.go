package routes

import (
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signbyte-bff/asclient"
	"github.com/signbyte/signbyte-bff/routes/request"
	"github.com/signbyte/signbyte-bff/routes/response"
	"github.com/signbyte/signbyte-bff/session"
)

// refreshLeeway refreshes the access token this long before it expires.
const refreshLeeway = 30 * time.Second

// csrfCookieName is the app-readable cookie carrying the anti-forgery token the
// app must echo back in the request header.
const csrfCookieName = "portal_csrf"

// loginStart begins a login: it mints a fresh signing-bound key + proof-key
// verifier + state, parks them server-side under the state, and returns the Auth
// Service authorization URL for the browser to follow. Anonymous.
//
// @operationId PortalLoginStart
// @title Begin login
// @success 200 LoginStart response.LoginStart "Authorization URL + state"
// @route /api/portal/v1/login/start [post].
func (r *router) loginStart(ctx *azugo.Context) {
	var req request.LoginStart
	if len(ctx.Body.Bytes()) > 0 {
		if err := ctx.Body.JSON(&req); err != nil {
			ctx.Error(err)

			return
		}
	}

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
	state, err := asclient.RandomToken(24)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	if err := r.Sessions().PutFlow(ctx, state, &session.Flow{Key: keyEnc, Verifier: verifier}); err != nil {
		r.fail(ctx, err)

		return
	}

	ctx.JSON(&response.LoginStart{
		AuthorizeURL: r.AuthService().AuthorizeURL(challenge, state, req.ACRValues),
		State:        state,
	})
}

// loginCallback lands the browser back from the Auth Service, redeems the code
// for a session-key-bound token, establishes the cookie session, and sends the
// browser on to the app. Anonymous (the state + proof-key verifier are the
// guards). On any failure it redirects back with a generic marker.
//
// @operationId PortalLoginCallback
// @title Login callback
// @route /api/portal/v1/login/callback [get].
func (r *router) loginCallback(ctx *azugo.Context) {
	// The Auth Service propagates an IdP error here instead of a code. Map the
	// known OAuth2 error code to a fixed marker so the SPA can distinguish a
	// genuine user cancel from a provider-side failure; unknown codes default to
	// a provider error, never the reverse, so a mis-guess only ever downgrades a
	// real cancel to "provider had a problem" (still accurate enough). The
	// IdP-supplied error value itself is never reflected in the redirect.
	if idpErr := ctx.Query.StringOptional("error"); idpErr != nil && *idpErr != "" {
		marker := "idp_error"
		if *idpErr == "access_denied" {
			marker = "cancelled"
		}
		r.redirectWithError(ctx, marker)

		return
	}

	code := ctx.Query.StringOptional("code")
	state := ctx.Query.StringOptional("state")
	if code == nil || state == nil || *code == "" || *state == "" {
		r.redirectWithError(ctx, "missing_code")

		return
	}

	flow, err := r.Sessions().TakeFlow(ctx, *state)
	if err != nil {
		r.redirectWithError(ctx, "expired")

		return
	}

	key, err := session.ParseKey(flow.Key)
	if err != nil {
		r.redirectWithError(ctx, "bad_state")

		return
	}

	tokens, err := r.AuthService().ExchangeCode(ctx, key, *code, flow.Verifier)
	if err != nil {
		ctx.Log().Warn("token exchange failed")
		r.redirectWithError(ctx, "login_failed")

		return
	}

	// Elevation of an existing session keeps the same cookie; a fresh login mints a
	// new session id + anti-forgery token.
	if flow.SessionID != "" {
		sess, err := r.Sessions().GetSession(ctx, flow.SessionID)
		if err != nil {
			r.redirectWithError(ctx, "expired")

			return
		}
		applyTokens(sess, tokens)
		// A step-up is a new identification: its capabilities replace (or
		// clear) what the previous login captured — they describe the CURRENT
		// login method.
		sess.Capabilities = capabilitiesFromTokens(tokens)
		if err := r.Sessions().PutSession(ctx, flow.SessionID, sess); err != nil {
			r.fail(ctx, err)

			return
		}
		ctx.StatusCode(fasthttp.StatusFound)
		// PostLoginURL is the SPA origin (cross-origin) — bypass same-origin sanitizing.
		ctx.RedirectUnsafe(r.Config().PostLoginURL)

		return
	}

	// A redirect login (eParaksts Mobile / eID Scan) has no card auth certificate to
	// capture; only the eID-card flow supplies one.
	if err := r.establishSession(ctx, flow.Key, tokens, ""); err != nil {
		r.fail(ctx, err)

		return
	}
	ctx.StatusCode(fasthttp.StatusFound)
	// PostLoginURL is the SPA origin (cross-origin) — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(r.Config().PostLoginURL)
}

// establishSession mints a new cookie session from a freshly issued token set,
// keyed to the per-session signing-bound key, and sets the browser cookies (the
// http-only session id + the readable anti-forgery token). signingAuthCert is the
// card auth certificate captured at eID-card login (empty for redirect logins).
func (r *router) establishSession(ctx *azugo.Context, keyEnc string, tokens *asclient.Tokens, signingAuthCert string) error {
	sid, err := asclient.RandomToken(32)
	if err != nil {
		return err
	}
	csrf, err := asclient.RandomToken(32)
	if err != nil {
		return err
	}

	sess := &session.Session{
		Key:             keyEnc,
		RefreshToken:    tokens.RefreshToken,
		CSRF:            csrf,
		Subject:         asclient.SubjectFromToken(tokens.AccessToken),
		SigningAuthCert: signingAuthCert,
		Capabilities:    capabilitiesFromTokens(tokens),
	}
	applyTokens(sess, tokens)
	if err := r.Sessions().PutSession(ctx, sid, sess); err != nil {
		return err
	}

	setSessionCookies(ctx, r.Config().CookieName, sid, csrf)

	return nil
}

// me returns the logged-in user's identity (composed from the Auth Service),
// refreshing the access token first if it is about to expire.
//
// @operationId PortalMe
// @title Current identity
// @success 200 Me response.Me "Identity + permitted flows"
// @route /api/portal/v1/me [get].
func (r *router) me(ctx *azugo.Context) {
	sid, sess := sessionFromCtx(ctx)

	token, err := r.freshToken(ctx, sid, sess)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:unauthorized",
			pkerrors.WithDetail("session could not be refreshed")))

		return
	}

	key, err := session.ParseKey(sess.Key)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	id, err := r.AuthService().Identity(ctx, key, token)
	if err != nil {
		ctx.Log().Warn("identity lookup failed")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return
	}

	me := response.Me{
		Sub:            id.Subject,
		Name:           id.Name,
		LoA:            id.LoA,
		LoginMethod:    id.LoginMethod,
		PermittedFlows: id.PermittedFlows,
	}

	// Seal availability, when the login captured it: ids and display labels
	// only — the certificates stay server-side. An unread catalog leaves
	// can_eseal null (unknown), which the app treats differently from a
	// verified "no seals".
	if caps := sess.Capabilities; caps != nil && caps.SealsKnown {
		canEseal := len(caps.Seals) > 0
		me.CanEseal = &canEseal
		me.Seals = make([]response.MeSeal, 0, len(caps.Seals))
		for _, s := range caps.Seals {
			me.Seals = append(me.Seals, response.MeSeal{ID: s.ID, Label: s.Label})
		}
	}

	ctx.JSON(&me)
}

// refresh re-issues the access token within the session.
//
// @operationId PortalSessionRefresh
// @title Refresh session
// @success 200 OK response.OK "Refreshed"
// @route /api/portal/v1/session/refresh [post].
func (r *router) refresh(ctx *azugo.Context) {
	sid, sess := sessionFromCtx(ctx)

	key, err := session.ParseKey(sess.Key)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	tokens, err := r.AuthService().Refresh(ctx, key, sess.RefreshToken)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:unauthorized",
			pkerrors.WithDetail("refresh rejected")))

		return
	}

	applyTokens(sess, tokens)
	if err := r.Sessions().PutSession(ctx, sid, sess); err != nil {
		r.fail(ctx, err)

		return
	}

	ctx.JSON(&response.OK{OK: true})
}

// logout invalidates the session and clears the browser cookies.
//
// @operationId PortalLogout
// @title Log out
// @success 200 OK response.OK "Logged out"
// @route /api/portal/v1/logout [post].
func (r *router) logout(ctx *azugo.Context) {
	sid, sess := sessionFromCtx(ctx)

	// Build the front-channel logout URL BEFORE deleting the session: the browser
	// must navigate to the Auth Service so that, for an eParaksts-federated login, it
	// bounces on through the IdP logout and clears its SSO cookie. Without this the
	// IdP keeps its short-lived session and the next login is silently answered from
	// it (the user cannot switch identity/method). The session's refresh token is the
	// upstream handle that lets the Auth Service resolve the method + end its session.
	logoutURL := ""
	if sess != nil && r.AuthService() != nil {
		if redirect := r.Config().LogoutRedirectURI(); redirect != "" {
			logoutURL = r.AuthService().LogoutURL(redirect, sess.RefreshToken)
		}
	}

	if sid != "" {
		_ = r.Sessions().DeleteSession(ctx, sid)
	}
	clearSessionCookies(ctx, r.Config().CookieName)
	ctx.JSON(&response.Logout{OK: true, LogoutURL: logoutURL})
}

// stepUp asks the Auth Service to elevate the session to a stronger login method
// and relays its instruction (a redirect to a stronger login, or a card-signing
// challenge) to the app verbatim. The elevation completes back through the login
// callback, keeping the same session.
//
// @operationId PortalStepUp
// @title Step up
// @route /api/portal/v1/step-up [post].
func (r *router) stepUp(ctx *azugo.Context) {
	sid, sess := sessionFromCtx(ctx)

	var req request.StepUp
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	key, err := session.ParseKey(sess.Key)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	verifier, challenge, err := asclient.PKCE()
	if err != nil {
		r.fail(ctx, err)

		return
	}
	state, err := asclient.RandomToken(24)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	// Park the elevation flow so the callback updates this session in place.
	if err := r.Sessions().PutFlow(ctx, state, &session.Flow{Key: sess.Key, Verifier: verifier, SessionID: sid}); err != nil {
		r.fail(ctx, err)

		return
	}

	token, err := r.freshToken(ctx, sid, sess)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:unauthorized",
			pkerrors.WithDetail("session could not be refreshed")))

		return
	}

	body, status, err := r.AuthService().StepUp(ctx, key, token, asclient.StepUpRequest{
		SessionID:     sess.RefreshToken,
		ClientID:      r.Config().AuthClientID,
		Method:        req.Method,
		CodeChallenge: challenge,
		RedirectURI:   r.Config().AuthRedirectURI,
		State:         state,
	})
	if err != nil {
		ctx.Log().Warn("step-up request failed")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))

		return
	}

	ctx.StatusCode(status)
	ctx.ContentType("application/json")
	ctx.Raw(body)
}

// freshToken returns the session access token, refreshing it (and persisting the
// session) when it is at or near expiry.
func (r *router) freshToken(ctx *azugo.Context, sid string, sess *session.Session) (string, error) {
	if sess.AccessToken != "" && time.Now().Add(refreshLeeway).Unix() < sess.AccessExpiry {
		return sess.AccessToken, nil
	}

	key, err := session.ParseKey(sess.Key)
	if err != nil {
		return "", err
	}
	tokens, err := r.AuthService().Refresh(ctx, key, sess.RefreshToken)
	if err != nil {
		return "", err
	}
	applyTokens(sess, tokens)
	if err := r.Sessions().PutSession(ctx, sid, sess); err != nil {
		return "", err
	}

	return sess.AccessToken, nil
}

// fail logs an internal error (with its cause, off the wire) and returns a generic
// 500 (never an internal body).
func (r *router) fail(ctx *azugo.Context, err error) {
	ctx.Log().Error("signbyte-bff internal error", zap.Error(err))
	ctx.Error(pkerrors.NewProblem("err:portal:internal"))
}

// applyTokens copies a token response onto a session, computing the access-token
// expiry and rotating the refresh token when the Auth Service returns a new one.
func applyTokens(sess *session.Session, tokens *asclient.Tokens) {
	sess.AccessToken = tokens.AccessToken
	sess.AccessExpiry = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).Unix()
	if tokens.RefreshToken != "" {
		sess.RefreshToken = tokens.RefreshToken
	}
}

// capabilitiesFromTokens copies the code-exchange's signing capabilities onto
// the session type. Called only on code-exchange paths (login, step-up) — a
// refresh never carries capabilities, and clearing them there would turn every
// token refresh into a capability loss.
func capabilitiesFromTokens(tokens *asclient.Tokens) *session.Capabilities {
	c := tokens.Capabilities
	if c == nil {
		return nil
	}
	out := &session.Capabilities{
		SignIdentityID:     c.SignIdentityID,
		SigningCertificate: c.SigningCertificate,
		AuthCertificate:    c.AuthCertificate,
		SealsKnown:         c.SealsKnown,
	}
	for _, s := range c.Seals {
		out.Seals = append(out.Seals, session.Seal(s))
	}

	return out
}
