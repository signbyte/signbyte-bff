package routes

import (
	"crypto/ecdsa"
	"regexp"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/asclient"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signbyte-bff/routes/request"
	"github.com/signbyte/signbyte-bff/routes/response"
	"github.com/signbyte/signbyte-bff/session"
)

// methodNames is acr_values as this service passes it on: one sign-in method's
// name, or a few separated by single spaces.
var methodNames = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}( [A-Za-z][A-Za-z0-9]{0,63}){0,7}$`)

// refreshLeeway refreshes the access token this long before it expires.
const refreshLeeway = 30 * time.Second

// csrfCookieName is the app-readable cookie carrying the anti-forgery token the
// app must echo back in the request header.
const csrfCookieName = "portal_csrf"

// loginStart begins a login: it mints a fresh signing-bound key + proof-key
// verifier + state, parks them server-side under the state bound to this browser
// (the sign-in cookie), and returns the Auth Service authorization URL for the
// browser to follow, asking for a fresh sign-in. Anonymous.
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
	if req.ACRValues != "" && !methodNames.MatchString(req.ACRValues) {
		ctx.Error(pkerrors.NewProblem("err:request:invalid",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("acr_values is not a list of sign-in method names")))

		return
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
	nonce, err := asclient.RandomToken(24)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	binding, err := bindBrowser(ctx, r.Config().FlowTTL)
	if err != nil {
		r.fail(ctx, err)

		return
	}

	flow := &session.Flow{Key: keyEnc, Verifier: verifier, Nonce: nonce, ACRValues: req.ACRValues, Started: time.Now()}
	if err := r.Sessions().PutFlow(ctx, session.FlowKey(state, binding), flow); err != nil {
		r.fail(ctx, err)

		return
	}

	ctx.JSON(&response.LoginStart{
		AuthorizeURL: r.AuthService().AuthorizationURL(asclient.AuthorizationRequest{
			CodeChallenge: challenge,
			State:         state,
			Nonce:         nonce,
			ACRValues:     req.ACRValues,
			Prompt:        "login",
			MaxAge:        freshOnly(),
		}),
		State: state,
	})
}

// freshOnly is the age of authentication a sign-in here accepts: none. A
// signature rests on the sign-in, so the provider's own session must not answer
// it for whoever uses the browser next; the ID token's auth_time proves it.
func freshOnly() *time.Duration {
	age := time.Duration(0)

	return &age
}

// loginCallback lands the browser back from the Auth Service, redeems the code
// for a session-key-bound token, establishes the cookie session, and sends the
// browser on to the app. Anonymous (the state with the browser's sign-in cookie,
// and the proof-key verifier, are the guards). On any failure it redirects back
// with a generic marker.
//
// @operationId PortalLoginCallback
// @title Login callback
// @route /api/portal/v1/login/callback [get].
func (r *router) loginCallback(ctx *azugo.Context) {
	// A return that does not name the Auth Service's issuer is not its answer:
	// neither its error nor its code is used.
	iss := ""
	if v := ctx.Query.StringOptional("iss"); v != nil {
		iss = *v
	}
	if err := r.AuthService().CheckIssuer(iss); err != nil {
		ctx.Log().Warn("login return does not name the auth service's issuer")
		r.redirectWithError(ctx, "login_failed")

		return
	}

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

	// The sign-in belongs to the browser that started it: a return without that
	// browser's value names no flow, and the flow stays parked for its browser.
	binding := browserBinding(ctx)
	if binding == "" {
		ctx.Log().Warn("login return without this browser's sign-in binding")
		r.redirectWithError(ctx, "expired")

		return
	}
	flow, err := r.Sessions().TakeFlow(ctx, session.FlowKey(*state, binding))
	if err != nil {
		r.redirectWithError(ctx, "expired")

		return
	}

	key, err := session.ParseKey(flow.Key)
	if err != nil {
		r.redirectWithError(ctx, "bad_state")

		return
	}

	tokens, err := r.exchangeFlow(ctx, key, *code, flow)
	if err != nil {
		ctx.Log().Warn("token exchange failed")
		r.redirectWithError(ctx, "login_failed")

		return
	}

	// A sign-in mints a new session id + anti-forgery token.
	if err := r.establishSession(ctx, flow.Key, tokens); err != nil {
		r.fail(ctx, err)

		return
	}
	ctx.StatusCode(fasthttp.StatusFound)
	// PostLoginURL is the SPA origin (cross-origin) — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(r.Config().PostLoginURL)
}

// exchangeFlow redeems a parked sign-in's authorization code. The answer must
// carry an ID token proving it (its nonce, a method it named, an authentication no
// earlier than the sign-in began), or no tokens are returned — a sign-in parked
// without a nonce included, which is how an earlier release's elevation of a
// session reads now.
func (r *router) exchangeFlow(ctx *azugo.Context, key *ecdsa.PrivateKey, code string, flow *session.Flow) (*asclient.Tokens, error) {
	tokens, _, err := r.AuthService().ExchangeSignIn(ctx, key, code, flow.Verifier, asclient.IDTokenCheck{
		Nonce:     flow.Nonce,
		ACRValues: flow.ACRValues,
		MaxAge:    freshOnly(),
		Started:   flow.Started,
	})

	return tokens, err
}

// establishSession mints a new cookie session from a freshly issued token set,
// keyed to the per-session signing-bound key, and sets the browser cookies (the
// http-only session id + the readable anti-forgery token), keeping the signing
// capabilities the Auth Service returned with the tokens (a card sign-in's carry
// the card's authentication certificate).
func (r *router) establishSession(ctx *azugo.Context, keyEnc string, tokens *asclient.Tokens) error {
	sid, err := asclient.RandomToken(32)
	if err != nil {
		return err
	}
	csrf, err := asclient.RandomToken(32)
	if err != nil {
		return err
	}

	sess := &session.Session{
		Key:          keyEnc,
		RefreshToken: tokens.RefreshToken,
		CSRF:         csrf,
		Subject:      asclient.SubjectFromToken(tokens.AccessToken),
		Capabilities: capabilitiesFromTokens(tokens),
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
		PermittedFlows: r.offeredOnly(ctx, id.PermittedFlows),
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

	// End the session at the Auth Service first, server to server, with the
	// session's refresh token and key: the browser's address must never carry the
	// token. A refusal or an outage there does not keep the person signed in here;
	// the session there then ends at its own lifetime.
	//
	// Then build the front-channel logout URL: the browser must navigate to the
	// Auth Service so that, for an eParaksts-federated login, it bounces on through
	// the IdP logout and clears its SSO cookie. Without this the IdP keeps its
	// short-lived session and the next login is silently answered from it (the user
	// cannot switch identity/method). The login method decides that bounce.
	logoutURL := ""
	if sess != nil && r.AuthService() != nil {
		if key, err := session.ParseKey(sess.Key); err == nil && sess.RefreshToken != "" {
			if err := r.AuthService().Revoke(ctx, key, sess.RefreshToken); err != nil {
				ctx.Log().Warn("the authentication service did not end the session at sign-out")
			}
		}
		if redirect := r.Config().LogoutRedirectURI(); redirect != "" {
			loginMethod := ""
			if cl, err := asclient.ParseUnverified(sess.AccessToken); err == nil {
				loginMethod = cl.LoginMethod
			}
			logoutURL = r.AuthService().BrowserLogoutURL(redirect, loginMethod)
		}
	}

	if sid != "" {
		_ = r.Sessions().DeleteSession(ctx, sid)
	}
	clearSessionCookies(ctx, r.Config().CookieName)
	ctx.JSON(&response.Logout{OK: true, LogoutURL: logoutURL})
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
// the session type. Called only on the sign-in's code exchange — a
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

// offeredOnly narrows the flows a login permits to the ones the signing service
// runs, in the login's order, so the app offers no method the deployment would
// refuse. Nothing learned from the signing service yet (it has not answered since
// this service started, or no signing service is configured) leaves them as the
// login permits them: the signing service's own refusal stays the floor.
func (r *router) offeredOnly(ctx *azugo.Context, permitted []string) []string {
	o := r.OfferedFlows()
	if o == nil {
		return permitted
	}
	offered, err := o.Get(ctx)
	if err != nil {
		ctx.Log().Warn("signing flows the signing service runs are not current", zap.Error(err))
	}
	if offered == nil {
		return permitted
	}
	runs := make(map[string]bool, len(offered))
	for _, f := range offered {
		runs[f] = true
	}
	out := make([]string, 0, len(permitted))
	for _, f := range permitted {
		if runs[f] {
			out = append(out, f)
		}
	}

	return out
}
