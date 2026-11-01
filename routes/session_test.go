package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/routes/response"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestHealthz(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestReadyzMemoryStore(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/readyz")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestMeWithoutSessionUnauthorized(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/api/portal/v1/me")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

func TestRefreshWithoutSessionUnauthorized(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/api/portal/v1/session/refresh", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// testBinding is a well-formed binding value a test browser holds, so a test
// reaches what comes after the binding check.
const testBinding = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// TestWebEIDCompleteUnknownFlow proves the eID-card completion fails closed when
// the flow handle is unknown/expired — it rejects before any upstream call.
func TestWebEIDCompleteUnknownFlow(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"state":"does-not-exist","authToken":{"x":1}}`)
	client := app.TestClient()
	resp, err := client.Post("/api/portal/v1/login/webeid/complete", body, client.WithCookie(signInCookieName, testBinding))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

// TestLoginCallbackIdPErrorMarker proves the callback classifies the IdP's OAuth2
// error code into a fixed marker: a user-denied consent reads as "cancelled",
// everything else (a provider-side failure) reads as "idp_error" — never the
// raw IdP value.
func TestLoginCallbackIdPErrorMarker(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	cases := []struct {
		name   string
		idpErr string
		want   string
	}{
		{"userDenied", "access_denied", "cancelled"},
		{"providerError", "server_error", "idp_error"},
		{"unknownCode", "invalid_scope", "idp_error"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := app.TestClient().Get("/api/portal/v1/login/callback?error=" + c.idpErr + "&iss=" + url.QueryEscape(testIssuer))
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
			loc := string(resp.Header.Peek("Location"))
			fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsTrue(strings.Contains(loc, "error="+c.want)))
		})
	}
}

// testIssuer is the Auth Service's issuer in the test configuration.
const testIssuer = "http://localhost:8080"

// TestLoginStart proves the login can be initiated through the BFF without the
// browser ever holding a token: it returns an authorization URL for the upstream
// Auth Service and an opaque state. No upstream call is made yet. The sign-in
// asks for an ID token with a nonce kept only with its parked flow, and names
// the method asked for in the Auth Service's own names.
func TestLoginStart(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	client := ta.TestClient()
	before := time.Now()
	resp, err := client.Post("/api/portal/v1/login/start", []byte(`{"acr_values":"eidScan"}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var out response.LoginStart
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))
	qt.Assert(t, qt.IsTrue(out.State != ""))
	qt.Assert(t, qt.IsTrue(strings.Contains(out.AuthorizeURL, "/authorize?")))
	u, err := url.Parse(out.AuthorizeURL)
	qt.Assert(t, qt.IsNil(err))
	q := u.Query()
	qt.Check(t, qt.Not(qt.Equals(q.Get("code_challenge"), "")))
	qt.Check(t, qt.Equals(q.Get("client_id"), "portal-spa"))
	qt.Check(t, qt.Equals(q.Get("scope"), "openid"))
	qt.Check(t, qt.Equals(q.Get("acr_values"), "eidScan"))
	// Every sign-in here is a fresh one: a signature rests on it.
	qt.Check(t, qt.Equals(q.Get("prompt"), "login"))
	qt.Check(t, qt.Equals(q.Get("max_age"), "0"))

	flow, err := app.Sessions().TakeFlow(context.Background(), session.FlowKey(out.State, client.Cookies()[signInCookieName]))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(flow.Nonce, "")))
	qt.Check(t, qt.Equals(q.Get("nonce"), flow.Nonce))
	qt.Check(t, qt.Equals(flow.ACRValues, "eidScan"))
	qt.Check(t, qt.IsFalse(flow.Started.Before(before.Truncate(time.Second))))
	qt.Check(t, qt.IsFalse(flow.Started.After(time.Now())))

	for _, bad := range []string{"urn:eparaksts:authentication:flow:mobileid", strings.Repeat("a", 65), "eidScan  webEid"} {
		body, err := json.Marshal(map[string]string{"acr_values": bad})
		qt.Assert(t, qt.IsNil(err))
		resp, err := ta.TestClient().Post("/api/portal/v1/login/start", body)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest), qt.Commentf("%q", bad))
		fasthttp.ReleaseResponse(resp)
	}
}

// tokenCall counts what the Auth Service stand-in received at /token and /revoke.
type tokenCall struct {
	token, revoke int
	revoked       string
}

// callbackApp starts the BFF against an Auth Service that answers /token with
// tokenBody (no ID token unless the body has one) and counts /revoke.
func callbackApp(t *testing.T, tokenBody string) (*api.App, *azugo.TestApp, *tokenCall) {
	t.Helper()

	calls := &tokenCall{}
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			calls.token++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenBody))
		case "/revoke":
			_ = r.ParseForm()
			calls.revoke++
			calls.revoked = r.PostForm.Get("token")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(as.Close)
	t.Setenv("AUTH_INTERNAL_URL", as.URL)

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return app, ta, calls
}

// parkFlow parks a flow under state with a fresh key.
func parkFlow(t *testing.T, app *api.App, state string, flow session.Flow) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	flow.Key, err = session.MarshalKey(key)
	qt.Assert(t, qt.IsNil(err))
	flow.Verifier = "verifier-1"
	qt.Assert(t, qt.IsNil(app.Sessions().PutFlow(context.Background(), state, &flow)))
}

// callback lands a return at the callback and answers where the browser is sent.
func callback(t *testing.T, ta *azugo.TestApp, query string, opts ...azugo.TestClientOption) string {
	t.Helper()

	resp, err := ta.TestClient().Get("/api/portal/v1/login/callback?"+query, opts...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
	loc := string(resp.Header.Peek("Location"))
	fasthttp.ReleaseResponse(resp)

	return loc
}

// A return that does not name the Auth Service's issuer is not its answer: its
// code is never redeemed, its error is not read as the Auth Service's, and the
// flow it names is left as it was [RFC 9207 §2.4].
func TestLoginCallbackRefusesAReturnNotNamingTheIssuer(t *testing.T) {
	app, ta, calls := callbackApp(t, `{}`)
	parkFlow(t, app, "state-1", session.Flow{Nonce: "nonce-1"})

	for _, query := range []string{
		"code=c1&state=state-1",
		"code=c1&state=state-1&iss=" + url.QueryEscape("https://another.example"),
		"error=access_denied&state=state-1&iss=" + url.QueryEscape("https://another.example"),
	} {
		qt.Check(t, qt.IsTrue(strings.Contains(callback(t, ta, query), "error=login_failed")), qt.Commentf("%s", query))
	}
	qt.Check(t, qt.Equals(calls.token, 0))

	_, err := app.Sessions().TakeFlow(context.Background(), "state-1")
	qt.Check(t, qt.IsNil(err))
}

// A sign-in redeemed with no ID token in the answer establishes no session, and
// the session the exchange opened at the Auth Service is ended. An elevation of a
// session answers none, and is redeemed as before.
func TestASignInIsRedeemedOnlyWithItsIDToken(t *testing.T) {
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","login_method":"eparakstsMobile"}`))
	accessToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + claims + ".sig"
	app, ta, calls := callbackApp(t, `{"access_token":"`+accessToken+`","token_type":"DPoP","expires_in":300,"refresh_token":"refresh-1"}`)
	iss := "&iss=" + url.QueryEscape(testIssuer)
	bound := ta.TestClient().WithCookie(signInCookieName, testBinding)

	parkFlow(t, app, session.FlowKey("state-sign-in", testBinding), session.Flow{Nonce: "nonce-1", ACRValues: "eparakstsMobile"})
	resp, err := ta.TestClient().Get("/api/portal/v1/login/callback?code=c1&state=state-sign-in"+iss, bound)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Header.Peek("Location")), "error=login_failed")))
	qt.Check(t, qt.IsFalse(strings.Contains(string(resp.Header.Peek("Set-Cookie")), "portal_session=")))
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(calls.token, 1))
	qt.Check(t, qt.Equals(calls.revoke, 1))
	qt.Check(t, qt.Equals(calls.revoked, "refresh-1"))

	const sid = "sid-elevated"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "old", AccessExpiry: 1 << 62, CSRF: "csrf-1", RefreshToken: "refresh-0",
	})))
	parkFlow(t, app, session.FlowKey("state-step-up", testBinding), session.Flow{SessionID: sid})
	loc := callback(t, ta, "code=c2&state=state-step-up"+iss, bound)
	qt.Check(t, qt.IsFalse(strings.Contains(loc, "error=")))
	sess, err := app.Sessions().GetSession(context.Background(), sid)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.RefreshToken, "refresh-1"))

	// A sign-in parked without a nonce (an earlier release's) is not redeemed
	// at all: no ID token could prove it.
	calls.token = 0
	parkFlow(t, app, session.FlowKey("state-no-nonce", testBinding), session.Flow{})
	qt.Check(t, qt.IsTrue(strings.Contains(callback(t, ta, "code=c3&state=state-no-nonce"+iss, bound), "error=login_failed")))
	qt.Check(t, qt.Equals(calls.token, 0))

	// The card sign-in's completion completes sign-ins only, never an elevation.
	parkFlow(t, app, session.FlowKey("state-card-elevation", testBinding), session.Flow{SessionID: sid})
	resp, err = ta.TestClient().Post("/api/portal/v1/login/webeid/complete", []byte(`{"state":"state-card-elevation","authToken":{"x":1}}`), bound)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

// revokeCall is one sign-out the Auth Service stand-in received.
type revokeCall struct {
	form  url.Values
	proof string
}

// logoutAgainst signs a session out with the Auth Service answering /revoke with
// status, and returns the logout answer, the revocations it received and whether
// the local session is gone.
func logoutAgainst(t *testing.T, status int) (response.Logout, []revokeCall, bool) {
	t.Helper()

	var calls []revokeCall
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revoke" {
			http.NotFound(w, r)

			return
		}
		_ = r.ParseForm()
		calls = append(calls, revokeCall{form: r.PostForm, proof: r.Header.Get("DPoP")})
		w.WriteHeader(status)
	}))
	t.Cleanup(as.Close)
	t.Setenv("AUTH_INTERNAL_URL", as.URL)

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	stored, err := session.MarshalKey(key)
	qt.Assert(t, qt.IsNil(err))
	claims, err := json.Marshal(map[string]any{"sub": "user-1", "login_method": "eparakstsMobile"})
	qt.Assert(t, qt.IsNil(err))
	accessToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + ".sig"

	const sid, csrf = "sid-logout", "csrf-logout"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: accessToken, AccessExpiry: 1 << 62, CSRF: csrf,
		RefreshToken: "refresh-handle-9", Key: stored,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/logout", map[string]any{},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var out response.Logout
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))
	_, e := app.Sessions().GetSession(context.Background(), sid)

	return out, calls, e != nil
}

// Logout ends the session at the Auth Service server to server, then hands the
// browser an address that names no session: only the client, where to land and
// the login method, which decides whether the identity provider's logout is
// visited. The local session is gone afterwards.
func TestLogoutEndsTheAuthoritySessionAndNamesNoSessionToTheBrowser(t *testing.T) {
	out, calls, gone := logoutAgainst(t, http.StatusOK)

	qt.Assert(t, qt.IsTrue(out.OK))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "/logout?")))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "client_id=portal-spa")))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "login_method=eparakstsMobile")))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "%2Fwelcome")))
	qt.Check(t, qt.IsFalse(strings.Contains(out.LogoutURL, "refresh-handle-9")))
	qt.Check(t, qt.IsFalse(strings.Contains(out.LogoutURL, "sid=")))

	qt.Assert(t, qt.HasLen(calls, 1))
	qt.Check(t, qt.Equals(calls[0].form.Get("token"), "refresh-handle-9"))
	qt.Check(t, qt.Equals(calls[0].form.Get("client_id"), "portal-spa"))
	qt.Check(t, qt.Not(qt.Equals(calls[0].proof, "")))

	qt.Check(t, qt.IsTrue(gone))
}

// A step-up names the session to the Auth Service by its refresh token and this
// client: the Auth Service keeps its own session id to itself.
func TestStepUpNamesTheSessionByItsRefreshToken(t *testing.T) {
	sent := make(chan map[string]any, 1)
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/step-up" {
			http.NotFound(w, r)

			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mode":"redirect","authorize_url":"https://idp.example/authorize"}`))
	}))
	t.Cleanup(as.Close)
	t.Setenv("AUTH_INTERNAL_URL", as.URL)

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	stored, err := session.MarshalKey(key)
	qt.Assert(t, qt.IsNil(err))
	const sid, csrf = "sid-step-up", "csrf-step-up"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
		RefreshToken: "refresh-handle-9", Key: stored,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/step-up", map[string]any{"method": "eparakstsMobile"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	body, _ := resp.BodyUncompressed()
	status := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))

	got := <-sent
	qt.Check(t, qt.Equals(got["refresh_token"], any("refresh-handle-9")))
	qt.Check(t, qt.Equals(got["client_id"], any("portal-spa")))
	_, named := got["session_id"]
	qt.Check(t, qt.IsFalse(named))

	// The elevation is parked under this browser's value, as a sign-in is: its
	// return in another browser names nothing.
	state, _ := got["state"].(string)
	_, err = app.Sessions().TakeFlow(context.Background(), state)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	flow, err := app.Sessions().TakeFlow(context.Background(), session.FlowKey(state, tc.Cookies()[signInCookieName]))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(flow.SessionID, sid))
}

// A sign-out the Auth Service refuses or cannot take still signs the person out
// here: the browser leaves and the local session ends.
func TestLogoutStillEndsTheLocalSessionWhenTheAuthorityRefuses(t *testing.T) {
	out, calls, gone := logoutAgainst(t, http.StatusUnauthorized)

	qt.Check(t, qt.IsTrue(out.OK))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "/logout?")))
	qt.Check(t, qt.HasLen(calls, 1))
	qt.Check(t, qt.IsTrue(gone))
}
