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

// TestWebEIDCompleteUnknownFlow proves the eID-card completion fails closed when
// the flow handle is unknown/expired — it rejects before any upstream call.
func TestWebEIDCompleteUnknownFlow(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"state":"does-not-exist","authToken":{"x":1}}`)
	resp, err := app.TestClient().Post("/api/portal/v1/login/webeid/complete", body)
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
			resp, err := app.TestClient().Get("/api/portal/v1/login/callback?error=" + c.idpErr)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
			loc := string(resp.Header.Peek("Location"))
			fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsTrue(strings.Contains(loc, "error="+c.want)))
		})
	}
}

// TestLoginStart proves the login can be initiated through the BFF without the
// browser ever holding a token: it returns an authorization URL for the upstream
// Auth Service and an opaque state. No upstream call is made yet.
func TestLoginStart(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/api/portal/v1/login/start", []byte("{}"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	var out response.LoginStart
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))
	qt.Assert(t, qt.IsTrue(out.State != ""))
	qt.Assert(t, qt.IsTrue(strings.Contains(out.AuthorizeURL, "/authorize?")))
	qt.Assert(t, qt.IsTrue(strings.Contains(out.AuthorizeURL, "code_challenge=")))
	qt.Assert(t, qt.IsTrue(strings.Contains(out.AuthorizeURL, "client_id=portal-spa")))
	// Forces a fresh authentication so the IdP cannot answer from a lingering SSO
	// session and return a different login method than the one requested.
	qt.Assert(t, qt.IsTrue(strings.Contains(out.AuthorizeURL, "prompt=login")))
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
