package routes

import (
	"context"
	"encoding/json"
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

// TestLogoutReturnsFederatedLogoutURL proves logout clears the local session and
// returns a front-channel logout URL carrying the session handle, so the browser
// can be sent on to the Auth Service to clear the federated IdP SSO cookie.
func TestLogoutReturnsFederatedLogoutURL(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	const sid, csrf = "sid-logout", "csrf-logout"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
		RefreshToken: "refresh-handle-9",
	})
	qt.Assert(t, qt.IsNil(err))

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
	qt.Assert(t, qt.IsTrue(out.OK))
	// The front-channel logout URL targets the Auth Service, scopes the public
	// client, carries the session handle to terminate, and lands on the app's
	// public landing screen.
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "/logout?")))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "client_id=portal-spa")))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "sid=refresh-handle-9")))
	qt.Check(t, qt.IsTrue(strings.Contains(out.LogoutURL, "%2Fwelcome")))

	// The session handle is dead afterwards.
	_, e := app.Sessions().GetSession(context.Background(), sid)
	qt.Check(t, qt.IsNotNil(e))
}
