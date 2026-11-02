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
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The step-up is gone: a signed-in session asking for one is answered 404, and
// nothing reaches the Auth Service.
func TestTheStepUpIsGone(t *testing.T) {
	reached := make(chan string, 1)
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.Path
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
	const sid, csrf = "sid-1", "csrf-1"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
		RefreshToken: "refresh-1", Key: stored,
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
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
	select {
	case path := <-reached:
		t.Errorf("the Auth Service was called at %s", path)
	default:
	}
}

// An elevation parked before the upgrade carries the session it was to raise; read
// back now it is a sign-in with no nonce, which no ID token can prove. Its return
// is refused before the code is redeemed: no new session, and the session it named
// is left as it was.
func TestAnElevationParkedBeforeTheUpgradeRaisesNothing(t *testing.T) {
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","login_method":"eparakstsMobile"}`))
	accessToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + claims + ".sig"
	app, ta, calls := callbackApp(t, `{"access_token":"`+accessToken+`","token_type":"DPoP","expires_in":300,"refresh_token":"refresh-1"}`)
	bound := ta.TestClient().WithCookie(signInCookieName, testBinding)

	const sid = "sid-elevated"
	before := &session.Session{Subject: "user-1", AccessToken: "old", AccessExpiry: 1 << 62, CSRF: "csrf-1", RefreshToken: "refresh-0"}
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, before)))

	// The record as the earlier release stored it.
	var old session.Flow
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(`{"session_id":"`+sid+`"}`), &old)))
	parkFlow(t, app, session.FlowKey("state-old-elevation", testBinding), old)

	resp, err := ta.TestClient().Get("/api/portal/v1/login/callback?code=c1&state=state-old-elevation&iss="+url.QueryEscape(testIssuer), bound)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Header.Peek("Location")), "error=login_failed")), qt.Commentf("%s", resp.Header.Peek("Location")))
	qt.Check(t, qt.IsFalse(strings.Contains(string(resp.Header.Peek("Set-Cookie")), "portal_session=")))
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(calls.token, 0))

	after, err := app.Sessions().GetSession(context.Background(), sid)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(after.AccessToken, "old"))
	qt.Check(t, qt.Equals(after.RefreshToken, "refresh-0"))
}
