package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/routes/response"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// signInMethodsApp runs the service against an Auth Service whose discovery document
// answers with status and body, and counts the reads.
func signInMethodsApp(t *testing.T, status int, body string) (*azugo.TestApp, *atomic.Int32) {
	t.Helper()
	var reads atomic.Int32
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(as.Close)
	t.Setenv("AUTH_INTERNAL_URL", as.URL)

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	return azugo.NewTestApp(app.App), &reads
}

func getSignInMethods(t *testing.T, app *azugo.TestApp) (int, string) {
	t.Helper()
	tc := app.TestClient()
	resp, err := tc.Get("/api/portal/v1/sign-in-methods")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	return resp.StatusCode(), string(resp.Body())
}

// The sign-in page is told the ways to sign in the Auth Service publishes, in its
// order and with no session, names only (anything else in the list is dropped), and the Auth Service is read once per minute, not
// once per page.
func TestSignInMethodsRelayTheAuthServicesList(t *testing.T) {
	app, reads := signInMethodsApp(t, http.StatusOK,
		`{"issuer":"https://auth.example","acr_values_supported":["eparakstsMobile","eidScan","legacyEid","webEid","urn:not:a:method","<b>"]}`)
	app.Start(t)
	t.Cleanup(app.Stop)

	for range 2 {
		status, body := getSignInMethods(t, app)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("%s", body))
		var out response.SignInMethods
		qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(body), &out)))
		qt.Check(t, qt.DeepEquals(out.Methods, []string{"eparakstsMobile", "eidScan", "legacyEid", "webEid"}))
	}
	qt.Check(t, qt.Equals(reads.Load(), int32(1)))
}

// With no answer from the Auth Service ever, the page is told plainly that the
// list cannot be read, never an empty list it would show as "no way to sign in".
func TestSignInMethodsUnavailableWhenNeverRead(t *testing.T) {
	app, _ := signInMethodsApp(t, http.StatusInternalServerError, `{}`)
	app.Start(t)
	t.Cleanup(app.Stop)

	status, body := getSignInMethods(t, app)
	qt.Check(t, qt.Equals(status, fasthttp.StatusServiceUnavailable), qt.Commentf("%s", body))
	qt.Check(t, qt.IsTrue(strings.Contains(body, "err:upstream:unavailable")), qt.Commentf("%s", body))
}
