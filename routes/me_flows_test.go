package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// flowSource is the signing service's answer to which flows it runs.
type flowSource struct {
	flows []string
	err   error
}

func (s flowSource) Flows(context.Context) ([]string, error) { return s.flows, s.err }

// meWithFlows logs a session in, has the authentication service answer that its
// login permits permitted, and returns what /me says the session may sign with.
// offered nil leaves the signing service unconfigured.
func meWithFlows(t *testing.T, permitted []string, offered *clients.OfferedFlows) []string {
	t.Helper()
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "user-1", "login_method": "webEid", "loa": "high", "permitted_flows": permitted,
		})
	}))
	t.Cleanup(as.Close)
	t.Setenv("AUTH_INTERNAL_URL", as.URL)

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	if offered != nil {
		app.SetOfferedFlows(offered)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	stored, err := session.MarshalKey(key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), "test-sid", &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: time.Now().Add(time.Hour).Unix(), CSRF: "test-csrf", Key: stored,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)
	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/me", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	body, _ := resp.BodyUncompressed()
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK), qt.Commentf("%s", body))
	var me struct {
		PermittedFlows []string `json:"permitted_flows"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &me)), qt.Commentf("%s", body))

	return me.PermittedFlows
}

// The app is offered only the flows the login permits AND the signing service
// runs, in the login's order: a deployment without CSC offers a Web eID login its
// card flow alone.
func TestMeOffersOnlyFlowsTheSigningServiceRuns(t *testing.T) {
	permitted := []string{"webEid", "cscEidPlugin"}

	withoutCSC := clients.NewOfferedFlows(flowSource{flows: []string{"webEid", "eparakstsMobile", "eidScan", "eparakstsMobileEseal"}}, time.Minute)
	qt.Check(t, qt.DeepEquals(meWithFlows(t, permitted, withoutCSC), []string{"webEid"}))

	withCSC := clients.NewOfferedFlows(flowSource{flows: []string{"webEid", "eparakstsMobile", "eidScan", "eparakstsMobileEseal", "cscEidScan", "cscEidPlugin"}}, time.Minute)
	qt.Check(t, qt.DeepEquals(meWithFlows(t, permitted, withCSC), []string{"webEid", "cscEidPlugin"}))
}

// The signing service's answer never adds a flow the login does not permit.
func TestMeNeverOffersAFlowTheLoginDoesNotPermit(t *testing.T) {
	everything := clients.NewOfferedFlows(flowSource{flows: []string{"webEid", "eidScan", "cscEidScan", "cscEidPlugin"}}, time.Minute)
	qt.Check(t, qt.DeepEquals(meWithFlows(t, []string{"eidScan", "cscEidScan"}, everything), []string{"eidScan", "cscEidScan"}))
}

// Nothing learned from the signing service — none configured, or it has not
// answered yet — leaves the flows as the login permits them; the signing
// service's own refusal stays the floor, and /me still answers.
func TestMeKeepsTheLoginsFlowsWhenTheOfferIsUnknown(t *testing.T) {
	permitted := []string{"webEid", "cscEidPlugin"}
	qt.Check(t, qt.DeepEquals(meWithFlows(t, permitted, nil), permitted))

	down := clients.NewOfferedFlows(flowSource{err: errors.New("connection refused")}, time.Minute)
	qt.Check(t, qt.DeepEquals(meWithFlows(t, permitted, down), permitted))
}
