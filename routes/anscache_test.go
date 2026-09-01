package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// countingDoer answers every on-behalf call with a canned body and counts them.
type countingDoer struct {
	status int
	body   []byte
	calls  int
}

func (d *countingDoer) DoServiceOnBehalf(_ context.Context, _, _, _, _, _, _ string, _ http.Header, _ []byte) (*authclient.BackgroundResponse, error) {
	d.calls++

	return &authclient.BackgroundResponse{StatusCode: d.status, Body: d.body}, nil
}

func (d *countingDoer) DoServiceOnBehalfWithTimeout(ctx context.Context, _ time.Duration, audience, scope, sub, token, method, fullURL string, hdr http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	return d.DoServiceOnBehalf(ctx, audience, scope, sub, token, method, fullURL, hdr, body)
}

// TestValidationAnswerRenderRecentCache proves the render-recent path: a repeat
// fetch of the same signature's validation within the TTL serves the cached
// answer (no second upstream round), and an explicit ?force=1 re-validates.
func TestValidationAnswerRenderRecentCache(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &countingDoer{status: fasthttp.StatusOK,
		body: []byte(`{"signatureId":"sig-1","verdict":"PASSED","pass":true,"validatedAt":"2026-07-20T10:00:00Z"}`)}
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid = "cache-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: "c",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()
	tc := ta.TestClient()

	get := func(path string) map[string]any {
		resp, err := tc.Get(path, tc.WithCookie("portal_session", sid))
		qt.Assert(t, qt.IsNil(err))
		defer fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
		var out map[string]any
		qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))

		return out
	}

	// First fetch runs the upstream round and caches the answer.
	out := get("/api/portal/v1/signatures/sig-1/validation")
	qt.Check(t, qt.Equals(out["verdict"], "PASSED"))
	qt.Assert(t, qt.Equals(doer.calls, 1))

	// The repeat fetch is a cache hit — no second upstream call, and the answer
	// still carries its validatedAt ("as of", never "current").
	out = get("/api/portal/v1/signatures/sig-1/validation")
	qt.Check(t, qt.Equals(out["validatedAt"], "2026-07-20T10:00:00Z"))
	qt.Assert(t, qt.Equals(doer.calls, 1))

	// The explicit re-validate bypasses and refreshes the cache.
	_ = get("/api/portal/v1/signatures/sig-1/validation?force=1")
	qt.Assert(t, qt.Equals(doer.calls, 2))

	// A different user must never see the cached answer: same target, other
	// session → its own upstream round.
	const otherSID = "cache-sid-2"
	err = app.Sessions().PutSession(context.Background(), otherSID, &session.Session{
		Subject: "user-2", AccessToken: "tok2", AccessExpiry: 1 << 62, CSRF: "c2",
	})
	qt.Assert(t, qt.IsNil(err))
	resp, err := tc.Get("/api/portal/v1/signatures/sig-1/validation", tc.WithCookie("portal_session", otherSID))
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(doer.calls, 3))
}
