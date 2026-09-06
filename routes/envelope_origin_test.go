package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// composedWire is the composed envelope view decoded generically: the assertions in
// this file are about the wire the app receives — which keys are present, which are
// not — so they never read through the typed view.
type composedWire struct {
	Envelope map[string]json.RawMessage   `json:"envelope"`
	Slots    []map[string]json.RawMessage `json:"slots"`
}

func getComposedWire(t *testing.T, app *api.App, sid string) composedWire {
	t.Helper()

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out composedWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)

	return out
}

// TestGetEnvelopeCarriesOriginAndOwnReturnURLForCoSigner proves the composed view
// carries the envelope's origin — the system that prepared it — to a viewer, and the
// viewer's own return address on their own slot; another signer's return address,
// like their identity code, never reaches a viewer who is not the owner.
func TestGetEnvelopeCarriesOriginAndOwnReturnURLForCoSigner(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"svc:acme-dms","status":"sent","version":2,` +
				`"origin":{"name":"Acme DMS","returnUrl":"https://dms.acme.example/return","ref":"contracts/2026-117"}},` +
				`"slots":[` +
				`{"id":"s-1","orderIndex":0,"identityRef":"PNOLV-99999","returnUrl":"https://dms.acme.example/contracts/2026-117"},` +
				`{"id":"s-2","orderIndex":1,"identityRef":"PNOLV-11111","returnUrl":"https://dms.acme.example/thanks"}` +
				`],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "origin-cosigner-sid", "origin-cosigner-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-2", AccessToken: fakeAccessToken("PNOLV-99999"), AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	out := getComposedWire(t, app, sid)

	qt.Assert(t, qt.Equals(string(out.Envelope["origin"]),
		`{"name":"Acme DMS","returnUrl":"https://dms.acme.example/return","ref":"contracts/2026-117"}`))
	qt.Assert(t, qt.Equals(len(out.Slots), 2))
	qt.Check(t, qt.Equals(string(out.Slots[0]["you"]), "true"))
	qt.Check(t, qt.Equals(string(out.Slots[0]["returnUrl"]), `"https://dms.acme.example/contracts/2026-117"`))
	// The other signer's return address is not this viewer's business.
	_, leaked := out.Slots[1]["returnUrl"]
	qt.Check(t, qt.IsFalse(leaked))
}

// TestGetEnvelopeOwnerSeesEveryReturnURL proves the envelope owner — the party that set
// the return addresses — sees each slot's return address in the composed view.
func TestGetEnvelopeOwnerSeesEveryReturnURL(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","version":2,` +
				`"origin":{"name":"Acme DMS"}},` +
				`"slots":[` +
				`{"id":"s-1","orderIndex":0,"identityRef":"PNOLV-99999","returnUrl":"https://dms.acme.example/a"},` +
				`{"id":"s-2","orderIndex":1,"identityRef":"PNOLV-11111","returnUrl":"https://dms.acme.example/b"}` +
				`],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid = "origin-owner-sid"
	putSession(t, app, sid, "origin-owner-csrf")

	out := getComposedWire(t, app, sid)

	qt.Assert(t, qt.Equals(string(out.Envelope["origin"]), `{"name":"Acme DMS"}`))
	qt.Assert(t, qt.Equals(len(out.Slots), 2))
	qt.Check(t, qt.Equals(string(out.Slots[0]["returnUrl"]), `"https://dms.acme.example/a"`))
	qt.Check(t, qt.Equals(string(out.Slots[1]["returnUrl"]), `"https://dms.acme.example/b"`))
}

// TestGetEnvelopeWithoutOriginIsUnchanged proves an envelope started in the portal — no
// origin, no return addresses — composes exactly as before: neither key appears.
func TestGetEnvelopeWithoutOriginIsUnchanged(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","version":2},` +
				`"slots":[{"id":"s-1","orderIndex":0}],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid = "no-origin-sid"
	putSession(t, app, sid, "no-origin-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.IsFalse(strings.Contains(body, `"origin"`)))
	qt.Check(t, qt.IsFalse(strings.Contains(body, `"returnUrl"`)))
}
