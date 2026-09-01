package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/asclient"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// signApp wires a test app whose envelope + signflow clients answer a per-slot
// sign call, and returns the doer to inspect what the signing call carried.
func signApp(t *testing.T) (*api.App, *routingDoer) {
	t.Helper()
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-1/eligible", status: 200, body: []byte(`{"eligible":true}`)},
		{method: http.MethodPost, contains: "/api/v1/signings", status: 201, body: []byte(
			`{"jobId":"job-1","state":"awaiting_redirect","authorizeUrl":"https://idp/x"}`)},
		{method: http.MethodPost, contains: "/slots/s-1/job", status: 200, body: []byte(`{"id":"s-1","jobId":"job-1"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	return app, doer
}

func putCapabilitySession(t *testing.T, app *api.App, sid, csrf string, caps *session.Capabilities) {
	t.Helper()
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject:      "user-1",
		AccessToken:  "tok",
		AccessExpiry: 1 << 62,
		CSRF:         csrf,
		Capabilities: caps,
	})
	qt.Assert(t, qt.IsNil(err))
}

func postSign(t *testing.T, app *api.App, sid, csrf string, body map[string]any) {
	t.Helper()
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign", body,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)
}

// TestSignSlotRedirectThreadsCapabilities proves a redirect-flow signing carries
// the login-captured identity + certificates, so the signing provider can skip
// its own identity-resolution leg.
func TestSignSlotRedirectThreadsCapabilities(t *testing.T) {
	app, doer := signApp(t)
	const sid, csrf = "caps-sid", "caps-csrf"
	putCapabilitySession(t, app, sid, csrf, &session.Capabilities{
		SignIdentityID:     "id-serverid-sign",
		SigningCertificate: "MIIsignCaptured",
		AuthCertificate:    "MIIauthCaptured",
		SealsKnown:         true,
	})

	postSign(t, app, sid, csrf, map[string]any{
		"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"})

	var sent clients.BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.signBody, &sent)))
	qt.Check(t, qt.Equals(sent.SignIdentityID, "id-serverid-sign"))
	qt.Check(t, qt.Equals(sent.SigningCertificate, "MIIsignCaptured"))
	qt.Check(t, qt.Equals(sent.AuthCertificate, "MIIauthCaptured"))
}

// TestSignSlotRedirectWithoutCapabilitiesUnchanged proves the fallback stays the
// fallback: no capabilities on the session, no identity fields on the wire.
func TestSignSlotRedirectWithoutCapabilitiesUnchanged(t *testing.T) {
	app, doer := signApp(t)
	const sid, csrf = "nocaps-sid", "nocaps-csrf"
	putCapabilitySession(t, app, sid, csrf, nil)

	postSign(t, app, sid, csrf, map[string]any{
		"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"})

	var sent clients.BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.signBody, &sent)))
	qt.Check(t, qt.Equals(sent.SignIdentityID, ""))
	qt.Check(t, qt.Equals(sent.SigningCertificate, ""))
	qt.Check(t, qt.Equals(sent.AuthCertificate, ""))
}

// TestSignSlotEsealThreadsPickedSeal proves the e-seal flow signs with the seal
// the request picked — the seal IS the signing identity — and still relays the
// pick for the provider's own disambiguation.
func TestSignSlotEsealThreadsPickedSeal(t *testing.T) {
	app, doer := signApp(t)
	const sid, csrf = "seal-sid", "seal-csrf"
	putCapabilitySession(t, app, sid, csrf, &session.Capabilities{
		SignIdentityID:     "id-serverid-sign",
		SigningCertificate: "MIIsignPersonal",
		AuthCertificate:    "MIIauthCaptured",
		SealsKnown:         true,
		Seals: []session.Seal{
			{ID: "id-seal-1", Label: "ORG ONE SIA : eZimogs", Certificate: "MIIsealOne"},
			{ID: "id-seal-2", Label: "ORG TWO SIA : eZimogs", Certificate: "MIIsealTwo"},
		},
	})

	postSign(t, app, sid, csrf, map[string]any{
		"documentId": "doc-1", "flow": "eparakstsMobileEseal", "sigFormat": "XAdES", "sealId": "id-seal-2"})

	var sent clients.BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.signBody, &sent)))
	qt.Check(t, qt.Equals(sent.SignIdentityID, "id-seal-2"))
	qt.Check(t, qt.Equals(sent.SigningCertificate, "MIIsealTwo"))
	qt.Check(t, qt.Equals(sent.AuthCertificate, "MIIauthCaptured"))
	qt.Check(t, qt.Equals(sent.SealID, "id-seal-2"))
}

// TestSignSlotEsealSingleSealAutoPicks proves one seal needs no pick.
func TestSignSlotEsealSingleSealAutoPicks(t *testing.T) {
	app, doer := signApp(t)
	const sid, csrf = "seal1-sid", "seal1-csrf"
	putCapabilitySession(t, app, sid, csrf, &session.Capabilities{
		AuthCertificate: "MIIauthCaptured",
		SealsKnown:      true,
		Seals: []session.Seal{
			{ID: "id-seal-1", Label: "ORG ONE SIA : eZimogs", Certificate: "MIIsealOne"},
		},
	})

	postSign(t, app, sid, csrf, map[string]any{
		"documentId": "doc-1", "flow": "eparakstsMobileEseal", "sigFormat": "XAdES"})

	var sent clients.BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.signBody, &sent)))
	qt.Check(t, qt.Equals(sent.SignIdentityID, "id-seal-1"))
	qt.Check(t, qt.Equals(sent.SigningCertificate, "MIIsealOne"))
	qt.Check(t, qt.Equals(sent.SealID, ""))
}

// TestCapabilitiesFromTokens proves the code-exchange copy keeps every field
// and that a capability-less exchange stores nothing.
func TestCapabilitiesFromTokens(t *testing.T) {
	qt.Check(t, qt.IsNil(capabilitiesFromTokens(&asclient.Tokens{})))

	got := capabilitiesFromTokens(&asclient.Tokens{Capabilities: &asclient.Capabilities{
		SignIdentityID:     "id-serverid-sign",
		SigningCertificate: "MIIsign",
		AuthCertificate:    "MIIauth",
		SealsKnown:         true,
		Seals:              []asclient.Seal{{ID: "id-seal-1", Label: "ORG ONE SIA : eZimogs", Certificate: "MIIseal"}},
	}})
	qt.Assert(t, qt.IsNotNil(got))
	qt.Check(t, qt.Equals(got.SignIdentityID, "id-serverid-sign"))
	qt.Check(t, qt.IsTrue(got.SealsKnown))
	qt.Assert(t, qt.HasLen(got.Seals, 1))
	qt.Check(t, qt.Equals(got.Seals[0].Certificate, "MIIseal"))
}

// TestArchiveTimestampThreadsSessionAuthCert proves the archive request carries
// the session's captured auth certificate — the timestamp is requested in the
// acting user's name.
func TestArchiveTimestampThreadsSessionAuthCert(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodPost, contains: "/api/v1/archive-timestamps", status: 200, body: []byte(
			`{"documentId":"doc-1","contentHash":"h2","mime":"application/vnd.etsi.asic-e+zip","size":10}`)},
	}}
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "arch-sid", "arch-csrf"
	putCapabilitySession(t, app, sid, csrf, &session.Capabilities{
		AuthCertificate: "MIIauthCaptured", SealsKnown: true,
	})

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/documents/doc-1/archive-timestamp", map[string]any{},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)

	var sent struct {
		DocumentID      string `json:"documentId"`
		AuthCertificate string `json:"authCertificate"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.lastBody, &sent)))
	qt.Check(t, qt.Equals(sent.DocumentID, "doc-1"))
	qt.Check(t, qt.Equals(sent.AuthCertificate, "MIIauthCaptured"))
}

// TestArchiveTimestampWithoutCertRefusesBeforeUpstream proves the capture
// fallback signal: a session holding no certificate gets a precise conflict —
// re-authenticate (which re-captures capabilities) and retry — with zero
// upstream traffic, never a silently mis-attributed timestamp.
func TestArchiveTimestampWithoutCertRefusesBeforeUpstream(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{}
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "arch-nocert-sid", "arch-nocert-csrf"
	putCapabilitySession(t, app, sid, csrf, nil)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/documents/doc-1/archive-timestamp", map[string]any{},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Body()), "err:signing:authCertificateRequired")))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(doer.calls), 0))
}
