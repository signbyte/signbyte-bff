package routes

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestSigningRequiresSession(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/api/portal/v1/signings/job-1/abandon", []byte(`{}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// TestAuthCertFromToken extracts the card auth certificate from a login token, and
// returns "" for a malformed token (signing then falls back to a supplied cert).
func TestAuthCertFromToken(t *testing.T) {
	qt.Check(t, qt.Equals(
		authCertFromToken(json.RawMessage(`{"algorithm":"ES384","unverifiedCertificate":"MIIauth","signature":"s"}`)),
		"MIIauth"))
	qt.Check(t, qt.Equals(authCertFromToken(json.RawMessage(`not json`)), ""))
}

// TestSigningStatusRelaysChainAdvanced proves the BFF relays the orchestrator's
// keep-latest conflict as the structured chain-advanced code (a 409), so the SPA can
// tell the signer another party co-signed and to sign the updated document again —
// rather than flattening it to a generic conflict the UI can't act on. The relay
// preserves the terminal code from the downstream problem+json.
func TestSigningStatusRelaysChainAdvanced(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetSignflow(clients.NewSignflow(
		&stubDoer{status: fasthttp.StatusConflict, body: []byte(`{"code":"err:document:chainAdvanced","title":"Document changed since signing began","status":409,"source":"Signing Orchestrator (signflow)"}`)},
		"http://signflow:8080", "svc:signflow",
	))

	const sid, csrf = "test-sid-ca", "test-csrf-ca"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/signings/job-1/status", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))

	var body struct {
		Code string `json:"code"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &body)))
	qt.Check(t, qt.Equals(body.Code, "err:document:chainAdvanced"))
	fasthttp.ReleaseResponse(resp)
}

// The status relay carries the device-push confirmation context (eID Scan): the
// verification code the user matches on their phone + the confirm-by deadline,
// published by the orchestrator while the signature awaits in-app confirmation.
func TestSigningStatusRelaysVerificationCode(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetSignflow(clients.NewSignflow(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(`{"jobId":"job-1","state":"SIGNING","verificationCode":"4821","verificationMessage":"Confirm signing in eParaksts","signingDeadline":1737467942694}`)},
		"http://signflow:8080", "svc:signflow",
	))

	const sid, csrf = "test-sid-vc", "test-csrf-vc"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/signings/job-1/status", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var body struct {
		State               string `json:"state"`
		VerificationCode    string `json:"verificationCode"`
		VerificationMessage string `json:"verificationMessage"`
		SigningDeadline     int64  `json:"signingDeadline"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &body)))
	qt.Check(t, qt.Equals(body.State, "SIGNING"))
	qt.Check(t, qt.Equals(body.VerificationCode, "4821"))
	qt.Check(t, qt.Equals(body.VerificationMessage, "Confirm signing in eParaksts"))
	qt.Check(t, qt.Equals(body.SigningDeadline, int64(1737467942694)))
	fasthttp.ReleaseResponse(resp)
}

// TestSigningCSRFRequired proves a state-changing signing call without the
// anti-forgery token is refused even with a valid session.
func TestSigningCSRFRequired(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	const sid, csrf = "test-sid-2", "test-csrf-2"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/signings/job-1/abandon",
		map[string]any{},
		tc.WithCookie("portal_session", sid), // no X-CSRF-Token header
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)
}
