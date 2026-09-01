package routes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
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

// routingDoer answers an on-behalf call by matching the request method + a URL
// substring, and records the order calls arrived in. It lets one doer back both
// the envelope client and the signing client in a composed test.
type routingDoer struct {
	routes []routedResponse
	calls  []string
	// signBody captures the body of the begin-signing call so a test can assert the
	// certificates / return URLs the BFF threaded into it.
	signBody []byte
	// lastBody captures the most recent call body, whichever endpoint it hit.
	lastBody []byte
}

type routedResponse struct {
	method   string
	contains string
	status   int
	body     []byte
}

func (d *routingDoer) DoServiceOnBehalfWithTimeout(ctx context.Context, _ time.Duration, audience, scope, sub, token, method, fullURL string, hdr http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	return d.DoServiceOnBehalf(ctx, audience, scope, sub, token, method, fullURL, hdr, body)
}

func (d *routingDoer) DoServiceOnBehalf(_ context.Context, _, _, _, _, method, fullURL string, _ http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	d.calls = append(d.calls, method+" "+fullURL)
	d.lastBody = append([]byte(nil), body...)
	if method == http.MethodPost && strings.Contains(fullURL, "/api/v1/signings") {
		d.signBody = append([]byte(nil), body...)
	}
	for _, r := range d.routes {
		if r.method == method && strings.Contains(fullURL, r.contains) {
			return &authclient.BackgroundResponse{StatusCode: r.status, Body: r.body}, nil
		}
	}

	return &authclient.BackgroundResponse{StatusCode: fasthttp.StatusNotFound, Body: []byte(`{}`)}, nil
}

// fakeAccessToken builds an unsigned JWT-shaped token carrying only the
// serial_number claim asclient.SerialFromToken reads — enough to drive the
// "which slot is yours" matching without a real Auth Service.
func fakeAccessToken(serial string) string {
	payload, _ := json.Marshal(map[string]string{"serial_number": serial})

	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
}

// putSession seeds a logged-in session with a far-future token (no refresh) and a
// matching anti-forgery token.
func putSession(t *testing.T, app *api.App, sid, csrf string) {
	t.Helper()
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject:      "user-1",
		AccessToken:  "tok",
		AccessExpiry: 1 << 62,
		CSRF:         csrf,
	})
	qt.Assert(t, qt.IsNil(err))
}

func TestEnvelopeRequiresSession(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/api/portal/v1/envelopes/env-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// TestCreateEnvelopeCSRFRequired proves a state-changing call without the
// anti-forgery token is refused even with a valid session.
func TestCreateEnvelopeCSRFRequired(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusCreated, body: []byte(`{"id":"env-1","status":"draft","version":1}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "env-sid-csrf", "env-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes",
		map[string]any{"title": "x"},
		tc.WithCookie("portal_session", sid), // no X-CSRF-Token header
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)
}

// TestCreateEnvelopeThroughBFF drives a logged-in session through the BFF to the
// (stubbed) envelope service, proving the route → on-behalf create path including
// the session + anti-forgery guard.
func TestCreateEnvelopeThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusCreated, body: []byte(`{"id":"env-1","status":"draft","version":1,"slotIds":["s-1"]}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "env-sid", "env-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes",
		map[string]any{"title": "Q3 contract", "orderPolicy": "sequential"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)
}

// TestSigningTasksThroughBFF proves the signer-inbox endpoint passes the user's awaiting
// envelopes through from the envelope service (a co-signer's view, keyed on their identity).
func TestSigningTasksThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(
			`{"tasks":[{"envelope":{"id":"env-9","title":"NDA","status":"sent","orderPolicy":"parallel","version":2},` +
				`"slotId":"s-2","orderIndex":2,"slotStatus":"sent","yourTurn":true}]}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "tasks-sid", "tasks-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/signing-tasks", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out clients.SigningTasksResult
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(out.Tasks), 1))
	qt.Assert(t, qt.Equals(out.Tasks[0].Envelope.ID, "env-9"))
	qt.Assert(t, qt.Equals(out.Tasks[0].SlotID, "s-2"))
	qt.Assert(t, qt.IsTrue(out.Tasks[0].YourTurn))
}

// TestSignSlotOrchestratesEligibleBeginSetJob proves the per-slot signing trigger
// checks eligibility, begins signing with the real envelope + slot ids, then
// records the job on the slot — in that order.
func TestSignSlotOrchestratesEligibleBeginSetJob(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-1/eligible", status: 200, body: []byte(`{"eligible":true}`)},
		{method: http.MethodPost, contains: "/api/v1/signings", status: 201, body: []byte(`{"jobId":"job-1","state":"awaiting_redirect","authorizeUrl":"https://idp/x"}`)},
		{method: http.MethodPost, contains: "/slots/s-1/job", status: 200, body: []byte(`{"id":"s-1","jobId":"job-1"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "sign-sid", "sign-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)

	// The three upstream calls arrived in order: eligibility, begin signing, set job.
	qt.Assert(t, qt.Equals(len(doer.calls), 3))
	qt.Assert(t, qt.IsTrue(strings.Contains(doer.calls[0], "/slots/s-1/eligible")))
	qt.Assert(t, qt.IsTrue(strings.Contains(doer.calls[1], "/api/v1/signings")))
	qt.Assert(t, qt.IsTrue(strings.Contains(doer.calls[2], "/slots/s-1/job")))
}

// TestSignSlotNotEligible proves a slot that is not yet eligible is refused with a
// conflict, and signing is never begun.
func TestSignSlotNotEligible(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-2/eligible", status: 200, body: []byte(`{"eligible":false}`)},
		{method: http.MethodPost, contains: "/api/v1/signings", status: 201, body: []byte(`{"jobId":"job-x"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "noteligible-sid", "noteligible-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-2/sign",
		map[string]any{"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)

	// Only the eligibility check ran; signing was never begun.
	qt.Assert(t, qt.Equals(len(doer.calls), 1))
	qt.Assert(t, qt.IsTrue(strings.Contains(doer.calls[0], "/slots/s-2/eligible")))
}

// TestSignSlotWebEidThreadsCerts proves a per-slot in-browser (webEid) signing
// threads the app's signing certificate and the auth certificate captured at card
// login down to the orchestrator (Layer 1/2), so envelope slots can be signed
// with the card.
func TestSignSlotWebEidThreadsCerts(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-1/eligible", status: 200, body: []byte(`{"eligible":true}`)},
		{method: http.MethodPost, contains: "/api/v1/signings", status: 201, body: []byte(
			`{"jobId":"job-1","state":"AWAITING_CLIENT_SIGNATURE","documents":[{"documentId":"doc-1","digest":"ZGln"}]}`)},
		{method: http.MethodPost, contains: "/slots/s-1/job", status: 200, body: []byte(`{"id":"s-1","jobId":"job-1"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "slot-webeid-sid", "slot-webeid-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
		SigningAuthCert: "MIIauthFromLogin",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{"documentId": "doc-1", "flow": "webEid", "sigFormat": "XAdES", "signingCertificate": "MIIsign"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)

	// The signing call carried the app's signing cert and the login auth cert; no
	// redirect return URLs (the in-browser flow never leaves the page).
	var sent clients.BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.signBody, &sent)))
	qt.Check(t, qt.Equals(sent.SigningCertificate, "MIIsign"))
	qt.Check(t, qt.Equals(sent.AuthCertificate, "MIIauthFromLogin"))
	qt.Check(t, qt.Equals(sent.PostAuthRedirect, ""))
}

// TestSignSlotWebEidRequiresCerts proves a per-slot in-browser signing that omits
// the signing certificate is refused with 400 before any upstream call.
func TestSignSlotWebEidRequiresCerts(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-1/eligible", status: 200, body: []byte(`{"eligible":true}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "slot-nocert-sid", "slot-nocert-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{"documentId": "doc-1", "flow": "webEid", "sigFormat": "XAdES"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)

	// The cert check fails closed before the eligibility round-trip — no upstream call.
	qt.Assert(t, qt.Equals(len(doer.calls), 0))
}

// TestSignSlotRedirectThreadsReturnURLs proves a per-slot redirect flow threads the
// BFF-synthesized return URLs pointing back at the slot's signing screen, so the
// browser returns and resumes polling after the provider authorizes.
func TestSignSlotRedirectThreadsReturnURLs(t *testing.T) {
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

	const sid, csrf = "slot-redir-sid", "slot-redir-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)

	var sent clients.BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(doer.signBody, &sent)))
	qt.Check(t, qt.IsTrue(strings.Contains(sent.PostAuthRedirect, "/envelopes/env-1/slots/s-1/sign?job={jobId}")))
	qt.Check(t, qt.IsTrue(strings.HasSuffix(sent.AuthErrorRedirect, "&error=1")))
}

// TestGetEnvelopeMergesSigningState proves the composed detail view enriches a
// slot that has a backing job with that job's live signing state.
func TestGetEnvelopeMergesSigningState(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","status":"sent","version":2},` +
				`"slots":[{"id":"s-1","orderIndex":0,"jobId":"job-1"}],` +
				`"documents":[{"documentId":"doc-1","contentHash":"abc"}]}`)},
		{method: http.MethodGet, contains: "/api/v1/signings/job-1/status", status: 200, body: []byte(
			`{"jobId":"job-1","state":"COMPLETED","signatureId":"sig-1","containerId":"c-1"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid = "getenv-sid"
	putSession(t, app, sid, "getenv-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)

	// The envelope view fetched the envelope and then the slot's live signing state.
	qt.Assert(t, qt.Equals(len(doer.calls), 2))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"state":"COMPLETED"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"signatureId":"sig-1"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"containerId":"c-1"`)))
}

// TestGetEnvelopeContainerFromDurableRef proves the download affordance survives the
// live signing job going away: a settled slot with no backing job still carries a
// containerId, seeded from the persisted signed_doc_ref — so a completed envelope's
// signed document stays downloadable from the tracking page after the session ends.
func TestGetEnvelopeContainerFromDurableRef(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","status":"completed","version":3},` +
				`"slots":[{"id":"s-1","orderIndex":0,"status":"signed","signedDocRef":"cont-9"}],` +
				`"documents":[{"documentId":"doc-1","contentHash":"abc"}]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	// No signflow set and the slot has no jobId → no live state to query; the durable ref
	// must still surface as the container to download.

	const sid = "getenv-dur-sid"
	putSession(t, app, sid, "getenv-dur-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"containerId":"cont-9"`)))
}

// TestGetEnvelopeResolvesFilenames proves the composed detail view resolves each
// document's filename from the document service and passes the envelope's created time
// through, and is fail-soft: a document whose metadata lookup misses is still returned
// (without a filename, so the app falls back to the id).
func TestGetEnvelopeResolvesFilenames(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","status":"sent","version":2,"createdAt":"2026-07-01T10:00:00Z"},` +
				`"slots":[],` +
				`"documents":[{"documentId":"doc-1","contentHash":"abc"},{"documentId":"doc-2","contentHash":"def"}]}`)},
		{method: http.MethodGet, contains: "/api/v1/documents/doc-1", status: 200, body: []byte(
			`{"id":"doc-1","filename":"Q3-contract.asice"}`)},
		// doc-2 has no metadata route → the doer's default 404 → its filename stays empty.
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "getenv-fn-sid"
	putSession(t, app, sid, "getenv-fn-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)

	// doc-1's filename resolved; doc-2's lookup missed but it is still present; the
	// envelope's created time passed through to the header.
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"filename":"Q3-contract.asice"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"documentId":"doc-2"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"createdAt":"2026-07-01T10:00:00Z"`)))
}

// TestGetEnvelopeNotConfigured proves envelope routes fail closed with a 503 (not
// a panic or a 404) when the envelope service was never wired — distinct from the
// 401 an unauthenticated caller gets, since envelopeReady is checked first.
func TestGetEnvelopeNotConfigured(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	// No SetEnvelope call: r.Envelope() stays nil.

	const sid = "notconf-sid"
	putSession(t, app, sid, "notconf-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
	fasthttp.ReleaseResponse(resp)
}

// TestListEnvelopesThroughBFF proves the listing endpoint passes the user's
// envelopes through from the envelope service.
func TestListEnvelopesThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(
			`{"envelopes":[{"id":"env-1","title":"NDA","status":"draft","version":1,"slotCount":1,"signedCount":0}],"nextCursor":"c-2"}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid = "list-sid"
	putSession(t, app, sid, "list-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes?limit=10&cursor=c-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out clients.ListResult
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(out.Envelopes), 1))
	qt.Assert(t, qt.Equals(out.Envelopes[0].ID, "env-1"))
	qt.Assert(t, qt.Equals(out.NextCursor, "c-2"))
}

// TestListEnvelopesDocumentFilterThroughBFF proves ?documentId= becomes the
// targeted covering-envelope lookup against the envelope service (the document
// hub's "which envelope carries this document?" resolution).
func TestListEnvelopesDocumentFilterThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "documentId=doc-9", status: 200, body: []byte(
			`{"envelopes":[{"id":"env-9","status":"completed","version":3,"slotCount":1,"signedCount":1}]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid = "list-doc-sid"
	putSession(t, app, sid, "list-doc-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes?documentId=doc-9", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out clients.ListResult
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(out.Envelopes), 1))
	qt.Assert(t, qt.Equals(out.Envelopes[0].ID, "env-9"))
	// The outbound call is the filter form, not the paged listing.
	qt.Assert(t, qt.Equals(len(doer.calls), 1))
	qt.Assert(t, qt.IsTrue(strings.Contains(doer.calls[0], "/api/v1/envelopes?documentId=doc-9")))
}

// TestAttachEnvelopeDocumentThroughBFF proves attaching a document to an envelope
// round-trips through the BFF to the envelope service.
func TestAttachEnvelopeDocumentThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusCreated, body: []byte(`{"envelopeId":"env-1","documentId":"doc-1","contentHash":"abc"}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "attach-sid", "attach-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/documents",
		map[string]any{"documentId": "doc-1"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"documentId":"doc-1"`)))
}

// TestAddEnvelopeSlotThroughBFF proves adding a signer slot round-trips through the
// BFF and returns the new slot's id.
func TestAddEnvelopeSlotThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusCreated, body: []byte(`{"id":"s-2"}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "addslot-sid", "addslot-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots",
		map[string]any{"orderIndex": 1, "role": "signer"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"id":"s-2"`)))
}

// TestSendEnvelopeThroughBFF proves the send transition round-trips through the BFF.
func TestSendEnvelopeThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(`{"id":"env-1","status":"sent","version":2}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "send-sid", "send-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/send", nil,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"status":"sent"`)))
}

// TestSendEnvelopeConflictRelayed proves a lifecycle conflict from the envelope
// service (e.g. an already-sent envelope) is relayed unchanged, not flattened to a
// generic error.
func TestSendEnvelopeConflictRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusConflict, body: []byte(
			`{"code":"err:envelope:alreadySent","title":"Envelope already sent","status":409,"source":"Envelope Service"}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "sendconflict-sid", "sendconflict-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/send", nil,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)
}

// TestCancelEnvelopeUpstreamServerErrorBecomesGateway proves an upstream 5xx is
// never passed through as-is: it becomes a 502 gateway error so the caller never
// mistakes the envelope service's own fault for one of its own.
func TestCancelEnvelopeUpstreamServerErrorBecomesGateway(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusInternalServerError, body: []byte(`{"code":"err:envelope:internal","status":500}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "cancel500-sid", "cancel500-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/cancel", nil,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	fasthttp.ReleaseResponse(resp)
}

// TestDeclineEnvelopeSlotThroughBFF proves declining a slot round-trips through the
// BFF to the envelope service.
func TestDeclineEnvelopeSlotThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(`{"id":"env-1","status":"sent","version":3}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "decline-sid", "decline-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/decline", nil,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// TestGetEnvelopeYouFlagAndIdentityMaskingForCoSigner proves the composed view marks
// an invited co-signer's own slot as "you" by matching their eIDAS code against the
// slot's identityRef, and — since the viewer is not the envelope owner — never
// leaks another party's identityRef to them.
func TestGetEnvelopeYouFlagAndIdentityMaskingForCoSigner(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","version":2},` +
				`"slots":[` +
				`{"id":"s-1","orderIndex":0,"identityRef":"PNOLV-99999"},` +
				`{"id":"s-2","orderIndex":1,"identityRef":"PNOLV-11111"}` +
				`],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "cosigner-sid", "cosigner-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-2", AccessToken: fakeAccessToken("PNOLV-99999"), AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out composedDetail
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(out.Slots), 2))
	qt.Check(t, qt.IsTrue(out.Slots[0].You))
	qt.Check(t, qt.IsFalse(out.Slots[1].You))
	// Neither slot's identityRef reaches a non-owner viewer, including their own.
	qt.Check(t, qt.Equals(out.Slots[0].IdentityRef, ""))
	qt.Check(t, qt.Equals(out.Slots[1].IdentityRef, ""))
}

// TestGetEnvelopeOwnerSeesIdentityRefs proves the envelope owner — who entered the
// invited signers' eIDAS codes — still sees them in the composed view, unlike a
// co-signer.
func TestGetEnvelopeOwnerSeesIdentityRefs(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","version":2},` +
				`"slots":[{"id":"s-1","orderIndex":0,"identityRef":"PNOLV-22222"}],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "owner-sid", "owner-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out composedDetail
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(out.Slots), 1))
	qt.Check(t, qt.Equals(out.Slots[0].IdentityRef, "PNOLV-22222"))
	// The invited slot belongs to someone else, not the owner's own turn.
	qt.Check(t, qt.IsFalse(out.Slots[0].You))
}

// TestGetEnvelopeSlotLiveStateUnavailableIsBestEffort proves a slot whose backing
// job's live state cannot be read (upstream miss) is still returned — without a
// state — rather than failing the whole envelope view.
func TestGetEnvelopeSlotLiveStateUnavailableIsBestEffort(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","status":"sent","version":2},` +
				`"slots":[{"id":"s-1","orderIndex":0,"jobId":"job-missing"}],"documents":[]}`)},
		// No route for job-missing's status → the doer's default 404 → the job status
		// lookup errors and the slot is returned without a live state.
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid = "slotmiss-sid"
	putSession(t, app, sid, "slotmiss-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out composedDetail
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(out.Slots), 1))
	qt.Check(t, qt.Equals(out.Slots[0].State, ""))
	qt.Check(t, qt.Equals(out.Slots[0].ID, "s-1"))
}

// TestCreateEnvelopeInvalidOrderPolicyRejected proves a create request with an
// orderPolicy outside the allowed enum is rejected by struct validation (422)
// before any upstream call — the wire's own request shape is enforced first.
func TestCreateEnvelopeInvalidOrderPolicyRejected(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &routingDoer{}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "badpolicy-sid", "badpolicy-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes",
		map[string]any{"title": "x", "orderPolicy": "bogus"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(doer.calls), 0))
}

// TestCreateEnvelopeUpstreamErrorRelayed proves a failure from the envelope
// service on create is relayed rather than swallowed.
func TestCreateEnvelopeUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusBadRequest, body: []byte(
			`{"code":"err:envelope:invalidRequest","status":400}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "createerr-sid", "createerr-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes",
		map[string]any{"title": "x"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

// TestListEnvelopesUpstreamErrorRelayed proves a listing failure from the envelope
// service is relayed rather than swallowed.
func TestListEnvelopesUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusInternalServerError, body: []byte(`{"code":"err:envelope:internal","status":500}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid = "listerr-sid"
	putSession(t, app, sid, "listerr-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	fasthttp.ReleaseResponse(resp)
}

// TestSigningTasksUpstreamErrorRelayed proves a signer-inbox failure from the
// envelope service is relayed rather than swallowed.
func TestSigningTasksUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusInternalServerError, body: []byte(`{"code":"err:envelope:internal","status":500}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid = "taskserr-sid"
	putSession(t, app, sid, "taskserr-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/signing-tasks", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	fasthttp.ReleaseResponse(resp)
}

// TestGetEnvelopeUpstreamErrorRelayed proves a lookup failure from the envelope
// service (e.g. an unknown envelope id) is relayed unchanged.
func TestGetEnvelopeUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusNotFound, body: []byte(`{"code":"err:envelope:notFound","status":404}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid = "getenverr-sid"
	putSession(t, app, sid, "getenverr-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-missing", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}

// TestAttachEnvelopeDocumentMissingIdRejected proves an attach request without a
// documentId is rejected by struct validation (422) before any upstream call.
func TestAttachEnvelopeDocumentMissingIdRejected(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &routingDoer{}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "attachmiss-sid", "attachmiss-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/documents",
		map[string]any{},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(doer.calls), 0))
}

// TestAttachEnvelopeDocumentUpstreamErrorRelayed proves a failure attaching a
// document (e.g. it does not exist) is relayed rather than swallowed.
func TestAttachEnvelopeDocumentUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusNotFound, body: []byte(`{"code":"err:document:notFound","status":404}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "attacherr-sid", "attacherr-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/documents",
		map[string]any{"documentId": "doc-missing"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}

// TestAddEnvelopeSlotMissingOrderIndexRejected proves an add-slot request without
// an orderIndex is rejected by struct validation (422) before any upstream call.
func TestAddEnvelopeSlotMissingOrderIndexRejected(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &routingDoer{}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "addslotmiss-sid", "addslotmiss-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots",
		map[string]any{"role": "signer"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(doer.calls), 0))
}

// TestAddEnvelopeSlotUpstreamErrorRelayed proves a failure adding a slot is
// relayed rather than swallowed.
func TestAddEnvelopeSlotUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusConflict, body: []byte(`{"code":"err:envelope:alreadySent","status":409}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "addsloterr-sid", "addsloterr-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots",
		map[string]any{"orderIndex": 1, "role": "signer"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)
}

// TestDeclineEnvelopeSlotUpstreamErrorRelayed proves a failure declining a slot is
// relayed rather than swallowed.
func TestDeclineEnvelopeSlotUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetEnvelope(clients.NewEnvelope(
		&stubDoer{status: fasthttp.StatusConflict, body: []byte(`{"code":"err:envelope:alreadyDecided","status":409}`)},
		"http://envelope:8080", "svc:envelope",
	))

	const sid, csrf = "declineerr-sid", "declineerr-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/decline", nil,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)
}

// TestSignEnvelopeSlotMissingFieldsRejected proves a sign request missing the
// required fields (documentId/flow/sigFormat) is rejected by struct validation
// (422) before the eligibility check or any upstream call.
func TestSignEnvelopeSlotMissingFieldsRejected(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &routingDoer{}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "signmiss-sid", "signmiss-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(doer.calls), 0))
}

// TestSignEnvelopeSlotEligibilityTransportErrorRelayed proves a transport failure
// checking slot eligibility (as opposed to a clean eligible:false answer) is
// relayed rather than swallowed, and signing is never begun.
func TestSignEnvelopeSlotEligibilityTransportErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-1/eligible", status: 500, body: []byte(`{"code":"err:envelope:internal","status":500}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "eligerr-sid", "eligerr-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(doer.calls), 1))
}

// TestSignEnvelopeSlotBeginSigningErrorRelayed proves an eligible slot whose begin-
// signing call fails downstream (e.g. the document changed) relays that failure
// and never records a job on the slot.
func TestSignEnvelopeSlotBeginSigningErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/slots/s-1/eligible", status: 200, body: []byte(`{"eligible":true}`)},
		{method: http.MethodPost, contains: "/api/v1/signings", status: 409, body: []byte(
			`{"code":"err:document:chainAdvanced","status":409}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetSignflow(clients.NewSignflow(doer, "http://signflow:8080", "svc:signflow"))

	const sid, csrf = "beginerr-sid", "beginerr-csrf"
	putSession(t, app, sid, csrf)

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/portal/v1/envelopes/env-1/slots/s-1/sign",
		map[string]any{"documentId": "doc-1", "flow": "eparakstsMobile", "sigFormat": "XAdES"},
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)

	// Only eligibility + the failed begin-signing call ran; no job was recorded.
	qt.Assert(t, qt.Equals(len(doer.calls), 2))
	qt.Check(t, qt.IsTrue(strings.Contains(doer.calls[0], "/slots/s-1/eligible")))
	qt.Check(t, qt.IsTrue(strings.Contains(doer.calls[1], "/api/v1/signings")))
}
