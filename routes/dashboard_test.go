package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The composed dashboard enforces the row model server-side: one row per
// envelope plus one row per STANDALONE chain — a chain covered by an envelope
// (matched on its root or head id) is subtracted, so N envelopes/chains render
// exactly N rows and a document never appears next to the envelope containing it.
func TestDashboardSubtractsEnvelopeCoveredChains(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/signing-tasks", status: 200, body: []byte(
			`{"tasks":[]}`)},
		{method: http.MethodGet, contains: "/api/v1/envelopes", status: 200, body: []byte(
			`{"envelopes":[{"id":"env-1","status":"in_progress","version":2,"docIds":["doc-1"],` +
				`"slotCount":2,"signedCount":1,"yourTurn":false}]}`)},
		{method: http.MethodGet, contains: "view=chains", status: 200, body: []byte(
			`{"chains":[` +
				`{"chainRootId":"doc-1","id":"cont-1","kind":"container","status":"signed","filename":"covered.asice","hasSignatures":true,"platformSigned":true},` +
				`{"chainRootId":"doc-2","id":"doc-2","kind":"source","status":"received","filename":"standalone.pdf"}` +
				`],"count":2}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "dash-sid"
	putSession(t, app, sid, "dash-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/dashboard", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := resp.Body()

	var out struct {
		Tasks     []json.RawMessage  `json:"tasks"`
		Envelopes []clients.Summary  `json:"envelopes"`
		Chains    []clients.ChainRow `json:"chains"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	fasthttp.ReleaseResponse(resp)

	// One envelope row + one standalone chain row: the doc-1 chain is covered by
	// env-1 and must not render as a second row.
	qt.Assert(t, qt.Equals(len(out.Envelopes), 1))
	qt.Assert(t, qt.Equals(out.Envelopes[0].ID, "env-1"))
	qt.Assert(t, qt.Equals(len(out.Chains), 1))
	qt.Assert(t, qt.Equals(out.Chains[0].ChainRootID, "doc-2"))
	qt.Assert(t, qt.Equals(len(out.Tasks), 0))
}

// The subtraction covers INVITED-signer envelopes too: a co-signer owns no envelopes,
// but their signing task's envelope carries its document ids, and the shared chain
// (readable via the send-time access grant) must not render as the co-signer's own
// standalone document while the invitation is open.
func TestDashboardSubtractsSigningTaskCoveredChains(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/signing-tasks", status: 200, body: []byte(
			`{"tasks":[{"envelope":{"id":"env-9","status":"sent","orderPolicy":"sequential",` +
				`"version":1,"docIds":["doc-9"]},"slotId":"slot-2","orderIndex":2,` +
				`"slotStatus":"sent","yourTurn":false}]}`)},
		{method: http.MethodGet, contains: "/api/v1/envelopes", status: 200, body: []byte(
			`{"envelopes":[]}`)},
		{method: http.MethodGet, contains: "view=chains", status: 200, body: []byte(
			`{"chains":[` +
				`{"chainRootId":"doc-9","id":"doc-9","kind":"source","status":"received","filename":"shared.png"},` +
				`{"chainRootId":"doc-8","id":"doc-8","kind":"source","status":"received","filename":"own.pdf","resultFrozen":true}` +
				`],"count":2}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "dash-cosigner-sid"
	putSession(t, app, sid, "dash-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/dashboard", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := resp.Body()

	var out struct {
		Tasks     []json.RawMessage  `json:"tasks"`
		Envelopes []clients.Summary  `json:"envelopes"`
		Chains    []clients.ChainRow `json:"chains"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	fasthttp.ReleaseResponse(resp)

	// The task renders; the shared doc-9 chain is task-covered and must be
	// subtracted; the viewer's own doc-8 chain stays — carrying the freeze flag
	// through so the SPA can render "in signing".
	qt.Assert(t, qt.Equals(len(out.Tasks), 1))
	qt.Assert(t, qt.Equals(len(out.Envelopes), 0))
	qt.Assert(t, qt.Equals(len(out.Chains), 1))
	qt.Assert(t, qt.Equals(out.Chains[0].ChainRootID, "doc-8"))
	qt.Assert(t, qt.IsTrue(out.Chains[0].ResultFrozen))
}

// Signing one document repeatedly must not multiply its rows: each signing run
// creates its own envelope over the same document, and the dashboard keeps only
// the envelope that acted last, so the document still renders as a single row.
func TestDashboardKeepsOnlyTheLatestEnvelopePerDocument(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/signing-tasks", status: 200, body: []byte(
			`{"tasks":[]}`)},
		// Three envelopes over doc-1, newest first, plus one over doc-2 and an
		// envelope draft with nothing attached yet.
		{method: http.MethodGet, contains: "/api/v1/envelopes", status: 200, body: []byte(
			`{"envelopes":[` +
				`{"id":"env-3","status":"completed","version":4,"docIds":["doc-1"],"updatedAt":"2026-08-12T19:18:35Z","slotCount":1,"signedCount":1},` +
				`{"id":"env-2","status":"completed","version":4,"docIds":["doc-1"],"updatedAt":"2026-08-12T19:02:27Z","slotCount":1,"signedCount":1},` +
				`{"id":"env-1","status":"completed","version":4,"docIds":["doc-1"],"updatedAt":"2026-08-12T18:24:09Z","slotCount":1,"signedCount":1},` +
				`{"id":"env-other","status":"completed","version":4,"docIds":["doc-2"],"updatedAt":"2026-08-12T18:25:57Z","slotCount":1,"signedCount":1},` +
				`{"id":"env-empty","status":"draft","version":1,"slotCount":0,"signedCount":0}` +
				`]}`)},
		{method: http.MethodGet, contains: "view=chains", status: 200, body: []byte(
			`{"chains":[` +
				`{"chainRootId":"doc-1","id":"doc-1","kind":"container","status":"signed","filename":"one.asice","hasSignatures":true},` +
				`{"chainRootId":"doc-2","id":"doc-2","kind":"container","status":"signed","filename":"two.asice","hasSignatures":true}` +
				`],"count":2}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "dash-latest-sid"
	putSession(t, app, sid, "dash-latest-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/dashboard", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := resp.Body()

	var out struct {
		Tasks     []json.RawMessage  `json:"tasks"`
		Envelopes []clients.Summary  `json:"envelopes"`
		Chains    []clients.ChainRow `json:"chains"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	fasthttp.ReleaseResponse(resp)

	// doc-1's two older envelopes are gone; doc-2's envelope and the unattached
	// draft both stay. Both chains are envelope-covered, so no standalone rows.
	ids := make([]string, 0, len(out.Envelopes))
	for _, e := range out.Envelopes {
		ids = append(ids, e.ID)
	}
	qt.Assert(t, qt.DeepEquals(ids, []string{"env-3", "env-other", "env-empty"}))
	qt.Assert(t, qt.Equals(len(out.Chains), 0))
}

// An envelope-covered document has no chain row left to state its auto-delete
// instant, so the envelope carries it instead — the soonest among its documents.
// Without this a workflow-touched document shows no time-to-live at all, which
// reads as "kept forever" for exactly the documents that are not.
func TestDashboardEnvelopeCarriesSoonestDocumentRetention(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/signing-tasks", status: 200, body: []byte(
			`{"tasks":[]}`)},
		{method: http.MethodGet, contains: "/api/v1/envelopes", status: 200, body: []byte(
			`{"envelopes":[` +
				`{"id":"env-1","status":"completed","version":2,"docIds":["doc-1","doc-2"],"updatedAt":"2026-08-13T12:00:00Z","slotCount":1,"signedCount":1},` +
				`{"id":"env-none","status":"draft","version":1,"docIds":["doc-unknown"],"slotCount":0,"signedCount":0}` +
				`]}`)},
		// doc-2 expires first, so it is the one the envelope must report.
		{method: http.MethodGet, contains: "view=chains", status: 200, body: []byte(
			`{"chains":[` +
				`{"chainRootId":"doc-1","id":"head-1","kind":"container","status":"signed","filename":"a.asice","retentionUntil":"2026-08-14T18:00:00Z"},` +
				`{"chainRootId":"doc-2","id":"head-2","kind":"container","status":"signed","filename":"b.asice","retentionUntil":"2026-08-14T06:00:00Z"}` +
				`],"count":2}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "dash-ttl-sid"
	putSession(t, app, sid, "dash-ttl-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/dashboard", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := resp.Body()

	var out struct {
		Envelopes []clients.Summary  `json:"envelopes"`
		Chains    []clients.ChainRow `json:"chains"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	fasthttp.ReleaseResponse(resp)

	byID := map[string]clients.Summary{}
	for _, e := range out.Envelopes {
		byID[e.ID] = e
	}
	// The soonest of the two, not the later one and not the first seen.
	qt.Assert(t, qt.Equals(byID["env-1"].RetentionUntil, "2026-08-14T06:00:00Z"))
	// An envelope whose document is not in the chain listing stays empty rather
	// than claiming an unbounded life.
	qt.Assert(t, qt.Equals(byID["env-none"].RetentionUntil, ""))
}

// Retention destroys a document's storage while the envelope RECORD legitimately
// survives in its grace window — but the dashboard must not keep rendering that
// record as a live row: every action it offers can only answer 410 Gone, and the
// chain's home is history. A terminal envelope whose documents all fail to resolve
// in the live chain listing is dropped; a draft with no documents yet and a
// non-terminal envelope over destroyed storage both stay (the latter deliberately —
// hiding an in-flight workflow is a product decision, not a compose default).
func TestDashboardDropsTerminalEnvelopesOverDestroyedChains(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/signing-tasks", status: 200, body: []byte(
			`{"tasks":[]}`)},
		{method: http.MethodGet, contains: "/api/v1/envelopes", status: 200, body: []byte(
			`{"envelopes":[` +
				// completed over a chain the live listing no longer carries → dropped
				`{"id":"env-dead","status":"completed","version":3,"docIds":["doc-gone"],"slotCount":1,"signedCount":1,"yourTurn":false},` +
				// completed over a still-live chain → stays
				`{"id":"env-live","status":"completed","version":3,"docIds":["doc-live"],"slotCount":1,"signedCount":1,"yourTurn":false},` +
				// sent over a destroyed chain → stays (the open in-flight window)
				`{"id":"env-open","status":"sent","version":2,"docIds":["doc-gone-2"],"slotCount":2,"signedCount":0,"yourTurn":true},` +
				// draft with nothing attached → stays (a row in its own right)
				`{"id":"env-draft","status":"draft","version":1,"slotCount":0,"signedCount":0,"yourTurn":false}` +
				`]}`)},
		{method: http.MethodGet, contains: "view=chains", status: 200, body: []byte(
			`{"chains":[` +
				`{"chainRootId":"doc-live","id":"cont-live","kind":"container","status":"signed","filename":"alive.asice","hasSignatures":true,"platformSigned":true}` +
				`],"count":1}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "dash-destroyed-sid"
	putSession(t, app, sid, "dash-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/dashboard", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := resp.Body()

	var out struct {
		Envelopes []clients.Summary  `json:"envelopes"`
		Chains    []clients.ChainRow `json:"chains"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)))
	fasthttp.ReleaseResponse(resp)

	ids := make([]string, 0, len(out.Envelopes))
	for _, e := range out.Envelopes {
		ids = append(ids, e.ID)
	}
	qt.Assert(t, qt.Equals(len(out.Envelopes), 3), qt.Commentf("rows: %v", ids))
	qt.Check(t, qt.SliceContains(ids, "env-live"))
	qt.Check(t, qt.SliceContains(ids, "env-open"))
	qt.Check(t, qt.SliceContains(ids, "env-draft"))
	// The dead one is the assertion's point: present in the upstream answer,
	// absent from the composed view.
	qt.Check(t, qt.Not(qt.SliceContains(ids, "env-dead")))
}
