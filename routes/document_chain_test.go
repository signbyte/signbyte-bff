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

// A chain the dashboard deliberately omits is still fully readable on its own.
// The dashboard subtracts a chain an envelope covers — correct for a listing
// that must not show a document next to the envelope containing it — so the
// document screen must NOT source its facts from that listing. This asserts both
// halves in one run: the covered chain is absent from the dashboard, and the
// chain read still reports it as signed here, with what is inside it.
func TestChainReadAnswersForAnEnvelopeCoveredChain(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/signing-tasks", status: 200, body: []byte(`{"tasks":[]}`)},
		{method: http.MethodGet, contains: "/api/v1/envelopes", status: 200, body: []byte(
			`{"envelopes":[{"id":"env-1","status":"completed","version":3,"docIds":["doc-1"],` +
				`"slotCount":1,"signedCount":1,"yourTurn":false}]}`)},
		{method: http.MethodGet, contains: "view=chains", status: 200, body: []byte(
			`{"chains":[{"chainRootId":"doc-1","id":"doc-1","kind":"container","status":"signed",` +
				`"filename":"signed.asice","hasSignatures":true,"platformSigned":true}],"count":1}`)},
		{method: http.MethodGet, contains: "/documents/doc-1/chain", status: 200, body: []byte(
			`{"chainRootId":"doc-1","id":"doc-1","kind":"container","status":"signed",` +
				`"filename":"signed.asice","hasSignatures":true,"platformSigned":true,` +
				`"preservationClass":"none","innerFiles":[{"name":"contract.pdf","mediaType":"application/pdf"}]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid = "chain-sid"
	putSession(t, app, sid, "chain-csrf")

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()
	tc := ta.TestClient()

	// The dashboard drops it — the envelope speaks for the chain there.
	resp, err := tc.Get("/api/portal/v1/dashboard", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var dash struct {
		Chains []clients.ChainRow `json:"chains"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &dash)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(dash.Chains), 0))

	// ...and the chain read still knows everything the screen needs.
	resp, err = tc.Get("/api/portal/v1/documents/doc-1/chain", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var chain clients.ChainRow
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &chain)))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(chain.ID, "doc-1"))
	qt.Assert(t, qt.IsTrue(chain.PlatformSigned))
	qt.Assert(t, qt.IsTrue(chain.HasSignatures))
	qt.Assert(t, qt.Equals(len(chain.InnerFiles), 1))
	qt.Assert(t, qt.Equals(chain.InnerFiles[0].Name, "contract.pdf"))
}
