package routes

import (
	"context"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// loggedIn builds an app with a far-future session and returns a started test app
// + the test client, so a preview route can be driven through the cookie session.
func loggedIn(t *testing.T, app *api.App) *azugo.TestApp {
	const sid = "test-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject:      "user-1",
		AccessToken:  "tok",
		AccessExpiry: 1 << 62,
		CSRF:         "test-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)

	return ta
}

func TestPreviewRequiresSession(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/api/portal/v1/documents/doc-1/preview")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// TestPreviewNotConfigured reports not-ready until the preview service is wired.
func TestPreviewNotConfigured(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1/preview", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
	fasthttp.ReleaseResponse(resp)
}

// TestPreviewManifestThroughBFF drives a logged-in session through the BFF to the
// (stubbed) preview service and relays the manifest.
func TestPreviewManifestThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetPreview(clients.NewPreview(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(`{"documentId":"doc-1","renderable":true,"pageCount":1}`)},
		"http://previewbyte:8080", "svc:preview",
	))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1/preview", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// TestPreviewPageThroughBFF relays a rendered page image from the preview service.
func TestPreviewPageThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetPreview(clients.NewPreview(
		&stubDoer{status: fasthttp.StatusOK, body: []byte("\x89PNG\r\n\x1a\n")},
		"http://previewbyte:8080", "svc:preview",
	))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1/preview/pages/0", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// TestInnerPreviewManifestThroughBFF relays the manifest for one inner file of a
// container, addressed by (container id, inner name).
func TestInnerPreviewManifestThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetPreview(clients.NewPreview(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(`{"documentId":"cont-1","renderable":true,"pageCount":1}`)},
		"http://previewbyte:8080", "svc:preview",
	))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/cont-1/data-objects/report.pdf/preview", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// TestInnerPreviewPageThroughBFF relays a rendered inner-file page image.
func TestInnerPreviewPageThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetPreview(clients.NewPreview(
		&stubDoer{status: fasthttp.StatusOK, body: []byte("\x89PNG\r\n\x1a\n")},
		"http://previewbyte:8080", "svc:preview",
	))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/cont-1/data-objects/report.pdf/preview/pages/0", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}
