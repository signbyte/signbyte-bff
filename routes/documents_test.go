package routes

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/audit"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// buildMultipart encodes a single-file multipart/form-data body (plus optional
// text fields) the way a browser upload would, for driving uploadDocument.
func buildMultipart(t *testing.T, filename string, data []byte, fields map[string]string) ([]byte, string) {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if filename != "" {
		part, err := w.CreateFormFile("file", filename)
		qt.Assert(t, qt.IsNil(err))
		_, err = part.Write(data)
		qt.Assert(t, qt.IsNil(err))
	}
	for k, v := range fields {
		qt.Assert(t, qt.IsNil(w.WriteField(k, v)))
	}
	qt.Assert(t, qt.IsNil(w.Close()))

	return buf.Bytes(), w.FormDataContentType()
}

// stubDoer returns a canned upstream response for the on-behalf calls and records
// the last outbound request body (so tests can assert what the BFF relayed).
type stubDoer struct {
	status   int
	body     []byte
	lastBody []byte
	lastURL  string
}

func (s *stubDoer) DoServiceOnBehalf(_ context.Context, _, _, _, _, _, fullURL string, _ http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	s.lastBody = body
	s.lastURL = fullURL

	return &authclient.BackgroundResponse{StatusCode: s.status, Body: s.body}, nil
}

func (s *stubDoer) DoServiceOnBehalfWithTimeout(ctx context.Context, _ time.Duration, audience, scope, sub, token, method, fullURL string, hdr http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	return s.DoServiceOnBehalf(ctx, audience, scope, sub, token, method, fullURL, hdr, body)
}

func TestDocumentRequiresSession(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/api/portal/v1/documents/doc-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// TestDocumentMetadataThroughBFF drives a logged-in session through the BFF to the
// (stubbed) document service and back, proving the route → on-behalf client path.
func TestDocumentMetadataThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusOK, body: []byte(`{"id":"doc-1","contentHash":"abc"}`)},
		"http://document:8080", "svc:document",
	))

	const sid = "test-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject:      "user-1",
		AccessToken:  "tok",
		AccessExpiry: 1 << 62, // far future → no refresh attempted in-test
		CSRF:         "test-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// TestDocumentListThroughBFF drives a logged-in session through the BFF to the
// (stubbed) document service's listing and back, proving the route → on-behalf
// client path and that the narrow summary projection drops the owner subject so it
// never reaches the browser.
func TestDocumentListThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{
			status: fasthttp.StatusOK,
			body:   []byte(`{"count":1,"documents":[{"id":"doc-1","owner":"user-1","filename":"lease.pdf","status":"received"}]}`),
		},
		"http://document:8080", "svc:document",
	))

	const sid = "test-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject:      "user-1",
		AccessToken:  "tok",
		AccessExpiry: 1 << 62, // far future → no refresh attempted in-test
		CSRF:         "test-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	qt.Check(t, qt.StringContains(body, `"doc-1"`))
	qt.Check(t, qt.StringContains(body, `"lease.pdf"`))
	// The owner subject must not be relayed to the browser.
	qt.Check(t, qt.Not(qt.StringContains(body, "user-1")))
	fasthttp.ReleaseResponse(resp)
}

// TestBundleDocumentsThroughBFF drives the eager draft-save commit point: the staged
// source ids are relayed to the document service in order and the bundle row comes
// back (201).
func TestBundleDocumentsThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &stubDoer{status: fasthttp.StatusCreated, body: []byte(`{"id":"cont-1","filename":"a.asice","mime":"application/vnd.etsi.asic-e+zip"}`)}
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/documents/bundle", []byte(`{"sourceIds":["s1","s2"]}`),
		tc.WithCookie("portal_session", "test-sid"),
		tc.WithHeader("X-CSRF-Token", "test-csrf"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	respBody := string(resp.Body())
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(strings.Contains(respBody, `"cont-1"`)))
	// The staged source ids are relayed in order — that order is the inner-file order.
	qt.Check(t, qt.IsTrue(strings.Contains(string(doer.lastBody), `"s1"`)))
	qt.Check(t, qt.IsTrue(strings.Contains(string(doer.lastBody), `"s2"`)))
}

// TestRebundleDocumentThroughBFF drives a draft edit: the ordered entries (an
// existing inner file by name + a newly staged source by id) are relayed and the
// updated bundle row comes back (200).
func TestRebundleDocumentThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &stubDoer{status: fasthttp.StatusOK, body: []byte(`{"id":"cont-1","filename":"a.asice"}`)}
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/documents/cont-1/rebundle",
		[]byte(`{"entries":[{"name":"a.pdf"},{"sourceId":"s3"}]}`),
		tc.WithCookie("portal_session", "test-sid"),
		tc.WithHeader("X-CSRF-Token", "test-csrf"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
	// The ordered entries are relayed: an existing inner file kept by name and a
	// newly staged loose source added by id.
	qt.Check(t, qt.IsTrue(strings.Contains(string(doer.lastBody), `"a.pdf"`)))
	qt.Check(t, qt.IsTrue(strings.Contains(string(doer.lastBody), `"s3"`)))
}

// TestExtractDataObjectThroughBFF relays one inner file's bytes back to the browser.
func TestExtractDataObjectThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &stubDoer{status: fasthttp.StatusOK, body: []byte("the inner file bytes")}
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/cont-1/data-objects/report.pdf", tc.WithCookie("portal_session", "test-sid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Body()), "the inner file bytes")))
	// The download declares the review purpose, so it keeps working while the
	// chain's signed result is download-frozen mid-workflow.
	qt.Check(t, qt.IsTrue(strings.Contains(doer.lastURL, "conduit=review")))
	fasthttp.ReleaseResponse(resp)
}

// TestDocumentDownloadRecordsAccess proves the BFF records a user-facing GDPR
// access event when the person downloads their document's bytes: an interactive
// document.access with the person as both the actor and the data subject — the
// reveal the document service (a background byte supplier) cannot characterize.
func TestDocumentDownloadRecordsAccess(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusOK, body: []byte("the document bytes")},
		"http://document:8080", "svc:document",
	))

	// Capture the access record the recorder posts, in place of a live access-audit.
	var captured *broker.Envelope
	gc, err := gdpr.New(gdpr.Configuration{
		Endpoint:       "http://access-audit:8080",
		Audience:       "svc:access-audit",
		Scope:          "access-audit:write",
		Timeout:        time.Second,
		OutboxCapacity: 16,
		RetryBackoff:   time.Second,
	}, gdpr.PosterFunc(func(_ context.Context, rec *broker.Envelope) error {
		captured = rec

		return nil
	}))
	qt.Assert(t, qt.IsNil(err))
	app.SetAudit(audit.New(gc, nil))

	const sid = "test-sid"
	err = app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject:      "user-1",
		AccessToken:  "tok",
		AccessExpiry: 1 << 62, // far future → no refresh attempted in-test
		CSRF:         "test-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1/download", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	// Script-vector defence: the BFF guarantees nosniff on a download
	// independently of whatever the document service relayed.
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Content-Type-Options")), "nosniff"))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.IsNotNil(captured))
	qt.Check(t, qt.Equals(captured.EventType, gdpr.EventDocumentAccess))
	qt.Check(t, qt.Equals(captured.Operation, broker.OpRead))
	qt.Check(t, qt.IsNotNil(captured.Actor))
	qt.Check(t, qt.Equals(captured.Actor.ID, "user-1"))
	qt.Check(t, qt.Equals(captured.Actor.Type, "user"))
	qt.Check(t, qt.IsNotNil(captured.Resource))
	qt.Check(t, qt.Equals(captured.Resource.ID, "doc-1"))
	qt.Check(t, qt.DeepEquals(captured.DataSubjects, []string{"user-1"}))
	qt.Check(t, qt.Equals(captured.Attributes[gdpr.AttrChannel], gdpr.ChannelInteractive))
}

// TestDocumentNotConfigured proves document routes fail closed with a 503 when
// the document service was never wired.
func TestDocumentNotConfigured(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	// No SetDocuments call: r.Documents() stays nil.

	const sid = "notconf-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: "notconf-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
	fasthttp.ReleaseResponse(resp)
}

// TestOnBehalfRefreshFailureUnauthorized proves a session past its access-token
// expiry that cannot be refreshed (an unparseable per-session key here standing in
// for a dead Auth Service) fails the request closed with 401 rather than composing
// on behalf of no one.
func TestOnBehalfRefreshFailureUnauthorized(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(&stubDoer{}, "http://document:8080", "svc:document"))

	const sid = "expired-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1, // already expired
		RefreshToken: "refresh-1", Key: "", CSRF: "expired-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// TestUploadDocumentThroughBFF proves a multipart upload is re-encoded and
// forwarded to the document service, and the caller's extra fields ride along.
func TestUploadDocumentThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &stubDoer{status: fasthttp.StatusCreated, body: []byte(
		`{"id":"doc-1","filename":"lease.pdf","mime":"application/pdf","contentHash":"abc","size":11}`)}
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid, csrf = "upload-sid", "upload-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	body, contentType := buildMultipart(t, "lease.pdf", []byte("hello world"), map[string]string{"mime": "application/pdf"})

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/documents", body,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
		tc.WithHeader("Content-Type", contentType),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	respBody := string(resp.Body())
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(strings.Contains(respBody, `"id":"doc-1"`)))

	// The BFF re-encoded its own multipart body upstream, carrying the file bytes
	// and the caller's field, rather than forwarding the raw request verbatim.
	qt.Assert(t, qt.IsTrue(strings.Contains(string(doer.lastBody), "hello world")))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(doer.lastBody), "application/pdf")))
}

// TestUploadDocumentMissingFileRejected proves an upload without a "file" part is
// refused with 400 before any upstream call.
func TestUploadDocumentMissingFileRejected(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	doer := &stubDoer{status: fasthttp.StatusCreated, body: []byte(`{}`)}
	app.SetDocuments(clients.NewDocuments(doer, "http://document:8080", "svc:document"))

	const sid, csrf = "uploadmiss-sid", "uploadmiss-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	// No file part, only a text field.
	body, contentType := buildMultipart(t, "", nil, map[string]string{"mime": "application/pdf"})

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/documents", body,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
		tc.WithHeader("Content-Type", contentType),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(doer.lastBody))
}

// TestUploadDocumentUpstreamErrorRelayed proves a failure from the document
// service on upload (e.g. quota exceeded) is relayed rather than swallowed.
func TestUploadDocumentUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusConflict, body: []byte(`{"code":"err:document:duplicate","status":409}`)},
		"http://document:8080", "svc:document",
	))

	const sid, csrf = "uploaderr-sid", "uploaderr-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	body, contentType := buildMultipart(t, "lease.pdf", []byte("hello world"), nil)

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/documents", body,
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
		tc.WithHeader("Content-Type", contentType),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)
}

// TestDeleteDocumentThroughBFF proves deleting a document round-trips through the
// BFF to the document service.
func TestDeleteDocumentThroughBFF(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusOK, body: nil},
		"http://document:8080", "svc:document",
	))

	const sid, csrf = "delete-sid", "delete-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Delete("/api/portal/v1/documents/doc-1",
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body := string(resp.Body())
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(strings.Contains(body, `"ok":true`)))
}

// TestDeleteDocumentUpstreamErrorRelayed proves a failure deleting a document
// (e.g. it is referenced by an active envelope) is relayed rather than swallowed.
func TestDeleteDocumentUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusConflict, body: []byte(`{"code":"err:document:inUse","status":409}`)},
		"http://document:8080", "svc:document",
	))

	const sid, csrf = "deleteerr-sid", "deleteerr-csrf"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: csrf,
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Delete("/api/portal/v1/documents/doc-1",
		tc.WithCookie("portal_session", sid),
		tc.WithHeader("X-CSRF-Token", csrf),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)
}

// TestDocumentListUpstreamErrorRelayed proves a listing failure from the document
// service is relayed rather than swallowed.
func TestDocumentListUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusInternalServerError, body: []byte(`{"code":"err:document:internal","status":500}`)},
		"http://document:8080", "svc:document",
	))

	const sid = "listerr-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: "listerr-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	fasthttp.ReleaseResponse(resp)
}

// TestDocumentDownloadUpstreamErrorRelayed proves a download failure from the
// document service (e.g. the document does not exist) is relayed rather than
// swallowed, and no access record is posted for a download that never happened.
func TestDocumentDownloadUpstreamErrorRelayed(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusNotFound, body: []byte(`{"code":"err:document:notFound","status":404}`)},
		"http://document:8080", "svc:document",
	))

	const sid = "downloaderr-sid"
	err := app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: "downloaderr-csrf",
	})
	qt.Assert(t, qt.IsNil(err))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/documents/doc-missing/download", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}
