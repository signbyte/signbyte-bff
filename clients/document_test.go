package clients

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-quicktest/qt"
)

// stubDoer records the last on-behalf call and returns a canned response.
type stubDoer struct {
	resp *authclient.BackgroundResponse
	err  error

	lastSub      string
	lastToken    string
	lastAudience string
	lastScope    string
	lastMethod   string
	lastURL      string
	lastBody     []byte
	lastTimeout  time.Duration
}

func (s *stubDoer) DoServiceOnBehalf(_ context.Context, audience, scope, subjectSub, subjectToken, method, fullURL string, _ http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	s.lastAudience, s.lastScope = audience, scope
	s.lastSub, s.lastToken = subjectSub, subjectToken
	s.lastMethod, s.lastURL = method, fullURL
	s.lastBody = body

	return s.resp, s.err
}

func (s *stubDoer) DoServiceOnBehalfWithTimeout(ctx context.Context, timeout time.Duration, audience, scope, subjectSub, subjectToken, method, fullURL string, hdr http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	s.lastTimeout = timeout

	return s.DoServiceOnBehalf(ctx, audience, scope, subjectSub, subjectToken, method, fullURL, hdr, body)
}

func TestMetadataOnBehalf(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"id":"doc-1","filename":"f.pdf","mime":"application/pdf","contentHash":"abc","size":3,"preservationClass":"none"}`),
	}}
	docs := NewDocuments(d, "http://document:8080", "svc:document")

	meta, err := docs.Metadata(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "doc-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(meta.ID, "doc-1"))
	qt.Assert(t, qt.Equals(meta.ContentHash, "abc"))
	// The call went out on behalf of the user, read scope, at the document audience.
	qt.Assert(t, qt.Equals(d.lastSub, "user-1"))
	qt.Assert(t, qt.Equals(d.lastToken, "tok"))
	qt.Assert(t, qt.Equals(d.lastAudience, "svc:document"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeDocRead))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodGet))
	qt.Assert(t, qt.Equals(d.lastURL, "http://document:8080/api/v1/documents/doc-1"))
}

func TestUploadOnBehalfWriteScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body:       []byte(`{"id":"doc-2","contentHash":"h","mime":"text/plain","size":5,"preservationClass":"none"}`),
	}}
	docs := NewDocuments(d, "http://document:8080", "svc:document")

	meta, err := docs.Upload(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "multipart/form-data; boundary=x", []byte("body"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(meta.ID, "doc-2"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeDocWrite))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
}

func TestContentRelaysBytes(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/pdf"}},
		Body:       []byte("PDFBYTES"),
	}}
	docs := NewDocuments(d, "http://document:8080", "svc:document")

	resp, err := docs.Content(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "doc-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(resp.Body), "PDFBYTES"))
	qt.Assert(t, qt.Equals(resp.Header.Get("Content-Type"), "application/pdf"))
}

func TestUpstreamErrorMappedToHTTPError(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{StatusCode: 404, Body: []byte("nope")}}
	docs := NewDocuments(d, "http://document:8080", "svc:document")

	_, err := docs.Metadata(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "missing")
	var he *HTTPError
	qt.Assert(t, qt.IsTrue(err != nil))
	qt.Assert(t, qt.IsTrue(errors.As(err, &he)))
	qt.Assert(t, qt.Equals(he.StatusCode, 404))
}

// TestFailsClosedWithoutToken proves a call with no subject token never reaches
// the doer (it cannot fall back to this service's own identity).
func TestFailsClosedWithoutToken(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{StatusCode: 200}}
	docs := NewDocuments(d, "http://document:8080", "svc:document")

	_, err := docs.Metadata(context.Background(), OnBehalf{Sub: "user-1", Token: ""}, "doc-1")
	qt.Assert(t, qt.IsTrue(err != nil))
	qt.Assert(t, qt.Equals(d.lastMethod, "")) // doer never called
}

func TestBundleOnBehalf(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body:       []byte(`{"id":"bundle-1","filename":"a.asice","mime":"application/vnd.etsi.asic-e+zip","contentHash":"xyz","size":9}`),
	}}
	docs := NewDocuments(d, "http://document:8080", "svc:document")

	meta, err := docs.Bundle(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, []string{"d1", "d2", "d3"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(meta.ID, "bundle-1"))
	// Write scope, POST to the bundle route, sender order preserved verbatim.
	qt.Assert(t, qt.Equals(d.lastScope, scopeDocWrite))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
	qt.Assert(t, qt.Equals(d.lastURL, "http://document:8080/api/v1/documents/bundle"))
	qt.Assert(t, qt.Equals(string(d.lastBody), `{"sourceIds":["d1","d2","d3"]}`))
}
