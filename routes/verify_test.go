package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/audit"
	"github.com/signbyte/signbyte-bff/clients"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// verifyStubDoer scripts the signing service's answer to the verify proxy and
// records what was sent.
type verifyStubDoer struct {
	mu       sync.Mutex
	status   int
	body     []byte
	header   http.Header
	err      error
	timeout  time.Duration
	audience string
	scope    string
	url      string
	calls    int
}

func (s *verifyStubDoer) DoServiceWithTimeout(_ context.Context, timeout time.Duration, audience, scope, _, fullURL string, _ http.Header, _ []byte) (*authclient.BackgroundResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeout, s.audience, s.scope, s.url = timeout, audience, scope, fullURL
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	hdr := s.header
	if hdr == nil {
		hdr = http.Header{}
	}

	return &authclient.BackgroundResponse{StatusCode: s.status, Header: hdr, Body: s.body}, nil
}

// verifyEventsDoer records posted abuse-evidence events.
type verifyEventsDoer struct {
	mu     sync.Mutex
	events [][]byte
	done   chan struct{}
}

func (s *verifyEventsDoer) DoService(_ context.Context, _, _, _, _ string, _ http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	s.mu.Lock()
	s.events = append(s.events, append([]byte(nil), body...))
	s.mu.Unlock()
	select {
	case s.done <- struct{}{}:
	default:
	}

	return &authclient.BackgroundResponse{StatusCode: 202}, nil
}

// verifyTestApp builds a route test app with the verify proxy wired to the
// given stub and generous rate limits (the rate-limit path has its own test).
func verifyTestApp(t *testing.T, stub *verifyStubDoer, events *verifyEventsDoer) *azugo.TestApp {
	t.Helper()

	t.Setenv("VERIFY_RATE_PER_MINUTE", "600")
	t.Setenv("VERIFY_RATE_BURST", "100")

	app := api.TestApp(t)
	app.SetVerify(clients.NewVerify(stub, "http://signer:8080", "svc:eparaksts-signer"))
	if events != nil {
		app.SetVerifyAudit(audit.NewVerifyRecorder(events, "http://access-audit:8080", "svc:access-audit", nil, nil))
	}

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

// samplePDF builds a minimal, valid, unsigned single-page PDF with correct
// cross-reference offsets, so it parses without relying on a repair path.
func samplePDF() []byte {
	var buf bytes.Buffer
	offsets := make([]int, 4)

	buf.WriteString("%PDF-1.4\n")
	obj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}

	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")

	xref := buf.Len()
	buf.WriteString("xref\n0 4\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)

	return buf.Bytes()
}

// signedSamplePDF extends samplePDF with an incremental update carrying an
// INVISIBLE signature (a /Type /Sig dictionary, an AcroForm signature field
// with a zero-rect widget, a chained second xref) — the shape an external
// signing tool produces. Structural only; presence is what the gate reads.
func signedSamplePDF() []byte {
	base := samplePDF()
	prevXref := bytes.LastIndex(base, []byte("xref"))

	var b bytes.Buffer
	b.Write(base)
	offsets := map[int]int{}
	obj := func(num int, body string) {
		offsets[num] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", num, body)
	}
	obj(4, "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached"+
		" /ByteRange [0 1024 2048 512] /Contents <3082000a0500> >>")
	obj(5, "<< /FT /Sig /T (Signature1) /V 4 0 R /Type /Annot /Subtype /Widget"+
		" /Rect [0 0 0 0] /F 132 /P 3 0 R >>")
	obj(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>")

	xrefAt := b.Len()
	fmt.Fprintf(&b, "xref\n0 1\n0000000000 65535 f \n1 1\n%010d 00000 n \n4 2\n%010d 00000 n \n%010d 00000 n \n",
		offsets[1], offsets[4], offsets[5])
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", prevXref, xrefAt)

	return b.Bytes()
}

// sampleV2Report is a minimal SignAPI v2 validation report the normalizer can
// read to a PASSED answer.
var sampleV2Report = `{"data":{"validationConclusion":"POSITIVE","signaturesCount":1,"validSignaturesCount":1,` +
	`"signaturesExt":[{"id":"S1","signatureFormat":"PAdES_BASELINE_LT","signatureLevel":"QESIG","indication":"TOTAL-PASSED",` +
	`"signerExt":{"commonName":"JOHN DOE","serialNumber":"` + testSerial(0, 0) + `"},"info":{"bestSignatureTime":"2026-07-19T10:00:00Z"},` +
	`"signatureScopes":[{"name":"doc.pdf"}]}]}}`

func postVerify(t *testing.T, app *azugo.TestApp, filename string, data []byte) *fasthttp.Response {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filename)
	qt.Assert(t, qt.IsNil(err))
	_, err = part.Write(data)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(w.Close()))

	tc := app.TestClient()
	resp, err := tc.Post("/api/portal/v1/verify", buf.Bytes(),
		tc.WithHeader("Content-Type", w.FormDataContentType()))
	qt.Assert(t, qt.IsNil(err))

	return resp
}

func TestVerifyHappyPathNormalizesAndEmitsEvidence(t *testing.T) {
	stub := &verifyStubDoer{status: 200, body: []byte(sampleV2Report),
		header: http.Header{"X-Validation-Session": []string{"sess-42"}}}
	events := &verifyEventsDoer{done: make(chan struct{}, 1)}
	app := verifyTestApp(t, stub, events)
	app.Start(t)
	defer app.Stop()

	resp := postVerify(t, app, "signed.pdf", signedSamplePDF())
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var v struct {
		Verdict string `json:"verdict"`
		Pass    bool   `json:"pass"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &v)))
	qt.Check(t, qt.Equals(v.Verdict, "PASSED"))
	qt.Check(t, qt.IsTrue(v.Pass))

	// The upstream call ran under the slow-op per-call ceiling with the read scope.
	qt.Check(t, qt.Equals(stub.scope, "signatures:read"))
	qt.Check(t, qt.Equals(stub.audience, "svc:eparaksts-signer"))
	qt.Check(t, qt.IsTrue(stub.timeout >= 60*time.Second))
	qt.Check(t, qt.IsTrue(strings.HasSuffix(stub.url, "/api/v1/validations")))

	// The abuse-evidence event landed with the verdict + session evidence.
	select {
	case <-events.done:
	case <-time.After(3 * time.Second):
		t.Fatal("no evidence event posted")
	}
	events.mu.Lock()
	defer events.mu.Unlock()
	qt.Assert(t, qt.Equals(len(events.events), 1))
	var ev audit.VerifyEvent
	qt.Assert(t, qt.IsNil(json.Unmarshal(events.events[0], &ev)))
	qt.Check(t, qt.Equals(ev.Verdict, "PASSED"))
	qt.Check(t, qt.Equals(ev.SessionID, "sess-42"))
	qt.Check(t, qt.Not(qt.Equals(ev.SHA256, "")))
	qt.Check(t, qt.Equals(ev.SizeBytes, int64(len(signedSamplePDF()))))
}

func TestVerifyUnsignedPDFRejected(t *testing.T) {
	stub := &verifyStubDoer{status: 200, body: []byte(sampleV2Report)}
	app := verifyTestApp(t, stub, nil)
	app.Start(t)
	defer app.Stop()

	resp := postVerify(t, app, "plain.pdf", samplePDF())
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Body()), "err:verify:notSigned")))
	// Nothing was forwarded upstream.
	qt.Check(t, qt.Equals(stub.calls, 0))
}

func TestVerifyGarbageRejectedTyped(t *testing.T) {
	stub := &verifyStubDoer{status: 200}
	app := verifyTestApp(t, stub, nil)
	app.Start(t)
	defer app.Stop()

	resp := postVerify(t, app, "junk.bin", []byte{0xde, 0xad, 0xbe, 0xef})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Body()), "err:verify:unsupportedType")))
	qt.Check(t, qt.Equals(stub.calls, 0))
}

func TestVerifyTooLargeRejectedBeforeUpstream(t *testing.T) {
	stub := &verifyStubDoer{status: 200}
	t.Setenv("VERIFY_MAX_BYTES", "64")
	app := verifyTestApp(t, stub, nil)
	app.Start(t)
	defer app.Stop()

	resp := postVerify(t, app, "big.pdf", bytes.Repeat([]byte("A"), 200))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Body()), "err:verify:fileTooLarge")))
	qt.Check(t, qt.Equals(stub.calls, 0))
}

func TestVerifyMissingFilePart(t *testing.T) {
	app := verifyTestApp(t, &verifyStubDoer{status: 200}, nil)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.PostForm("/api/portal/v1/verify", map[string]any{"note": "no file"})
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestVerifyUpstreamFailureIs502(t *testing.T) {
	stub := &verifyStubDoer{err: fmt.Errorf("boom: connection refused")}
	app := verifyTestApp(t, stub, nil)
	app.Start(t)
	defer app.Stop()

	resp := postVerify(t, app, "signed.pdf", signedSamplePDF())
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
}

func TestVerifyUpstreamSemantic4xxIs422(t *testing.T) {
	stub := &verifyStubDoer{status: 400, body: []byte(`{"error":{"code":"BSS-002","message":"Document format not recognized"}}`)}
	app := verifyTestApp(t, stub, nil)
	app.Start(t)
	defer app.Stop()

	resp := postVerify(t, app, "signed.pdf", signedSamplePDF())
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Body()), "err:verify:notValidatable")))
}

func TestVerifyRateLimited(t *testing.T) {
	stub := &verifyStubDoer{status: 200, body: []byte(sampleV2Report)}

	t.Setenv("VERIFY_RATE_PER_MINUTE", "1")
	t.Setenv("VERIFY_RATE_BURST", "1")

	app := api.TestApp(t)
	app.SetVerify(clients.NewVerify(stub, "http://signer:8080", "svc:eparaksts-signer"))
	err := Init(app)
	qt.Assert(t, qt.IsNil(err))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	resp := postVerify(t, ta, "signed.pdf", signedSamplePDF())
	first := resp.StatusCode()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(first, fasthttp.StatusOK))

	resp = postVerify(t, ta, "signed.pdf", signedSamplePDF())
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusTooManyRequests))
}

func TestVerifyNotConfiguredIs503(t *testing.T) {
	app := api.TestApp(t)
	err := Init(app)
	qt.Assert(t, qt.IsNil(err))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	resp := postVerify(t, ta, "signed.pdf", signedSamplePDF())
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
}
