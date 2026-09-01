package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-quicktest/qt"
)

func TestBeginSigningOnBehalf(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body:       []byte(`{"jobId":"job-1","state":"awaiting_redirect","authorizeUrl":"https://idp/x"}`),
	}}
	sf := NewSignflow(d, "http://signflow:8080", "svc:signflow")

	job, err := sf.BeginSigning(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, BeginInput{
		EnvelopeID: "env-abc", SlotID: "s-1", Flow: "eparakstsMobile", SigFormat: "XAdES", DocumentID: "doc-1",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(job.JobID, "job-1"))
	qt.Assert(t, qt.Equals(job.AuthorizeURL, "https://idp/x"))
	qt.Assert(t, qt.Equals(d.lastSub, "user-1"))
	qt.Assert(t, qt.Equals(d.lastAudience, "svc:signflow"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeSigCreate))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
	qt.Assert(t, qt.Equals(d.lastURL, "http://signflow:8080/api/v1/signings"))
}

// TestOnBehalfBindingScopesCacheKey proves the login binding is folded into the
// subject the delegated-token cache keys on, so the same person logging in with a
// different method gets a distinct cache entry (and never a token bound to the old
// method) — while Sub itself stays the pure subject.
func TestOnBehalfBindingScopesCacheKey(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{StatusCode: 200, Body: []byte(`{}`)}}
	sf := NewSignflow(d, "http://signflow:8080", "svc:signflow")

	_, _ = sf.Status(context.Background(), OnBehalf{Sub: "user-1", Token: "t", Binding: "lm:webEid|loa:high"}, "job-1", 0)
	qt.Check(t, qt.Equals(d.lastSub, "user-1|lm:webEid|loa:high"))

	_, _ = sf.Status(context.Background(), OnBehalf{Sub: "user-1", Token: "t", Binding: "lm:eidScan|loa:high"}, "job-1", 0)
	qt.Check(t, qt.Equals(d.lastSub, "user-1|lm:eidScan|loa:high"))

	// No binding → subject-only key (unchanged behaviour).
	_, _ = sf.Status(context.Background(), OnBehalf{Sub: "user-1", Token: "t"}, "job-1", 0)
	qt.Check(t, qt.Equals(d.lastSub, "user-1"))
}

// TestBeginSigningWebEidRelaysCertsAndParsesDigests proves the in-browser flow in
// both directions: the card certificates are marshalled into the outbound request,
// and the signature algorithm + per-document digests are parsed from the response.
func TestBeginSigningWebEidRelaysCertsAndParsesDigests(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body: []byte(`{"jobId":"job-1","state":"AWAITING_CLIENT_SIGNATURE","signAlgorithm":"RSA_SHA256",` +
			`"documents":[{"documentId":"doc-1","digest":"ZGlnZXN0","digestAlgorithm":"SHA-256"}]}`),
	}}
	sf := NewSignflow(d, "http://signflow:8080", "svc:signflow")

	job, err := sf.BeginSigning(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, BeginInput{
		EnvelopeID: "env-abc", SlotID: "s-1", Flow: "webEid", SigFormat: "XAdES", DocumentID: "doc-1",
		SigningCertificate: "MIIsign", AuthCertificate: "MIIauth",
	})
	qt.Assert(t, qt.IsNil(err))
	// Digests + algorithm parsed from the response.
	qt.Assert(t, qt.Equals(job.SignAlgorithm, "RSA_SHA256"))
	qt.Assert(t, qt.Equals(len(job.Documents), 1))
	qt.Assert(t, qt.Equals(job.Documents[0].Digest, "ZGlnZXN0"))
	qt.Assert(t, qt.Equals(job.Documents[0].DocumentID, "doc-1"))
	// Certificates marshalled into the outbound body.
	var sent BeginInput
	qt.Assert(t, qt.IsNil(json.Unmarshal(d.lastBody, &sent)))
	qt.Assert(t, qt.Equals(sent.SigningCertificate, "MIIsign"))
	qt.Assert(t, qt.Equals(sent.AuthCertificate, "MIIauth"))
}

func TestSigningStatusReadScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"jobId":"job-1","state":"COMPLETED","containerId":"c-1","signatureId":"s-1"}`),
	}}
	sf := NewSignflow(d, "http://signflow:8080", "svc:signflow")

	job, err := sf.Status(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "job-1", 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(job.State, "COMPLETED"))
	qt.Assert(t, qt.Equals(job.SignatureID, "s-1"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeSigRead))
	qt.Assert(t, qt.Equals(d.lastURL, "http://signflow:8080/api/v1/signings/job-1/status"))

	// A positive wait turns the call into a long-poll: the seconds ride through as a
	// query parameter signflow holds the request on.
	_, err = sf.Status(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "job-1", 5)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.lastURL, "http://signflow:8080/api/v1/signings/job-1/status?wait=5"))
}

func TestValidationReadScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"signatureId":"s-1","verdict":"TOTAL-PASSED","pass":true,"format":"XAdES"}`),
	}}
	sf := NewSignflow(d, "http://signflow:8080", "svc:signflow")

	v, err := sf.Validate(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "s-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(v.Pass))
	qt.Assert(t, qt.Equals(v.Verdict, "TOTAL-PASSED"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeSigRead))
}

// TestBeginSigningFailsClosed proves a signing with no subject token never reaches
// the orchestrator.
func TestBeginSigningFailsClosed(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{StatusCode: 201}}
	sf := NewSignflow(d, "http://signflow:8080", "svc:signflow")

	_, err := sf.BeginSigning(context.Background(), OnBehalf{Sub: "user-1", Token: ""}, BeginInput{DocumentID: "doc-1"})
	qt.Assert(t, qt.IsTrue(err != nil))
	qt.Assert(t, qt.Equals(d.lastMethod, "")) // doer never called
}
