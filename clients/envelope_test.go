package clients

import (
	"context"
	"net/http"
	"testing"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-quicktest/qt"
)

func TestEnvelopeCreateWriteScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body:       []byte(`{"id":"env-1","status":"draft","version":1,"slotIds":["s-1"]}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.Create(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, CreateInput{
		Title: "Q3 contract", OrderPolicy: "sequential",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.ID, "env-1"))
	qt.Assert(t, qt.Equals(out.Status, "draft"))
	qt.Assert(t, qt.Equals(d.lastSub, "user-1"))
	qt.Assert(t, qt.Equals(d.lastAudience, "svc:envelope"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvWrite))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes"))
}

func TestEnvelopeListReadScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"envelopes":[{"id":"env-1","status":"draft","version":1}],"nextCursor":"c2"}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.List(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, 25, "c1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(out.Envelopes), 1))
	qt.Assert(t, qt.Equals(out.NextCursor, "c2"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvRead))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodGet))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes?limit=25&cursor=c1"))
}

func TestEnvelopeSigningTasksReadScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body: []byte(`{"tasks":[{"envelope":{"id":"env-1","title":"contract","status":"sent","orderPolicy":"parallel","version":2},` +
			`"slotId":"s-2","orderIndex":2,"slotStatus":"sent","slotFlow":"eparakstsMobile","yourTurn":true}],"nextCursor":"c2"}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.SigningTasks(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, 25, "c1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(out.Tasks), 1))
	qt.Assert(t, qt.Equals(out.Tasks[0].Envelope.ID, "env-1"))
	qt.Assert(t, qt.Equals(out.Tasks[0].SlotID, "s-2"))
	qt.Assert(t, qt.IsTrue(out.Tasks[0].YourTurn))
	qt.Assert(t, qt.Equals(out.NextCursor, "c2"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvRead))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodGet))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/signing-tasks?limit=25&cursor=c1"))
}

func TestEnvelopeGetReturnsNestedView(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body: []byte(`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","orderPolicy":"sequential","version":2},` +
			`"slots":[{"id":"s-1","orderIndex":0,"role":"signer","flow":"eparakstsMobile","requiredLoa":"high","status":"pending","jobId":"job-1","signatureId":"sig-1"}],` +
			`"documents":[{"documentId":"doc-1","contentHash":"abc"}]}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.Get(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.Envelope.ID, "env-1"))
	qt.Assert(t, qt.Equals(out.Envelope.Status, "sent"))
	qt.Assert(t, qt.Equals(len(out.Slots), 1))
	qt.Assert(t, qt.Equals(out.Slots[0].JobID, "job-1"))
	qt.Assert(t, qt.Equals(out.Documents[0].DocumentID, "doc-1"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvRead))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1"))
}

func TestEnvelopeAttachDocumentWriteScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body:       []byte(`{"envelopeId":"env-1","documentId":"doc-1","contentHash":"abc"}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.AttachDocument(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1", "doc-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.DocumentID, "doc-1"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvWrite))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/documents"))
}

func TestEnvelopeAddSlotWriteScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 201,
		Body:       []byte(`{"id":"s-2"}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	id, err := env.AddSlot(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1", SlotInput{OrderIndex: 1, Role: "signer"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, "s-2"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvWrite))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/slots"))
}

func TestEnvelopeSendTransitionScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"id":"env-1","status":"sent","version":2}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.Send(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.Status, "sent"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvTransition))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/send"))
}

func TestEnvelopeCancelTransitionScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"id":"env-1","status":"cancelled","version":3}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.Cancel(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.Status, "cancelled"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvTransition))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/cancel"))
}

func TestEnvelopeSlotEligibleReadScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"eligible":true}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	ok, err := env.SlotEligible(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1", "s-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvRead))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodGet))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/slots/s-1/eligible"))
}

func TestEnvelopeSetSlotJobTransitionScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"id":"s-1","jobId":"job-1"}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	err := env.SetSlotJob(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1", "s-1", "job-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvTransition))
	qt.Assert(t, qt.Equals(d.lastMethod, http.MethodPost))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/slots/s-1/job"))
}

func TestEnvelopeDeclineSlotTransitionScope(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{
		StatusCode: 200,
		Body:       []byte(`{"id":"s-1","status":"declined"}`),
	}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	out, err := env.DeclineSlot(context.Background(), OnBehalf{Sub: "user-1", Token: "tok"}, "env-1", "s-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.Status, "declined"))
	qt.Assert(t, qt.Equals(d.lastScope, scopeEnvTransition))
	qt.Assert(t, qt.Equals(d.lastURL, "http://envelope:8080/api/v1/envelopes/env-1/slots/s-1/decline"))
}

// TestEnvelopeFailsClosedWithoutToken proves an envelope call with no subject
// token never reaches the envelope service.
func TestEnvelopeFailsClosedWithoutToken(t *testing.T) {
	d := &stubDoer{resp: &authclient.BackgroundResponse{StatusCode: 201}}
	env := NewEnvelope(d, "http://envelope:8080", "svc:envelope")

	_, err := env.Create(context.Background(), OnBehalf{Sub: "user-1", Token: ""}, CreateInput{Title: "x"})
	qt.Assert(t, qt.IsTrue(err != nil))
	qt.Assert(t, qt.Equals(d.lastMethod, "")) // doer never called
}
