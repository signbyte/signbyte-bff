package routes

import (
	"sync"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
)

// captureSink records every emitted security event so a test can assert on
// exactly what left the service.
type captureSink struct {
	mu     sync.Mutex
	events []*broker.Envelope
}

func (s *captureSink) Emit(_ *azugo.Context, ev *broker.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)

	return nil
}

func (s *captureSink) all() []*broker.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*broker.Envelope(nil), s.events...)
}

// TestCSRFMismatchEmitsSecurityEvent proves the anti-forgery rejection leaves a
// typed authz.denied event naming the session's subject — the one refusal shape
// only this boundary can classify as a cross-site request-forgery signal.
func TestCSRFMismatchEmitsSecurityEvent(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	sink := &captureSink{}
	app.SetSecEvents(secevents.NewEmitter(sink))

	ta := loggedIn(t, app)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/documents/bundle", []byte(`{"sourceIds":["s1"]}`),
		tc.WithCookie("portal_session", "test-sid"),
		tc.WithHeader("X-CSRF-Token", "wrong-token"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)

	events := sink.all()
	qt.Assert(t, qt.Equals(len(events), 1))
	qt.Check(t, qt.Equals(events[0].EventType, secevents.EventAuthZDenied))
	qt.Assert(t, qt.IsNotNil(events[0].Actor))
	qt.Check(t, qt.Equals(events[0].Actor.ID, "user-1"))
	qt.Check(t, qt.Equals(events[0].Actor.Type, "user"))
}

// TestMutationWithTokenEmitsNoSecurityEvent is the control: an authorized
// state-changing call emits nothing, so the event cannot be ambient noise.
func TestMutationWithTokenEmitsNoSecurityEvent(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetDocuments(clients.NewDocuments(
		&stubDoer{status: fasthttp.StatusCreated, body: []byte(`{"id":"cont-1","filename":"a.asice"}`)},
		"http://document:8080", "svc:document",
	))

	sink := &captureSink{}
	app.SetSecEvents(secevents.NewEmitter(sink))

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
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(sink.all()), 0))
}

// TestVerifyRateLimitEmitsEdgeBlock proves a public-verify rate-limit refusal
// leaves a typed edge.block event — and only the refused request leaves one.
func TestVerifyRateLimitEmitsEdgeBlock(t *testing.T) {
	t.Setenv("VERIFY_RATE_PER_MINUTE", "1")
	t.Setenv("VERIFY_RATE_BURST", "1")

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	sink := &captureSink{}
	app.SetSecEvents(secevents.NewEmitter(sink))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()

	// First request consumes the single-token bucket. Its own outcome does not
	// matter here (no signer is configured in-test); it must simply not be 429.
	resp, err := tc.Post("/api/portal/v1/verify", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusTooManyRequests)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(len(sink.all()), 0))

	// Second immediate request is refused for rate — the typed event records it.
	resp, err = tc.Post("/api/portal/v1/verify", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusTooManyRequests))
	fasthttp.ReleaseResponse(resp)

	events := sink.all()
	qt.Assert(t, qt.Equals(len(events), 1))
	qt.Check(t, qt.Equals(events[0].EventType, secevents.EventEdgeBlock))
	qt.Check(t, qt.Equals(events[0].Attributes[secevents.AttrRule], "verify_rate_limit"))
}

// Compile-time proof the capture sink satisfies the emitter's Sink contract.
var _ secevents.Sink = (*captureSink)(nil)
