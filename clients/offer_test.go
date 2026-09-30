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

// offerStub answers the signing service's info read and records the call.
type offerStub struct {
	status   int
	body     string
	err      error
	calls    int
	method   string
	url      string
	audience string
	scope    string
	timeout  time.Duration
}

func (s *offerStub) DoServiceWithTimeout(_ context.Context, timeout time.Duration, audience, scope, method, fullURL string, _ http.Header, _ []byte) (*authclient.BackgroundResponse, error) {
	s.calls++
	s.timeout, s.audience, s.scope, s.method, s.url = timeout, audience, scope, method, fullURL
	if s.err != nil {
		return nil, s.err
	}

	return &authclient.BackgroundResponse{StatusCode: s.status, Body: []byte(s.body)}, nil
}

// The read asks the signing service's info endpoint with this service's own
// identity and the read scope, and returns the flow names in its order.
func TestOfferReadsTheSigningServicesFlows(t *testing.T) {
	stub := &offerStub{status: http.StatusOK, body: `{"flows":[{"name":"webEid"},{"name":"eidScan"},{"name":"cscEidScan"}]}`}
	flows, err := NewOffer(stub, "http://signer:8080/", "svc:eparaksts-signer").Flows(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(flows, []string{"webEid", "eidScan", "cscEidScan"}))
	qt.Check(t, qt.Equals(stub.method, http.MethodGet))
	qt.Check(t, qt.Equals(stub.url, "http://signer:8080/api/v1/info"))
	qt.Check(t, qt.Equals(stub.audience, "svc:eparaksts-signer"))
	qt.Check(t, qt.Equals(stub.scope, "signatures:read"))
	qt.Check(t, qt.Equals(stub.timeout, offerCallTimeout))
}

// A refusal or an unreadable answer is an error, never an empty offer.
func TestOfferRefusalIsAnError(t *testing.T) {
	_, err := NewOffer(&offerStub{status: http.StatusForbidden, body: `{}`}, "http://signer", "svc:x").Flows(context.Background())
	var he *HTTPError
	qt.Assert(t, qt.IsTrue(errors.As(err, &he)))
	qt.Check(t, qt.Equals(he.StatusCode, http.StatusForbidden))

	flows, err := NewOffer(&offerStub{status: http.StatusOK, body: `not json`}, "http://signer", "svc:x").Flows(context.Background())
	qt.Check(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsNil(flows))
}

// fixedClock is a clock tests move by hand.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time { return c.t }

func newTestOffered(src FlowSource) (*OfferedFlows, *fixedClock) {
	clock := &fixedClock{t: time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)}
	o := NewOfferedFlows(src, time.Minute)
	o.now = clock.now

	return o, clock
}

// An answer is reused for the ttl, then asked again.
func TestOfferedFlowsAsksOncePerTTL(t *testing.T) {
	stub := &offerStub{status: http.StatusOK, body: `{"flows":[{"name":"webEid"}]}`}
	o, clock := newTestOffered(NewOffer(stub, "http://signer", "svc:x"))

	for range 3 {
		flows, err := o.Get(context.Background())
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(flows, []string{"webEid"}))
	}
	qt.Check(t, qt.Equals(stub.calls, 1))

	clock.t = clock.t.Add(time.Minute)
	stub.body = `{"flows":[{"name":"webEid"},{"name":"cscEidPlugin"}]}`
	flows, err := o.Get(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(flows, []string{"webEid", "cscEidPlugin"}))
	qt.Check(t, qt.Equals(stub.calls, 2))
}

// A failed refresh keeps the last answer, says it is stale, and is not retried
// before the ttl passes again — an unreachable signing service costs one timeout
// per ttl, not one per page load.
func TestOfferedFlowsKeepsTheLastAnswerWhenARefreshFails(t *testing.T) {
	stub := &offerStub{status: http.StatusOK, body: `{"flows":[{"name":"webEid"}]}`}
	o, clock := newTestOffered(NewOffer(stub, "http://signer", "svc:x"))
	_, err := o.Get(context.Background())
	qt.Assert(t, qt.IsNil(err))

	clock.t = clock.t.Add(2 * time.Minute)
	stub.err = errors.New("connection refused")
	flows, err := o.Get(context.Background())
	qt.Check(t, qt.ErrorIs(err, ErrOfferStale))
	qt.Check(t, qt.DeepEquals(flows, []string{"webEid"}))

	clock.t = clock.t.Add(30 * time.Second)
	flows, err = o.Get(context.Background())
	qt.Check(t, qt.ErrorIs(err, ErrOfferStale))
	qt.Check(t, qt.DeepEquals(flows, []string{"webEid"}))
	qt.Check(t, qt.Equals(stub.calls, 2)) // the failure was remembered, not retried
}

// With no answer ever, there is nothing to narrow by: nil and the error, and the
// failure is remembered for the ttl too.
func TestOfferedFlowsWithNoAnswerYet(t *testing.T) {
	stub := &offerStub{err: errors.New("connection refused")}
	o, clock := newTestOffered(NewOffer(stub, "http://signer", "svc:x"))
	flows, err := o.Get(context.Background())
	qt.Check(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsFalse(errors.Is(err, ErrOfferStale)))
	qt.Check(t, qt.IsNil(flows))

	_, _ = o.Get(context.Background())
	qt.Check(t, qt.Equals(stub.calls, 1))

	clock.t = clock.t.Add(time.Minute)
	stub.err, stub.status, stub.body = nil, http.StatusOK, `{"flows":[{"name":"eidScan"}]}`
	flows, err = o.Get(context.Background())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(flows, []string{"eidScan"}))
}
