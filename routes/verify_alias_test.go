package routes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unsafe"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/audit"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-platform-kit/propagation"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The abuse-evidence event is posted from a goroutine after the request has
// ended, and the caller's address, user agent and correlation id are read off
// the request's buffer, which the server reuses for the next request on the
// connection. The event must still name this request's caller.
func TestVerifyEvidenceKeepsItsOwnCopyOfTheRequestsValues(t *testing.T) {
	events := &verifyEventsDoer{done: make(chan struct{}, 1)}
	release := make(chan struct{})
	// The delivery waits here until the request's buffers have been reused.
	bg := func() context.Context {
		<-release

		return context.Background()
	}

	a := api.TestApp(t)
	a.SetVerifyAudit(audit.NewVerifyRecorder(events, "http://access-audit:8080", "svc:access-audit", bg, nil))
	r := &router{App: a}

	reused := 0

	app := azugo.NewTestApp(a.App)
	app.Get("/probe", func(ctx *azugo.Context) {
		corr := []byte("corr-1")
		ctx.SetUserValue(propagation.RequestValueName(), unsafe.String(&corr[0], len(corr))) //nolint:gosec // the aliasing a request read makes, on purpose

		r.recordVerify(ctx, verifyClientIP(ctx), 42, "abc123", "PASSED", "sess-1")

		// As the next request on the connection would.
		for _, h := range []string{"X-Forwarded-For", "User-Agent"} {
			buf := ctx.Request().Header.Peek(h)
			copy(buf, strings.Repeat("x", len(buf)))
			reused += len(buf)
		}
		copy(corr, strings.Repeat("x", len(corr)))
		close(release)

		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)

	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Get("/probe",
		tc.WithHeader("X-Forwarded-For", "192.0.2.7, 10.0.0.1"),
		tc.WithHeader("User-Agent", "agent-1"),
	)
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(reused, len("192.0.2.7, 10.0.0.1")+len("agent-1")))

	select {
	case <-events.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the evidence event was never posted")
	}

	events.mu.Lock()
	defer events.mu.Unlock()
	qt.Assert(t, qt.Equals(len(events.events), 1))

	var ev audit.VerifyEvent
	qt.Assert(t, qt.IsNil(json.Unmarshal(events.events[0], &ev)))
	qt.Check(t, qt.Equals(ev.IP, "192.0.2.7"))
	qt.Check(t, qt.Equals(ev.UserAgent, "agent-1"))
	qt.Check(t, qt.Equals(ev.CorrelationID, "corr-1"))
}
