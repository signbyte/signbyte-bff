package session

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/go-quicktest/qt"
)

// A session id read from the request (the session cookie) points into a buffer
// the server reuses for the next request. A token refresh stores the session
// again under the id it is given, so the store must keep a copy of its own, or
// the held session is filed under whatever the buffer holds next.
func TestMemoryRefreshKeepsItsOwnCopyOfTheSessionID(t *testing.T) {
	store := NewMemory(time.Hour, time.Minute)
	ctx := context.Background()
	qt.Assert(t, qt.IsNil(store.PutSession(ctx, "sid-1", &Session{AccessToken: "held"})))

	buf := []byte("sid-1")
	fromTheRequest := unsafe.String(&buf[0], len(buf)) //nolint:gosec // the aliasing a request read makes, on purpose
	qt.Assert(t, qt.IsNil(store.PutSession(ctx, fromTheRequest, &Session{AccessToken: "refreshed"})))

	copy(buf, "sid-2") // the next request reuses the buffer

	got, err := store.GetSession(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.AccessToken, "refreshed"))
}

// The same holds for a flow's state, the key its callback looks it up by.
func TestMemoryFlowKeepsItsOwnCopyOfTheState(t *testing.T) {
	store := NewMemory(time.Hour, time.Minute)
	ctx := context.Background()

	buf := []byte("state-1")
	fromTheRequest := unsafe.String(&buf[0], len(buf)) //nolint:gosec // the aliasing a request read makes, on purpose
	qt.Assert(t, qt.IsNil(store.PutFlow(ctx, fromTheRequest, &Flow{Verifier: "v-1"})))

	copy(buf, "state-2") // the next request reuses the buffer

	got, err := store.TakeFlow(ctx, "state-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Verifier, "v-1"))
}
