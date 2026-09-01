package asclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gmb-lib/go-platform-kit/propagation"
	"github.com/go-quicktest/qt"
)

// TestOutboundCarriesCorrelationID proves both Auth Service call paths — the plain
// card-login hop and the proof-carrying token/identity hop — forward the
// correlation id from the request context, so the login/token exchange is joinable
// to the originating request in the logs. It also proves the header is omitted
// entirely (not sent empty) when the context carries no id. The channel gives a
// happens-before between the handler and the assertions so the test is race-clean.
func TestOutboundCarriesCorrelationID(t *testing.T) {
	corrCh := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Header.Values canonicalizes the key; a direct map lookup would miss,
		// since the canonical form of "X-Correlation-ID" is "X-Correlation-Id".
		if vals := r.Header.Values(propagation.HeaderCorrelationID); len(vals) > 0 {
			corrCh <- vals[0]
		} else {
			corrCh <- "<absent>"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"n","state":"s","sub":"u1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.URL, "client-1", "https://app/callback")

	// plainDo path (card-login challenge) forwards the id on the context.
	ctx := propagation.WithCorrelationID(context.Background(), "corr-xyz")
	_, _, err := c.WebEIDChallenge(ctx, "chal", "state")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(<-corrCh, "corr-xyz"))

	// dpopDo path (identity, proof of possession) forwards it too.
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	_, err = c.Identity(ctx, key, "access-token")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(<-corrCh, "corr-xyz"))

	// No id on the context → the header is omitted, never sent empty.
	_, _, err = c.WebEIDChallenge(context.Background(), "chal", "state")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(<-corrCh, "<absent>"))
}
