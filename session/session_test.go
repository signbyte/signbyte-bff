package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestMarshalParseKeyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	s, err := MarshalKey(key)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(s != ""))

	parsed, err := ParseKey(s)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(key.Equal(parsed)))
}

func TestParseKeyRejectsGarbage(t *testing.T) {
	// Not valid base64.
	_, err := ParseKey("not-base64!!!")
	qt.Check(t, qt.IsNotNil(err))

	// Valid base64, but not a PKCS8 DER-encoded key.
	_, err = ParseKey("aGVsbG8gd29ybGQ=")
	qt.Check(t, qt.IsNotNil(err))
}

func TestParseKeyRejectsNonECDSAKey(t *testing.T) {
	// A validly PKCS8-DER-encoded key of a non-ECDSA type must still be rejected;
	// Ed25519 is the simplest such key to generate without pulling in RSA.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	qt.Assert(t, qt.IsNil(err))

	_, err = ParseKey(base64.StdEncoding.EncodeToString(der))
	qt.Check(t, qt.IsNotNil(err))
}

func TestMemorySessionRoundTrip(t *testing.T) {
	store := NewMemory(time.Hour, time.Minute)
	ctx := context.Background()

	_, err := store.GetSession(ctx, "unknown")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	sess := &Session{Subject: "user-1", AccessToken: "tok", CSRF: "csrf-1"}
	qt.Assert(t, qt.IsNil(store.PutSession(ctx, "sid-1", sess)))

	got, err := store.GetSession(ctx, "sid-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.Subject, "user-1"))
	qt.Check(t, qt.Equals(got.AccessToken, "tok"))
	qt.Check(t, qt.Equals(got.CSRF, "csrf-1"))

	qt.Assert(t, qt.IsNil(store.DeleteSession(ctx, "sid-1")))
	_, err = store.GetSession(ctx, "sid-1")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	// Deleting an already-absent session is not an error.
	qt.Check(t, qt.IsNil(store.DeleteSession(ctx, "sid-1")))
}

func TestMemorySessionExpires(t *testing.T) {
	ms := NewMemory(time.Minute, time.Minute).(*memoryStore)
	now := time.Now()
	ms.now = func() time.Time { return now }

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(ms.PutSession(ctx, "sid-1", &Session{Subject: "user-1"})))

	// Just before expiry, still readable.
	ms.now = func() time.Time { return now.Add(59 * time.Second) }
	_, err := ms.GetSession(ctx, "sid-1")
	qt.Check(t, qt.IsNil(err))

	// Past the TTL, gone.
	ms.now = func() time.Time { return now.Add(61 * time.Second) }
	_, err = ms.GetSession(ctx, "sid-1")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryFlowSingleUseAndExpiry(t *testing.T) {
	ms := NewMemory(time.Hour, time.Minute).(*memoryStore)
	now := time.Now()
	ms.now = func() time.Time { return now }

	ctx := context.Background()
	qt.Assert(t, qt.IsNil(ms.PutFlow(ctx, "state-1", &Flow{Key: "k", Verifier: "v"})))

	// TakeFlow returns the flow once...
	f, err := ms.TakeFlow(ctx, "state-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(f.Key, "k"))
	qt.Check(t, qt.Equals(f.Verifier, "v"))

	// ...and is single-use: a second take finds nothing.
	_, err = ms.TakeFlow(ctx, "state-1")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	// A flow past its TTL is treated as absent, even though take also removes it.
	qt.Assert(t, qt.IsNil(ms.PutFlow(ctx, "state-2", &Flow{Key: "k2"})))
	ms.now = func() time.Time { return now.Add(2 * time.Hour) }
	_, err = ms.TakeFlow(ctx, "state-2")
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryStorePing(t *testing.T) {
	store := NewMemory(time.Hour, time.Minute)
	qt.Check(t, qt.IsNil(store.Ping(context.Background())))
}
