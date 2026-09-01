// Package session is the Portal-API server-side session store: it maps a browser
// session cookie to the login state the browser must never see — the per-session
// signing-bound key and the access/refresh tokens — plus the short-lived state of
// a login in progress. A Redis-backed implementation is used in production; an
// in-memory implementation serves development and tests.
package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// ErrNotFound is returned when a session or login flow is absent or expired.
var ErrNotFound = errors.New("session: not found")

// Flow is the state of a login (or session elevation) in progress, held between
// the authorization redirect and the callback and correlated by the opaque state
// value. It carries the freshly generated signing-bound key and the proof-of-key
// verifier the callback needs to complete the token exchange.
type Flow struct {
	// Key is the per-session signing-bound private key (serialized), generated at
	// login start and carried into the session so the issued tokens stay bound to it.
	Key string `json:"key"`
	// Verifier is the proof-of-key-exchange secret the callback presents to the Auth
	// Service to redeem the authorization code.
	Verifier string `json:"verifier"`
	// SessionID, when set, marks an elevation of an existing session rather than a
	// fresh login: the callback updates that session's tokens in place.
	SessionID string `json:"session_id,omitempty"`
}

// Session is a logged-in browser session held server-side. The cookie carries
// only the opaque id that maps here.
type Session struct {
	// Key is the signing-bound private key (serialized) the access/refresh tokens
	// are bound to; every server-side call to the Auth Service proves possession of
	// it.
	Key string `json:"key"`
	// AccessToken is the current user access token; AccessExpiry is its expiry in
	// Unix seconds, so the store can refresh it before use.
	AccessToken  string `json:"access_token"`
	AccessExpiry int64  `json:"access_expiry"`
	// RefreshToken re-issues the access token within the session; it is also the
	// upstream session handle used for step-up.
	RefreshToken string `json:"refresh_token"`
	// Subject is the logged-in person's stable identifier.
	Subject string `json:"subject"`
	// CSRF is the per-session token the browser must echo on every state-changing
	// request, defending the cookie session against cross-site request forgery.
	CSRF string `json:"csrf"`
	// SigningAuthCert is the card authentication certificate captured at eID-card
	// login (the login token's unverifiedCertificate), reused as the finalize auth
	// certificate when signing so the card is not authenticated a second time at
	// signing. A public certificate, session-scoped (gone on logout/expiry); empty
	// for non-card logins.
	SigningAuthCert string `json:"signing_auth_cert,omitempty"`
	// Capabilities is the signing-capability set the auth service captured at
	// login and returned on the code exchange: the signing identity this login
	// method uses, its certificate, the auth certificate, and the person's
	// seals. Threaded into signing requests so a signing act skips its own
	// identity resolution; absent means "unknown" and signing resolves
	// identities itself. Certificates carry personal data — session-scoped,
	// never logged, gone on logout/expiry.
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// Capabilities mirrors the auth service's login-captured signing-capability
// set (see the asclient wire type); stored on the session verbatim.
type Capabilities struct {
	SignIdentityID     string `json:"sign_identity_id,omitempty"`
	SigningCertificate string `json:"signing_certificate,omitempty"`
	AuthCertificate    string `json:"auth_certificate,omitempty"`
	Seals              []Seal `json:"seals,omitempty"`
	// SealsKnown says the seal list is authoritative: an empty list then means
	// the person verifiably holds no seals rather than "unknown".
	SealsKnown bool `json:"seals_known,omitempty"`
}

// Seal is one organisation seal: id, picker display label, certificate.
type Seal struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Certificate string `json:"certificate,omitempty"`
}

// Store persists login flows and sessions with a bounded lifetime.
type Store interface {
	// PutFlow stores a login flow under the opaque state value, with the flow TTL.
	PutFlow(ctx context.Context, state string, f *Flow) error
	// TakeFlow atomically returns and removes the flow for state (single use).
	// Returns ErrNotFound if absent or expired.
	TakeFlow(ctx context.Context, state string) (*Flow, error)

	// PutSession stores (or replaces) a session under its id, with the session TTL.
	PutSession(ctx context.Context, id string, s *Session) error
	// GetSession returns the session for id, or ErrNotFound if absent or expired.
	GetSession(ctx context.Context, id string) (*Session, error)
	// DeleteSession removes the session for id (logout). Absent is not an error.
	DeleteSession(ctx context.Context, id string) error

	// Ping reports whether the backend is reachable.
	Ping(ctx context.Context) error
}

// MarshalKey serializes a signing-bound private key for storage.
func MarshalKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(der), nil
}

// ParseKey restores a signing-bound private key from its stored form.
func ParseKey(s string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("session: stored key is not an ECDSA private key")
	}

	return key, nil
}
