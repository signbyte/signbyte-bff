package asclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestAuthorizeURLAlwaysForcesLogin proves every authorization redirect carries
// prompt=login — dropping it would let a live IdP SSO session silently answer with
// a different login method than the one requested, which then permits the wrong
// signing flows.
func TestAuthorizeURLAlwaysForcesLogin(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	raw := c.AuthorizeURL("chal-1", "state-1", "")
	u, err := url.Parse(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Scheme+"://"+u.Host, "https://public"))
	qt.Check(t, qt.Equals(u.Path, "/authorize"))

	q := u.Query()
	qt.Check(t, qt.Equals(q.Get("client_id"), "client-1"))
	qt.Check(t, qt.Equals(q.Get("response_type"), "code"))
	qt.Check(t, qt.Equals(q.Get("code_challenge"), "chal-1"))
	qt.Check(t, qt.Equals(q.Get("code_challenge_method"), "S256"))
	qt.Check(t, qt.Equals(q.Get("redirect_uri"), "https://app/callback"))
	qt.Check(t, qt.Equals(q.Get("state"), "state-1"))
	qt.Check(t, qt.Equals(q.Get("prompt"), "login"))
	qt.Check(t, qt.Equals(q.Get("acr_values"), ""))
}

// TestAuthorizeURLIncludesACRValuesWhenRequested proves a requested login method
// rides along as acr_values, and is omitted entirely when not requested (rather
// than sent empty).
func TestAuthorizeURLIncludesACRValuesWhenRequested(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	u, err := url.Parse(c.AuthorizeURL("chal-1", "state-1", "eidScan"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Query().Get("acr_values"), "eidScan"))

	u, err = url.Parse(c.AuthorizeURL("chal-1", "state-1", ""))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(u.Query().Has("acr_values")))
}

// TestLogoutURLIncludesSidOnlyWhenPresent proves the front-channel logout redirect
// carries the upstream session handle when known, and omits it (rather than
// sending it empty) for a non-federated login with no upstream session.
func TestLogoutURLIncludesSidOnlyWhenPresent(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	u, err := url.Parse(c.LogoutURL("https://app/login", "refresh-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(u.Path, "/logout"))
	qt.Check(t, qt.Equals(u.Query().Get("client_id"), "client-1"))
	qt.Check(t, qt.Equals(u.Query().Get("redirect_uri"), "https://app/login"))
	qt.Check(t, qt.Equals(u.Query().Get("sid"), "refresh-1"))

	u, err = url.Parse(c.LogoutURL("https://app/login", ""))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(u.Query().Has("sid")))
}

func TestSubjectFromToken(t *testing.T) {
	qt.Check(t, qt.Equals(SubjectFromToken(jwtWith(map[string]any{"sub": "user-1"})), "user-1"))
	qt.Check(t, qt.Equals(SubjectFromToken(jwtWith(map[string]any{})), ""))
	qt.Check(t, qt.Equals(SubjectFromToken("not-a-jwt"), ""))
	qt.Check(t, qt.Equals(SubjectFromToken(""), ""))
}

func TestSerialFromToken(t *testing.T) {
	qt.Check(t, qt.Equals(SerialFromToken(jwtWith(map[string]any{"serial_number": "PNOLV-12345"})), "PNOLV-12345"))
	qt.Check(t, qt.Equals(SerialFromToken(jwtWith(map[string]any{"sub": "user-1"})), ""))
	qt.Check(t, qt.Equals(SerialFromToken("not-a-jwt"), ""))
}

// TestPKCEChallengeMatchesVerifier proves the returned challenge is the S256
// (base64url, unpadded) digest of the verifier, per RFC 7636 — a mismatch here
// would make every login fail at the Auth Service's PKCE check.
func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	verifier, challenge, err := PKCE()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(verifier != ""))

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	qt.Check(t, qt.Equals(challenge, want))

	// Two calls never reuse a verifier.
	verifier2, _, err := PKCE()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(verifier != verifier2))
}

func TestRandomTokenIsURLSafeAndUnique(t *testing.T) {
	a, err := RandomToken(32)
	qt.Assert(t, qt.IsNil(err))
	b, err := RandomToken(32)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.IsTrue(a != ""))
	qt.Check(t, qt.IsTrue(a != b))

	// Round-trips through the URL-safe, unpadded alphabet raw base64.RawURLEncoding produces.
	_, err = base64.RawURLEncoding.DecodeString(a)
	qt.Check(t, qt.IsNil(err))
}

func TestErrorMessageCarriesStatus(t *testing.T) {
	e := &Error{Status: 409, Body: `{"code":"conflict"}`}
	qt.Check(t, qt.Equals(e.Error(), "auth service responded 409"))
}

func TestGenerateKeyProducesUsableECDSAKey(t *testing.T) {
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(key))

	// Usable for signing, the purpose it is generated for.
	digest := sha256.Sum256([]byte("test"))
	sig, err := key.Sign(rand.Reader, digest[:], nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(len(sig) > 0))
}
