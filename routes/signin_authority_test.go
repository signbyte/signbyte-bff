package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/session"
)

// signInAuthority stands in for the Auth Service a sign-in talks to: it answers
// the code exchange with an ID token signed by a key it publishes, the card
// challenge and the card login, and counts what reached it. The real client
// drives it, so what it checks is what the edge checks.
//
// Each code names the sign-in it answers ("code-" + its state), as a real
// authority ties a code to its request, so two sign-ins in flight each get their
// own ID token.
type signInAuthority struct {
	key *ecdsa.PrivateKey

	mu         sync.Mutex
	signIns    map[string]session.Flow // by state
	authOffset time.Duration           // auth_time = the sign-in's start + authOffset
	noAuthTime bool
	tokens     int
	cardLogins int
	challenges int
}

// signInApp starts the BFF against a fresh stand-in authority, which learns each
// sign-in as the BFF parks it.
func signInApp(t *testing.T) (*api.App, *azugo.TestApp, *signInAuthority) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	a := &signInAuthority{key: key, signIns: map[string]session.Flow{}}

	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","login_method":"eparakstsMobile"}`))
	accessToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + claims + ".sig"

	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			_, _ = w.Write(a.jwks())
		case "/token":
			_ = r.ParseForm()
			a.tokens++
			body, _ := json.Marshal(map[string]any{
				"access_token": accessToken, "token_type": "DPoP", "expires_in": 300,
				"refresh_token": "refresh-" + strconv.Itoa(a.tokens),
				"id_token":      a.idToken(strings.TrimPrefix(r.PostForm.Get("code"), "code-")),
			})
			_, _ = w.Write(body)
		case "/webeid/challenge":
			a.challenges++
			_, _ = w.Write([]byte(`{"nonce":"card-nonce","state":"card-flow-` + strconv.Itoa(a.challenges) + `"}`))
		case "/webeid/login":
			a.cardLogins++
			var login struct {
				State string `json:"state"`
			}
			_ = json.NewDecoder(r.Body).Decode(&login)
			_, _ = w.Write([]byte(`{"code":"code-` + login.State + `"}`))
		case "/revoke":
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(as.Close)
	t.Setenv("AUTH_INTERNAL_URL", as.URL)

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetSessions(signInsTo{Store: app.Sessions(), authority: a})
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return app, ta, a
}

// counts reads what reached the authority: code exchanges and card logins.
func (a *signInAuthority) counts() (tokens, cardLogins int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.tokens, a.cardLogins
}

// answerAuthenticatedAt makes the ID tokens that follow name an authentication
// offset from the sign-in's start, or, with without, name none at all.
func (a *signInAuthority) answerAuthenticatedAt(offset time.Duration, without bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.authOffset, a.noAuthTime = offset, without
}

// jwks is the authority's published key set.
func (a *signInAuthority) jwks() []byte {
	point, _ := a.key.PublicKey.Bytes() // 0x04 ‖ x ‖ y
	raw, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k-1", "alg": "ES256", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:65]),
	}}})

	return raw
}

// idToken is a compact ES256 ID token for the sign-in parked under state.
func (a *signInAuthority) idToken(state string) string {
	f := a.signIns[state]
	now := time.Now()
	claims := map[string]any{
		"iss": testIssuer, "aud": "portal-spa", "sub": "user-1",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": f.Nonce,
	}
	if f.ACRValues != "" {
		claims["acr"] = strings.Fields(f.ACRValues)[0]
	}
	if !a.noAuthTime {
		at := now
		if !f.Started.IsZero() {
			at = f.Started.Add(a.authOffset)
		}
		claims["auth_time"] = at.Unix()
	}
	part := func(v any) string {
		raw, _ := json.Marshal(v)

		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := part(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k-1"}) + "." + part(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return ""
	}

	return input + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// signInsTo is the BFF's session store, telling the authority about each sign-in
// as it is parked, as the real one learns it from the request. The state is the
// key up to its binding.
type signInsTo struct {
	session.Store
	authority *signInAuthority
}

func (s signInsTo) PutFlow(ctx context.Context, key string, f *session.Flow) error {
	state, _, _ := strings.Cut(key, ".")
	s.authority.mu.Lock()
	s.authority.signIns[state] = *f
	s.authority.mu.Unlock()

	return s.Store.PutFlow(ctx, key, f)
}
