package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/signbyte-bff/session"
)

// A sign-in's return carries everything needed to find the sign-in it names, so
// on its own it could be opened in any browser. These tests hold the edge to the
// rule that only the browser that started a sign-in can finish it; a fresh test
// client is another browser, with a cookie jar of its own.

const signInRoutes = "/api/portal/v1/login"

// startSignIn starts a sign-in in client and returns its state.
func startSignIn(t *testing.T, client *azugo.TestClient) string {
	t.Helper()

	resp, err := client.Post(signInRoutes+"/start", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	var out struct {
		State string `json:"state"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))

	return out.State
}

// returnTo opens the return of the sign-in named by state in client, as the
// browser following the Auth Service's redirect does, and answers where the
// browser is sent.
func returnTo(t *testing.T, client *azugo.TestClient, query string, opts ...azugo.TestClientOption) string {
	t.Helper()

	resp, err := client.Get(signInRoutes+"/callback?"+query+"&iss="+url.QueryEscape(testIssuer), opts...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
	loc := string(resp.Header.Peek("Location"))
	fasthttp.ReleaseResponse(resp)

	return loc
}

// codeFor is the code the stand-in authority answers the sign-in under state with.
func codeFor(state string) string { return "code=code-" + state + "&state=" + state }

// signedIn reports whether client holds a session cookie.
func signedIn(client *azugo.TestClient) bool { return client.Cookies()["portal_session"] != "" }

func TestASignInStartBindsTheBrowser(t *testing.T) {
	app, ta, _ := signInApp(t)
	client := ta.TestClient()

	resp, err := client.Post(signInRoutes+"/start", nil)
	qt.Assert(t, qt.IsNil(err))
	set := strings.ToLower(string(resp.Header.PeekCookie(signInCookieName)))
	buf, _ := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	var out struct {
		State string `json:"state"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))

	for _, attr := range []string{"httponly", "samesite=lax", "max-age=600", "path=/"} {
		qt.Check(t, qt.IsTrue(strings.Contains(set, attr)), qt.Commentf("%s in %q", attr, set))
	}
	binding := client.Cookies()[signInCookieName]
	qt.Check(t, qt.Equals(len(binding), 43))

	// The flow is found by the state together with this browser's value, never by
	// the state alone, and what the store is keyed by does not contain the value.
	ctx := context.Background()
	_, err = app.Sessions().TakeFlow(ctx, out.State)
	qt.Check(t, qt.ErrorIs(err, session.ErrNotFound))
	key := session.FlowKey(out.State, binding)
	qt.Check(t, qt.IsFalse(strings.Contains(key, binding)))
	flow, err := app.Sessions().TakeFlow(ctx, key)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(flow.Nonce, "")))
}

func TestASignInFinishesOnceInTheBrowserThatStartedIt(t *testing.T) {
	_, ta, authority := signInApp(t)
	client := ta.TestClient()

	state := startSignIn(t, client)
	qt.Check(t, qt.Equals(returnTo(t, client, codeFor(state)), "http://localhost:8080/"))
	qt.Check(t, qt.IsTrue(signedIn(client)))

	qt.Check(t, qt.IsTrue(strings.Contains(returnTo(t, client, codeFor(state)), "error=expired")))
	tokens, _ := authority.counts()
	qt.Check(t, qt.Equals(tokens, 1))
}

func TestAReturnInAnotherBrowserSignsNobodyIn(t *testing.T) {
	_, ta, authority := signInApp(t)
	starter := ta.TestClient()
	state := startSignIn(t, starter)
	other := ta.TestClient()
	otherState := startSignIn(t, other)

	blank, short := ta.TestClient(), ta.TestClient()
	for _, try := range []struct {
		name   string
		client *azugo.TestClient
		opts   []azugo.TestClientOption
	}{
		{"a browser holding no value", ta.TestClient(), nil},
		{"a browser holding its own sign-in's value", other, nil},
		{"an empty value", blank, []azugo.TestClientOption{blank.WithCookie(signInCookieName, "")}},
		{"a value of the wrong length", short, []azugo.TestClientOption{short.WithCookie(signInCookieName, "short")}},
	} {
		loc := returnTo(t, try.client, codeFor(state), try.opts...)
		qt.Check(t, qt.IsTrue(strings.Contains(loc, "error=expired")), qt.Commentf("%s: %s", try.name, loc))
		qt.Check(t, qt.IsFalse(signedIn(try.client)), qt.Commentf("%s", try.name))
	}
	tokens, _ := authority.counts()
	qt.Check(t, qt.Equals(tokens, 0))

	// Neither browser's own sign-in was touched by the refusals.
	qt.Check(t, qt.Equals(returnTo(t, starter, codeFor(state)), "http://localhost:8080/"))
	qt.Check(t, qt.IsTrue(signedIn(starter)))
	qt.Check(t, qt.Equals(returnTo(t, other, codeFor(otherState)), "http://localhost:8080/"))
	tokens, _ = authority.counts()
	qt.Check(t, qt.Equals(tokens, 2))
}

func TestAProviderErrorEndsNoSignIn(t *testing.T) {
	_, ta, _ := signInApp(t)
	starter := ta.TestClient()
	state := startSignIn(t, starter)

	for _, client := range []*azugo.TestClient{ta.TestClient(), starter} {
		loc := returnTo(t, client, "error=access_denied&state="+state)
		qt.Check(t, qt.IsTrue(strings.Contains(loc, "error=cancelled")), qt.Commentf("%s", loc))
		qt.Check(t, qt.IsFalse(signedIn(client)))
	}

	qt.Check(t, qt.Equals(returnTo(t, starter, codeFor(state)), "http://localhost:8080/"))
}

func TestTwoSignInsInOneBrowserBothFinish(t *testing.T) {
	_, ta, authority := signInApp(t)
	client := ta.TestClient()

	first := startSignIn(t, client)
	binding := client.Cookies()[signInCookieName]
	second := startSignIn(t, client)
	qt.Check(t, qt.Equals(client.Cookies()[signInCookieName], binding))

	qt.Check(t, qt.Equals(returnTo(t, client, codeFor(second)), "http://localhost:8080/"))
	qt.Check(t, qt.Equals(returnTo(t, client, codeFor(first)), "http://localhost:8080/"))
	tokens, _ := authority.counts()
	qt.Check(t, qt.Equals(tokens, 2))
}

// A browser holding a value this service could not have set gets a new one, and
// still signs in: a value is never reused unless it is one of ours.
func TestABrowserHoldingAMalformedValueStillSignsIn(t *testing.T) {
	_, ta, _ := signInApp(t)
	for _, held := range []string{"", "short", "AAAA", strings.Repeat("*", 43)} {
		client := ta.TestClient()
		resp, err := client.Post(signInRoutes+"/start", nil, client.WithCookie(signInCookieName, held))
		qt.Assert(t, qt.IsNil(err))
		buf, _ := resp.BodyUncompressed()
		fasthttp.ReleaseResponse(resp)
		var out struct {
			State string `json:"state"`
		}
		qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))

		binding := client.Cookies()[signInCookieName]
		qt.Check(t, qt.Equals(len(binding), 43), qt.Commentf("held %q", held))
		qt.Check(t, qt.Not(qt.Equals(binding, held)))
		qt.Check(t, qt.Equals(returnTo(t, client, codeFor(out.State)), "http://localhost:8080/"), qt.Commentf("held %q", held))
	}
}

func TestASignInParkedWithoutABindingIsRefused(t *testing.T) {
	app, ta, authority := signInApp(t)
	client := ta.TestClient()
	startSignIn(t, client) // the browser holds a value of its own

	// Parked as an earlier release parked it: under the state alone.
	parkFlow(t, app, "state-earlier", session.Flow{Nonce: "nonce-earlier", Started: time.Now()})

	qt.Check(t, qt.IsTrue(strings.Contains(returnTo(t, client, codeFor("state-earlier")), "error=expired")))
	qt.Check(t, qt.IsFalse(signedIn(client)))
	tokens, _ := authority.counts()
	qt.Check(t, qt.Equals(tokens, 0))
}

func TestAnElevationReturnInAnotherBrowserElevatesNothing(t *testing.T) {
	app, ta, _ := signInApp(t)
	ctx := context.Background()
	const sid = "sid-elevated"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(ctx, sid, &session.Session{
		Subject: "user-1", AccessToken: "old", AccessExpiry: 1 << 62, CSRF: "csrf-1", RefreshToken: "refresh-0",
	})))
	starter := ta.TestClient()
	startSignIn(t, starter)
	parkFlow(t, app, session.FlowKey("state-step-up", starter.Cookies()[signInCookieName]), session.Flow{SessionID: sid})

	stranger := ta.TestClient()
	qt.Check(t, qt.IsTrue(strings.Contains(returnTo(t, stranger, codeFor("state-step-up")), "error=expired")))
	sess, err := app.Sessions().GetSession(ctx, sid)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.RefreshToken, "refresh-0"))

	qt.Check(t, qt.Equals(returnTo(t, starter, codeFor("state-step-up")), "http://localhost:8080/"))
	sess, err = app.Sessions().GetSession(ctx, sid)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sess.RefreshToken, "refresh-1"))
}

// startCardSignIn fetches a card challenge in client and returns the flow's state.
func startCardSignIn(t *testing.T, client *azugo.TestClient) string {
	t.Helper()

	resp, err := client.Post(signInRoutes+"/webeid/start", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	var out struct {
		State string `json:"state"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))

	return out.State
}

// completeCardSignIn posts the card's signed challenge for state in client and
// answers the status and the problem code, if any.
func completeCardSignIn(t *testing.T, client *azugo.TestClient, state string, opts ...azugo.TestClientOption) (int, string) {
	t.Helper()

	resp, err := client.PostJSON(signInRoutes+"/webeid/complete",
		map[string]any{"state": state, "authToken": map[string]string{"format": "web-eid:1.0"}}, opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	buf, _ := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	var problem struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(buf, &problem)

	return status, problem.Code
}

func TestACardSignInFinishesOnlyInTheBrowserThatStartedIt(t *testing.T) {
	_, ta, authority := signInApp(t)
	starter := ta.TestClient()
	state := startCardSignIn(t, starter)
	qt.Check(t, qt.Equals(len(starter.Cookies()[signInCookieName]), 43))

	other := ta.TestClient()
	startCardSignIn(t, other)
	for _, client := range []*azugo.TestClient{ta.TestClient(), other} {
		status, code := completeCardSignIn(t, client, state)
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest))
		qt.Check(t, qt.Equals(code, "err:session:flowExpired"))
		qt.Check(t, qt.IsFalse(signedIn(client)))
	}
	tokens, cardLogins := authority.counts()
	qt.Check(t, qt.Equals(cardLogins, 0))
	qt.Check(t, qt.Equals(tokens, 0))

	status, _ := completeCardSignIn(t, starter, state)
	qt.Check(t, qt.Equals(status, fasthttp.StatusOK))
	qt.Check(t, qt.IsTrue(signedIn(starter)))
}

func TestASignInMustBeAFreshOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offset  time.Duration
		without bool
		ok      bool
	}{
		{"an authentication 31 s before the start", -31 * time.Second, false, false},
		{"an authentication 29 s before the start", -29 * time.Second, false, true},
		{"an authentication at the start", 0, false, true},
		{"an authentication after the start", 5 * time.Second, false, true},
		{"no authentication time", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ta, authority := signInApp(t)
			authority.answerAuthenticatedAt(tc.offset, tc.without)
			client := ta.TestClient()

			state := startSignIn(t, client)
			loc := returnTo(t, client, codeFor(state))
			qt.Check(t, qt.Equals(!strings.Contains(loc, "error="), tc.ok), qt.Commentf("%s", loc))
			qt.Check(t, qt.Equals(signedIn(client), tc.ok))

			card := ta.TestClient()
			status, _ := completeCardSignIn(t, card, startCardSignIn(t, card))
			qt.Check(t, qt.Equals(status == fasthttp.StatusOK, tc.ok), qt.Commentf("card: HTTP %d", status))
			qt.Check(t, qt.Equals(signedIn(card), tc.ok))
		})
	}
}

// signedInUnderAnyName reports whether client holds a session cookie under any name.
func signedInUnderAnyName(client *azugo.TestClient) bool {
	for name, value := range client.Cookies() {
		if strings.HasSuffix(name, sessionCookieName) && value != "" {
			return true
		}
	}

	return false
}

// plantedBindings are a copy of another browser's binding value under a name the
// edge does not read on that lane: __Secure- over TLS, __Host- over plain HTTP in
// development.
func plantedBindings(ta *azugo.TestApp, value string) []struct {
	name   string
	client *azugo.TestClient
	opts   []azugo.TestClientOption
} {
	overTLSClient, plainClient := ta.TestClient(), ta.TestClient()

	return []struct {
		name   string
		client *azugo.TestClient
		opts   []azugo.TestClientOption
	}{
		{"over TLS, a __Secure- copy", overTLSClient,
			[]azugo.TestClientOption{overTLS(overTLSClient), overTLSClient.WithCookie("__Secure-"+signInCookieName, value)}},
		{"over plain HTTP, a __Host- copy", plainClient,
			[]azugo.TestClientOption{plainClient.WithCookie(hostName+signInCookieName, value)}},
	}
}

func TestAPlantedBindingIsNeverRead(t *testing.T) {
	t.Run("the return", func(t *testing.T) {
		_, ta, authority := signInApp(t)
		attacker := ta.TestClient()
		state := startSignIn(t, attacker)

		for _, try := range plantedBindings(ta, attacker.Cookies()[signInCookieName]) {
			loc := returnTo(t, try.client, codeFor(state), try.opts...)
			qt.Check(t, qt.IsTrue(strings.Contains(loc, "error=expired")), qt.Commentf("%s: %s", try.name, loc))
			qt.Check(t, qt.IsFalse(signedInUnderAnyName(try.client)), qt.Commentf("%s", try.name))
		}
		tokens, _ := authority.counts()
		qt.Check(t, qt.Equals(tokens, 0))

		// The attacker's own sign-in was not touched by the refusals.
		qt.Check(t, qt.Equals(returnTo(t, attacker, codeFor(state)), "http://localhost:8080/"))
		qt.Check(t, qt.IsTrue(signedIn(attacker)))
	})

	t.Run("the card completion", func(t *testing.T) {
		_, ta, authority := signInApp(t)
		attacker := ta.TestClient()
		state := startCardSignIn(t, attacker)

		for _, try := range plantedBindings(ta, attacker.Cookies()[signInCookieName]) {
			status, code := completeCardSignIn(t, try.client, state, try.opts...)
			qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("%s", try.name))
			qt.Check(t, qt.Equals(code, "err:session:flowExpired"), qt.Commentf("%s", try.name))
			qt.Check(t, qt.IsFalse(signedInUnderAnyName(try.client)), qt.Commentf("%s", try.name))
		}
		_, cardLogins := authority.counts()
		qt.Check(t, qt.Equals(cardLogins, 0))

		status, _ := completeCardSignIn(t, attacker, state)
		qt.Check(t, qt.Equals(status, fasthttp.StatusOK))
		qt.Check(t, qt.IsTrue(signedIn(attacker)))
	})
}
