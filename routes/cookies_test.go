package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/session"
)

// A cookie keeps no integrity between hosts: a page on a sibling host, or anyone on
// the network path where a cookie is not Secure, can set one for this edge's host
// under any name. These tests hold the edge to one name per cookie on each request —
// __Host- wherever the cookie is Secure — and to reading it under that name only, so
// a copy planted under another name is never taken for it.

// overTLS marks a request as arriving over TLS, as the edge's proxy reports it; the
// test app trusts every proxy.
func overTLS(c *azugo.TestClient) azugo.TestClientOption {
	return c.WithHeader("X-Forwarded-Proto", "https")
}

// answerCookies parses the cookies an answer sets, by name.
func answerCookies(t *testing.T, resp *fasthttp.Response) map[string]*fasthttp.Cookie {
	t.Helper()

	out := map[string]*fasthttp.Cookie{}
	for k, v := range resp.Header.Cookies() {
		c := new(fasthttp.Cookie)
		qt.Assert(t, qt.IsNil(c.ParseBytes(v)))
		out[string(k)] = c
	}

	return out
}

// signInOn signs a browser in through the stand-in authority in the named
// environment, over TLS or not, and answers the cookies the start and the return
// set, and the browser.
func signInOn(t *testing.T, environment string, tls bool) (start, done map[string]*fasthttp.Cookie, client *azugo.TestClient) {
	t.Helper()

	_, ta, _ := signInAppIn(t, environment)
	client = ta.TestClient()
	var opts []azugo.TestClientOption
	if tls {
		opts = append(opts, overTLS(client))
	}

	resp, err := client.Post(signInRoutes+"/start", nil, opts...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	start = answerCookies(t, resp)
	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	var out struct {
		State string `json:"state"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &out)))

	resp, err = client.Get(signInRoutes+"/callback?"+codeFor(out.State)+"&iss="+url.QueryEscape(testIssuer), opts...)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
	done = answerCookies(t, resp)
	fasthttp.ReleaseResponse(resp)

	return start, done, client
}

func TestEveryCookieIsHostPrefixedWhereSecure(t *testing.T) {
	cases := []struct {
		name        string
		environment string
		tls         bool
		prefix      string
	}{
		{"over TLS", "development", true, hostName},
		{"over plain HTTP outside development", "production", false, hostName},
		{"over plain HTTP in development", "development", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, done, _ := signInOn(t, tc.environment, tc.tls)
			secure := tc.prefix != ""

			check := func(set map[string]*fasthttp.Cookie, name string, httpOnly bool) {
				t.Helper()
				c, ok := set[tc.prefix+name]
				qt.Assert(t, qt.IsTrue(ok), qt.Commentf("%s set", tc.prefix+name))
				qt.Check(t, qt.Equals(c.Secure(), secure), qt.Commentf("%s Secure", tc.prefix+name))
				qt.Check(t, qt.Equals(string(c.Path()), "/"))
				qt.Check(t, qt.Equals(string(c.Domain()), ""))
				qt.Check(t, qt.Equals(c.HTTPOnly(), httpOnly))
				qt.Check(t, qt.Equals(c.SameSite(), fasthttp.CookieSameSiteLaxMode))
				if secure {
					_, plain := set[name]
					qt.Check(t, qt.IsFalse(plain), qt.Commentf("%s also set under its plain name", name))
				}
			}
			check(start, signInCookieName, true)
			check(done, sessionCookieName, true)
			check(done, csrfCookieName, false)
		})
	}
}

func TestSignOutClearsTheHostPrefixedCookies(t *testing.T) {
	_, done, client := signInOn(t, "development", true)
	set := done[hostName+csrfCookieName]
	qt.Assert(t, qt.IsNotNil(set), qt.Commentf("the sign-in over TLS set no %s", hostName+csrfCookieName))
	csrf := string(set.Value())

	resp, err := client.PostJSON("/api/portal/v1/logout", map[string]any{}, overTLS(client), client.WithHeader(csrfHeader, csrf))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	cleared := answerCookies(t, resp)
	fasthttp.ReleaseResponse(resp)

	for _, name := range []string{sessionCookieName, csrfCookieName} {
		c, ok := cleared[hostName+name]
		qt.Assert(t, qt.IsTrue(ok), qt.Commentf("%s cleared", hostName+name))
		qt.Check(t, qt.IsTrue(c.Expire().Equal(fasthttp.CookieExpireDelete)), qt.Commentf("%s expired", name))
		// A browser ignores a host-prefixed cookie, an expiring one included, without these.
		qt.Check(t, qt.IsTrue(c.Secure()), qt.Commentf("%s cleared without Secure", name))
		qt.Check(t, qt.Equals(string(c.Path()), "/"))
	}
}

// sessionProbe is the edge's session gate in front of a route that answers whose
// session it read, in the named environment.
func sessionProbe(t *testing.T, environment string) (*api.App, *azugo.TestApp) {
	t.Helper()

	app := api.TestAppIn(t, environment)
	r := &router{App: app}
	g := app.Group("/probe")
	g.Use(r.requireSession())
	g.Get("", func(ctx *azugo.Context) {
		_, sess := sessionFromCtx(ctx)
		ctx.Text(sess.Subject)
	})
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	return app, ta
}

// hostName is the prefix the edge names a Secure cookie with; the tests spell it
// out rather than borrow the edge's constant, so they also build against code
// that has none.
const hostName = "__Host-"

// sessionCookieName is the session cookie's name in the test configuration.
const sessionCookieName = "portal_session"

func TestAPlantedCopyIsNeverRead(t *testing.T) {
	putAs := func(t *testing.T, app *api.App, sid, subject string) {
		t.Helper()
		qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
			Subject: subject, AccessToken: "tok", AccessExpiry: 1 << 62, CSRF: "csrf-" + subject,
		})))
	}
	cases := []struct {
		name        string
		environment string
		tls         bool
		cookies     [][2]string
		want        string // the subject answered, or "" for no session (401)
	}{
		{"over TLS, only a __Secure- copy", "development", true,
			[][2]string{{"__Secure-" + sessionCookieName, "sid-other"}}, ""},
		{"over TLS, only the plain name (planted, or held from before)", "development", true,
			[][2]string{{sessionCookieName, "sid-other"}}, ""},
		{"over TLS, a miscapitalised __Host- copy", "development", true,
			[][2]string{{"__host-" + sessionCookieName, "sid-other"}}, ""},
		{"over TLS, the own __Host- session beside planted copies", "development", true,
			[][2]string{{"__Secure-" + sessionCookieName, "sid-other"}, {sessionCookieName, "sid-other"},
				{hostName + sessionCookieName, "sid-own"}}, "own"},
		{"outside development, only the plain name", "production", false,
			[][2]string{{sessionCookieName, "sid-other"}}, ""},
		{"over plain HTTP in development, the own session beside planted prefixed copies", "development", false,
			[][2]string{{hostName + sessionCookieName, "sid-other"}, {"__Secure-" + sessionCookieName, "sid-other"},
				{sessionCookieName, "sid-own"}}, "own"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, ta := sessionProbe(t, tc.environment)
			putAs(t, app, "sid-own", "own")
			putAs(t, app, "sid-other", "other")
			client := ta.TestClient()
			var opts []azugo.TestClientOption
			if tc.tls {
				opts = append(opts, overTLS(client))
			}
			for _, c := range tc.cookies {
				opts = append(opts, client.WithCookie(c[0], c[1]))
			}

			resp, err := client.Get("/probe", opts...)
			qt.Assert(t, qt.IsNil(err))
			status, body := resp.StatusCode(), string(resp.Body())
			fasthttp.ReleaseResponse(resp)

			if tc.want == "" {
				qt.Check(t, qt.Equals(status, fasthttp.StatusUnauthorized), qt.Commentf("answered %q", body))

				return
			}
			qt.Check(t, qt.Equals(status, fasthttp.StatusOK))
			qt.Check(t, qt.Equals(body, tc.want))
		})
	}
}
