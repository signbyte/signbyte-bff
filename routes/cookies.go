package routes

import (
	"encoding/base64"
	"time"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-authbyte/asclient"
)

// signInCookieName holds the value that binds a sign-in to the browser that
// started it (session.FlowKey). Http-only: nothing in the page needs it.
const signInCookieName = "portal_signin"

// bindingBytes is the binding value's size in random bytes.
const bindingBytes = 32

// setSessionCookies writes the browser's session state: an http-only cookie
// carrying only the opaque session id (never a token), and an app-readable
// anti-forgery token the app echoes back in the request header on state-changing
// calls. Both are Secure over TLS, SameSite=Lax, and scoped to the whole site.
func setSessionCookies(ctx *azugo.Context, name, sid, csrf string) {
	secure := ctx.IsTLS()

	ctx.Cookie.Set(name, sid,
		azugo.CookieHTTPOnly(true),
		azugo.CookieSecure(secure),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
	)
	ctx.Cookie.Set(csrfCookieName, csrf,
		azugo.CookieHTTPOnly(false),
		azugo.CookieSecure(secure),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
	)
}

// clearSessionCookies expires both session cookies on the browser.
func clearSessionCookies(ctx *azugo.Context, name string) {
	ctx.Cookie.Clear(name, azugo.CookiePath("/"))
	ctx.Cookie.Clear(csrfCookieName, azugo.CookiePath("/"))
}

// bindBrowser answers the binding value of the browser starting a sign-in, and
// sets its cookie for as long as a sign-in may take, on the session cookie's
// terms. A browser already holding one keeps it, so two sign-ins started in two
// tabs both finish; it is never cleared, only left to expire, for the same reason.
func bindBrowser(ctx *azugo.Context, flowTTL time.Duration) (string, error) {
	binding := browserBinding(ctx)
	if binding == "" {
		var err error
		if binding, err = asclient.RandomToken(bindingBytes); err != nil {
			return "", err
		}
	}
	ctx.Cookie.Set(signInCookieName, binding,
		azugo.CookieHTTPOnly(true),
		azugo.CookieSecure(ctx.IsTLS()),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
		azugo.CookieMaxAge(flowTTL),
	)

	return binding, nil
}

// browserBinding is the binding value the browser sent, or "" when it sent none
// or one this service could not have set.
func browserBinding(ctx *azugo.Context) string {
	v := ctx.Cookie.Get(signInCookieName)
	if len(v) != base64.RawURLEncoding.EncodedLen(bindingBytes) {
		return ""
	}
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		return ""
	}

	return v
}
