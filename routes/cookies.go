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

// hostPrefix names a cookie a browser keeps only when it was set Secure, with
// Path=/ and no Domain, by this host itself, so no other host and no plain-HTTP
// answer can plant one or overwrite it.
const hostPrefix = "__Host-"

// secureCookies reports whether this request's cookies are Secure, and so named
// with hostPrefix: over TLS (as the trusted proxy reports it), and in every
// environment but development, so a deployment whose proxy is not trusted still
// names them so. Only a development edge reached over plain HTTP uses the plain
// names. This is azugo's CookieDefaultSecurity rule; that option is not used
// itself because it forces the anti-forgery cookie http-only and reads a cookie
// by any of its prefixed names.
func secureCookies(ctx *azugo.Context) bool {
	return ctx.IsTLS() || !ctx.Env().IsDevelopment()
}

// cookieName is the name the cookie named name is set and read under on this
// request.
func cookieName(ctx *azugo.Context, name string) string {
	if secureCookies(ctx) {
		return hostPrefix + name
	}

	return name
}

// readCookie is the value of the cookie this service set as name, read by its
// exact name. Never ctx.Cookie.Get: given a plain name it answers a __Host- or
// __Secure- copy before the plain one, and either can be planted by another host.
func readCookie(ctx *azugo.Context, name string) string {
	return string(ctx.Request().Header.Cookie(cookieName(ctx, name)))
}

// setSessionCookies writes the browser's session state: an http-only cookie
// carrying only the opaque session id (never a token), and an app-readable
// anti-forgery token the app echoes back in the request header on state-changing
// calls. Both are SameSite=Lax, scoped to the whole site, and Secure and
// host-prefixed wherever secureCookies says.
func setSessionCookies(ctx *azugo.Context, name, sid, csrf string) {
	secure := secureCookies(ctx)

	ctx.Cookie.Set(cookieName(ctx, name), sid,
		azugo.CookieHTTPOnly(true),
		azugo.CookieSecure(secure),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
	)
	ctx.Cookie.Set(cookieName(ctx, csrfCookieName), csrf,
		azugo.CookieHTTPOnly(false),
		azugo.CookieSecure(secure),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
	)
}

// clearSessionCookies expires both session cookies on the browser. The expiring
// cookie carries Secure as the one it replaces did: a browser ignores a
// host-prefixed cookie without it, an expiring one included.
func clearSessionCookies(ctx *azugo.Context, name string) {
	secure := azugo.CookieSecure(secureCookies(ctx))

	ctx.Cookie.Clear(cookieName(ctx, name), azugo.CookiePath("/"), secure)
	ctx.Cookie.Clear(cookieName(ctx, csrfCookieName), azugo.CookiePath("/"), secure)
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
	ctx.Cookie.Set(cookieName(ctx, signInCookieName), binding,
		azugo.CookieHTTPOnly(true),
		azugo.CookieSecure(secureCookies(ctx)),
		azugo.CookieSameSiteLax,
		azugo.CookiePath("/"),
		azugo.CookieMaxAge(flowTTL),
	)

	return binding, nil
}

// browserBinding is the binding value the browser sent, or "" when it sent none
// or one this service could not have set.
func browserBinding(ctx *azugo.Context) string {
	v := readCookie(ctx, signInCookieName)
	if len(v) != base64.RawURLEncoding.EncodedLen(bindingBytes) {
		return ""
	}
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		return ""
	}

	return v
}
