package routes

import "azugo.io/azugo"

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
