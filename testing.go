package portalapi

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestApp builds an App for tests: metrics off, an in-memory session store (no
// Redis), no collaborators wired, and the upstream Auth Service pointed at a
// placeholder. Network-touching flows (token exchange, identity) are exercised on
// the live stack, not here.
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "signbyte-bff")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("SERVICE_AUDIENCE", "svc:portal-api")
	tb.Setenv("AUTH_REDIRECT_URI", "http://localhost:8080/api/portal/v1/login/callback")
	tb.Setenv("POST_LOGIN_URL", "http://localhost:8080/")

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	return app
}
