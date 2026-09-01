package portalapi

import (
	"strings"
	"testing"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/go-quicktest/qt"
)

func TestSigningSlotReturnURLsPrefersExplicitBaseAndEscapesIDs(t *testing.T) {
	c := &Configuration{}
	c.PostLoginURL = "https://app.example/"
	c.SigningReturnBaseURL = "https://signbyte.example/"

	post, _ := c.SigningSlotReturnURLs("a/b id", "s-1")
	// The explicit base wins over PostLoginURL, and the ids are path-escaped.
	qt.Check(t, qt.IsTrue(strings.HasPrefix(post, "https://signbyte.example/envelopes/")))
	qt.Check(t, qt.IsTrue(strings.Contains(post, "a%2Fb%20id")))
	qt.Check(t, qt.IsTrue(strings.HasSuffix(post, "/sign?job={jobId}")))
}

func TestSigningSlotReturnURLsTargetsTheSlotScreen(t *testing.T) {
	c := &Configuration{}
	c.PostLoginURL = "https://app.example/dashboard"

	post, autherr := c.SigningSlotReturnURLs("env-1", "slot 2")
	qt.Check(t, qt.Equals(post, "https://app.example/envelopes/env-1/slots/slot%202/sign?job={jobId}"))
	qt.Check(t, qt.Equals(autherr, "https://app.example/envelopes/env-1/slots/slot%202/sign?job={jobId}&error=1"))
}

func TestSigningSlotReturnURLsEmptyWhenNoOrigin(t *testing.T) {
	c := &Configuration{}
	post, autherr := c.SigningSlotReturnURLs("env-1", "s-1")
	qt.Check(t, qt.Equals(post, ""))
	qt.Check(t, qt.Equals(autherr, ""))
}

func TestInternalURLPrefersExplicitOverride(t *testing.T) {
	c := &Configuration{Auth: &authclient.Configuration{IssuerURL: "https://issuer.example"}}
	c.AuthInternalURL = "https://internal.example"
	qt.Check(t, qt.Equals(c.InternalURL(), "https://internal.example"))
}

func TestInternalURLFallsBackToIssuer(t *testing.T) {
	c := &Configuration{Auth: &authclient.Configuration{IssuerURL: "https://issuer.example"}}
	// No AuthInternalURL set — no reverse proxy between this service and the issuer.
	qt.Check(t, qt.Equals(c.InternalURL(), "https://issuer.example"))
}

func TestLogoutRedirectURIDerivesLandingScreenFromPostLogin(t *testing.T) {
	c := &Configuration{}
	c.PostLoginURL = "https://app.example/dashboard"
	qt.Check(t, qt.Equals(c.LogoutRedirectURI(), "https://app.example/welcome"))
}

func TestLogoutRedirectURIEmptyWhenNoOrigin(t *testing.T) {
	c := &Configuration{} // no PostLoginURL
	qt.Check(t, qt.Equals(c.LogoutRedirectURI(), ""))
}

func TestOutboundIssuerPrefersExplicitOverride(t *testing.T) {
	c := &Configuration{Auth: &authclient.Configuration{IssuerURL: "https://issuer.example"}}
	c.OutboundIssuerURL = "https://internal-mint.example"
	qt.Check(t, qt.Equals(c.outboundIssuer(), "https://internal-mint.example"))
}

func TestOutboundIssuerFallsBackToAuthIssuer(t *testing.T) {
	c := &Configuration{Auth: &authclient.Configuration{IssuerURL: "https://issuer.example"}}
	qt.Check(t, qt.Equals(c.outboundIssuer(), "https://issuer.example"))
}

// TestOutboundAuthClientConfigCopiesAuthAndAddsCredentials proves the outbound
// client config reuses the validated Auth settings (never re-derives them) and
// layers this service's own client-credentials + the in-network issuer override on
// top — without mutating the original Auth config that was validated at load time.
func TestOutboundAuthClientConfigCopiesAuthAndAddsCredentials(t *testing.T) {
	c := &Configuration{Auth: &authclient.Configuration{
		IssuerURL:       "https://issuer.example",
		ServiceAudience: "svc:portal-api",
	}}
	c.ServiceClientID = "svc:portal-api"
	c.ServiceClientSecret = "s3cr3t"
	c.OutboundIssuerURL = "https://internal-mint.example"

	out := c.OutboundAuthClientConfig()
	qt.Check(t, qt.Equals(out.IssuerURL, "https://internal-mint.example"))
	qt.Check(t, qt.Equals(out.ServiceAudience, "svc:portal-api"))
	qt.Check(t, qt.Equals(out.ServiceClientID, "svc:portal-api"))
	qt.Check(t, qt.Equals(out.ServiceClientSecret, "s3cr3t"))

	// The original Auth config is untouched.
	qt.Check(t, qt.Equals(c.Auth.IssuerURL, "https://issuer.example"))
	qt.Check(t, qt.Equals(c.Auth.ServiceClientID, ""))
}

// TestGDPRConfigMapsAccessAuditSettings proves the GDPR-audit client config is
// built from this service's access-audit settings, using the library's own
// resilience defaults rather than reimplementing them.
func TestGDPRConfigMapsAccessAuditSettings(t *testing.T) {
	c := &Configuration{}
	c.AccessAuditURL = "https://access-audit.example"
	c.AccessAuditAudience = "svc:access-audit"
	c.AccessAuditScope = "access-audit:write"

	out := c.GDPRConfig()
	qt.Check(t, qt.Equals(out.Endpoint, "https://access-audit.example"))
	qt.Check(t, qt.Equals(out.Audience, "svc:access-audit"))
	qt.Check(t, qt.Equals(out.Scope, "access-audit:write"))
	qt.Check(t, qt.Equals(out.Timeout, gdpr.DefaultTimeout))
	qt.Check(t, qt.Equals(out.OutboxCapacity, gdpr.DefaultOutboxCapacity))
	qt.Check(t, qt.Equals(out.MaxRetries, gdpr.DefaultMaxRetries))
}
