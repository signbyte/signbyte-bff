package portalapi

import (
	"net/url"
	"strings"
	"time"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"
)

// Configuration is the Portal-API (BFF) service configuration: the platform base
// config, the upstream Auth Service this service drives on the user's behalf, the
// browser-facing cookie session backed by Redis, the outbound service-client
// identity, and the collaborator services it composes (the document service, the
// envelope service, the signing orchestrator, the preview service).
//
// The Portal-API is the single trust boundary between the public internet and the
// internal service mesh. The browser holds only an opaque session cookie; this
// service holds the per-session signing-bound key and the access/refresh tokens
// server-side and never exposes them to the browser.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth carries the upstream Auth Service trust settings: the issuer URL
	// (AUTH_ISSUER_URL), this service's own audience, and the sender-constraint /
	// key-cache defaults. The issuer is used for three things, all against the same
	// address so the sender-constraint proof matches: the browser-facing
	// authorization redirect, the server-side token + identity + step-up calls this
	// service makes, and the proof URL bound into each of those calls. It is also
	// the basis for the outbound delegated-token client.
	Auth *authclient.Configuration `mapstructure:"auth"`

	// AuthInternalURL is the in-network address this service reaches the Auth Service
	// at for the server-side token, identity, and step-up calls, and the address
	// bound into each proof (so it matches what the Auth Service reconstructs). Empty
	// falls back to the issuer URL (when no reverse proxy sits between them).
	AuthInternalURL string `mapstructure:"auth_internal_url" validate:"omitempty,url"`

	// AuthClientID is the public client id this service presents to the Auth Service
	// when it runs the authorization-code flow for a user. AuthRedirectURI is the
	// callback the Auth Service redirects the browser back to after authentication;
	// it must be registered as an allowed redirect for AuthClientID.
	AuthClientID    string `mapstructure:"auth_client_id" validate:"required"`
	AuthRedirectURI string `mapstructure:"auth_redirect_uri" validate:"required,url"`

	// PostLoginURL is where the browser is sent after a successful login or session
	// elevation (the single-page app's entry point). Required.
	PostLoginURL string `mapstructure:"post_login_url" validate:"required,url"`

	// SigningReturnBaseURL is the app origin the signing provider returns the browser
	// to after a redirect-flow authorization (scheme://host[:port]). Empty derives the
	// origin from PostLoginURL, so dev needs no extra wiring. It is always controlled
	// by the BFF (never built from client input), so there is no open-redirect surface.
	SigningReturnBaseURL string `mapstructure:"signing_return_base_url" validate:"omitempty,url"`

	// RedisURL backs the cookie-to-session map, the per-session signing key + tokens,
	// and the short-lived login-flow state. Empty selects an in-memory store
	// (development/test only — sessions do not survive a restart and do not scale
	// past one instance). Production must set it.
	RedisURL string `mapstructure:"redis_url"`

	// SessionTTL is how long a logged-in session lives without re-login. FlowTTL is
	// the short window a login may take from start to callback.
	SessionTTL time.Duration `mapstructure:"session_ttl" validate:"required,gt=0"`
	FlowTTL    time.Duration `mapstructure:"flow_ttl" validate:"required,gt=0"`

	// CookieName is the name of the session cookie handed to the browser.
	CookieName string `mapstructure:"cookie_name" validate:"required"`

	// --- Collaborators (composed in later increments; optional in the skeleton) ---
	DocumentBaseURL string `mapstructure:"document_base_url" validate:"omitempty,url"`
	EnvelopeBaseURL string `mapstructure:"envelope_base_url" validate:"omitempty,url"`
	SignflowBaseURL string `mapstructure:"signflow_base_url" validate:"omitempty,url"`
	PreviewBaseURL  string `mapstructure:"preview_base_url" validate:"omitempty,url"`

	// Target audiences for the outbound delegated tokens (one per collaborator).
	DocumentAudience string `mapstructure:"document_audience"`
	EnvelopeAudience string `mapstructure:"envelope_audience"`
	SignflowAudience string `mapstructure:"signflow_audience"`
	PreviewAudience  string `mapstructure:"preview_audience"`

	// --- Public verify (the unauthenticated Verify tab) ---
	// SignerBaseURL is the signing service the public verify route forwards the
	// uploaded file to, with this service's OWN client-credentials identity —
	// there is no user on this path and the signing orchestrator is bypassed by
	// design (the flow is a stateless proxy; the bytes are never persisted
	// here). Empty leaves the verify route unconfigured (503).
	SignerBaseURL string `mapstructure:"signer_base_url" validate:"omitempty,url"`
	// SignerAudience targets the outbound service token at the signing service.
	SignerAudience string `mapstructure:"signer_audience"`
	// VerifyMaxBytes caps the uploaded verify file; larger uploads are rejected
	// before any bytes are forwarded upstream.
	VerifyMaxBytes int64 `mapstructure:"verify_max_bytes" validate:"gt=0"`
	// VerifyRatePerMinute + VerifyRateBurst shape the per-client-IP rate limit
	// on the public verify route; VerifyConcurrentPerIP caps in-flight verify
	// requests per client IP (a verification legitimately runs tens of
	// seconds — one slow request must not become a cheap resource pin).
	VerifyRatePerMinute   float64 `mapstructure:"verify_rate_per_minute" validate:"gt=0"`
	VerifyRateBurst       int     `mapstructure:"verify_rate_burst" validate:"gt=0"`
	VerifyConcurrentPerIP int     `mapstructure:"verify_concurrent_per_ip" validate:"gt=0"`

	// ValidationCacheTTL is the render-recent window for validation answers:
	// an answer that just passed through this service is served again from
	// cache instead of re-running the full upstream validation round (which
	// legitimately takes tens of seconds). Explicitly NOT a persisted read
	// path — an explicit re-validate (?force=1) bypasses it, and rendered
	// answers carry their validatedAt. Zero disables the cache.
	ValidationCacheTTL time.Duration `mapstructure:"validation_cache_ttl" validate:"gte=0"`

	// --- Outbound service-client identity ---
	// ServiceClientID/Secret authenticate this service's outbound token requests:
	// the token exchange that mints a downstream token carrying the user's identity.
	// OutboundIssuerURL points the token mint at the in-network address (the trusted
	// issuer stays the upstream Auth Service); empty falls back to it.
	ServiceClientID     string `mapstructure:"service_client_id"`
	ServiceClientSecret string `mapstructure:"service_client_secret"`
	OutboundIssuerURL   string `mapstructure:"outbound_issuer_url" validate:"omitempty,url"`

	// --- GDPR-audit (user-facing personal-data access) ---
	// AccessAuditURL is the access-audit service base URL; empty disables GDPR-audit
	// recording (development). Audience/Scope target the outbound service token at
	// access-audit. OutboxDir, when set, buffers undelivered records to disk for
	// crash-durable background retry (else an in-memory buffer).
	AccessAuditURL       string `mapstructure:"access_audit_url" validate:"omitempty,url"`
	AccessAuditAudience  string `mapstructure:"access_audit_audience"`
	AccessAuditScope     string `mapstructure:"access_audit_scope"`
	AccessAuditOutboxDir string `mapstructure:"access_audit_outbox_dir"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)
	v.SetDefault("auth.service_audience", "svc:portal-api")

	// Upstream Auth Service public client.
	v.SetDefault("auth_client_id", "portal-spa")
	_ = v.BindEnv("auth_internal_url", "AUTH_INTERNAL_URL")
	_ = v.BindEnv("auth_client_id", "AUTH_CLIENT_ID")
	_ = v.BindEnv("auth_redirect_uri", "AUTH_REDIRECT_URI")
	_ = v.BindEnv("post_login_url", "POST_LOGIN_URL")
	_ = v.BindEnv("signing_return_base_url", "SIGNING_RETURN_BASE_URL")

	// Session + cookie.
	v.SetDefault("session_ttl", 12*time.Hour)
	v.SetDefault("flow_ttl", 10*time.Minute)
	v.SetDefault("cookie_name", "portal_session")
	_ = v.BindEnv("redis_url", "REDIS_URL")
	_ = v.BindEnv("session_ttl", "SESSION_TTL")
	_ = v.BindEnv("flow_ttl", "FLOW_TTL")
	_ = v.BindEnv("cookie_name", "COOKIE_NAME")

	// Collaborators (composed later).
	_ = v.BindEnv("document_base_url", "DOCUMENT_BASE_URL")
	_ = v.BindEnv("envelope_base_url", "ENVELOPE_BASE_URL")
	_ = v.BindEnv("signflow_base_url", "SIGNFLOW_BASE_URL")
	_ = v.BindEnv("preview_base_url", "PREVIEW_BASE_URL")

	v.SetDefault("document_audience", "svc:document")
	v.SetDefault("envelope_audience", "svc:envelope")
	v.SetDefault("signflow_audience", "svc:signflow")
	v.SetDefault("preview_audience", "svc:preview")
	_ = v.BindEnv("document_audience", "DOCUMENT_AUDIENCE")
	_ = v.BindEnv("envelope_audience", "ENVELOPE_AUDIENCE")
	_ = v.BindEnv("signflow_audience", "SIGNFLOW_AUDIENCE")
	_ = v.BindEnv("preview_audience", "PREVIEW_AUDIENCE")

	// Public verify.
	v.SetDefault("signer_audience", "svc:eparaksts-signer")
	v.SetDefault("verify_max_bytes", int64(25<<20))
	v.SetDefault("verify_rate_per_minute", 6.0)
	v.SetDefault("verify_rate_burst", 3)
	v.SetDefault("verify_concurrent_per_ip", 1)
	_ = v.BindEnv("signer_base_url", "SIGNER_BASE_URL")
	_ = v.BindEnv("signer_audience", "SIGNER_AUDIENCE")
	_ = v.BindEnv("verify_max_bytes", "VERIFY_MAX_BYTES")
	_ = v.BindEnv("verify_rate_per_minute", "VERIFY_RATE_PER_MINUTE")
	_ = v.BindEnv("verify_rate_burst", "VERIFY_RATE_BURST")
	_ = v.BindEnv("verify_concurrent_per_ip", "VERIFY_CONCURRENT_PER_IP")

	// Render-recent validation-answer cache.
	v.SetDefault("validation_cache_ttl", 5*time.Minute)
	_ = v.BindEnv("validation_cache_ttl", "VALIDATION_CACHE_TTL")

	// Outbound service-client identity.
	v.SetDefault("service_client_id", "svc:portal-api")
	loadSecret(v, "service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv("service_client_id", "SERVICE_CLIENT_ID")
	_ = v.BindEnv("service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv("outbound_issuer_url", "OUTBOUND_ISSUER_URL")

	// GDPR-audit — off until ACCESS_AUDIT_URL is set.
	v.SetDefault("access_audit_audience", "svc:access-audit")
	v.SetDefault("access_audit_scope", "access-audit:write")
	_ = v.BindEnv("access_audit_url", "ACCESS_AUDIT_URL")
	_ = v.BindEnv("access_audit_audience", "ACCESS_AUDIT_AUDIENCE")
	_ = v.BindEnv("access_audit_scope", "ACCESS_AUDIT_SCOPE")
	_ = v.BindEnv("access_audit_outbox_dir", "ACCESS_AUDIT_OUTBOX_DIR")
}

// Validate validates the full configuration tree.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := c.Auth.Validate(valid); err != nil {
		return err
	}

	return valid.Struct(c)
}

// IssuerURL is the public upstream Auth Service base URL (browser authorization
// redirect + the trusted token issuer).
func (c *Configuration) IssuerURL() string { return c.Auth.IssuerURL }

// InternalURL is the in-network Auth Service address for server-side calls + the
// proof URL; falls back to the issuer URL when not separately configured.
func (c *Configuration) InternalURL() string {
	if u := strings.TrimSpace(c.AuthInternalURL); u != "" {
		return u
	}

	return c.Auth.IssuerURL
}

// RedisEnabled reports whether a Redis URL is configured (else in-memory).
func (c *Configuration) RedisEnabled() bool {
	return strings.TrimSpace(c.RedisURL) != ""
}

// LogoutRedirectURI is where the browser lands after logout completes — the app's
// public landing screen, on the same origin as PostLoginURL. A signed-out user
// belongs on the public site face, not parked on the login form. It must be
// registered as a redirect for the login client (the Auth Service validates it
// against that allowlist). Empty when no origin can be determined.
func (c *Configuration) LogoutRedirectURI() string {
	if u, err := url.Parse(c.PostLoginURL); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/welcome"
	}

	return ""
}

// SigningSlotReturnURLs builds the two URLs the signing provider returns the
// browser to after a redirect-flow authorization of an envelope slot — the success
// target and the failure target — so the app resumes on that slot's signing screen
// and polls to completion. Both carry a "{jobId}" placeholder the provider
// substitutes so the app recovers the job without holding client state; the failure
// target also carries an error marker so the app can show guidance without waiting
// for a status poll. The origin is taken from SigningReturnBaseURL, falling back to
// the origin of PostLoginURL. Empty (both) when no origin can be determined — the
// caller then sends no return URLs and the redirect flow falls back to the
// provider's own terminal page. The envelope + slot ids are path-escaped and
// nothing comes from client-supplied URLs, so there is no open-redirect surface.
func (c *Configuration) SigningSlotReturnURLs(envelopeID, slotID string) (postAuth, authError string) {
	origin := c.signingReturnOrigin()
	if origin == "" {
		return "", ""
	}

	base := origin + "/envelopes/" + url.PathEscape(envelopeID) +
		"/slots/" + url.PathEscape(slotID) + "/sign?job={jobId}"

	return base, base + "&error=1"
}

// signingReturnOrigin resolves the app origin redirect-flow return URLs are built
// on: SigningReturnBaseURL, falling back to the origin of PostLoginURL. Trailing
// slash trimmed; empty when neither yields a scheme + host.
func (c *Configuration) signingReturnOrigin() string {
	origin := strings.TrimSpace(c.SigningReturnBaseURL)
	if origin == "" {
		if u, err := url.Parse(c.PostLoginURL); err == nil && u.Scheme != "" && u.Host != "" {
			origin = u.Scheme + "://" + u.Host
		}
	}

	return strings.TrimRight(origin, "/")
}

// OutboundEnabled reports whether at least one collaborator base URL is set, so
// the outbound delegated-token client is worth building.
func (c *Configuration) OutboundEnabled() bool {
	return strings.TrimSpace(c.DocumentBaseURL) != "" ||
		strings.TrimSpace(c.EnvelopeBaseURL) != "" ||
		strings.TrimSpace(c.SignflowBaseURL) != "" ||
		strings.TrimSpace(c.PreviewBaseURL) != "" ||
		strings.TrimSpace(c.SignerBaseURL) != ""
}

// outboundIssuer returns the issuer base for the outbound token mint.
func (c *Configuration) outboundIssuer() string {
	if u := strings.TrimSpace(c.OutboundIssuerURL); u != "" {
		return u
	}

	return c.Auth.IssuerURL
}

// OutboundAuthClientConfig builds the outbound auth-client config: it reuses the
// validated Auth settings and adds this service's client-credentials + the
// optional in-network issuer override (the token exchange that mints a downstream
// token carrying the user's identity).
func (c *Configuration) OutboundAuthClientConfig() *authclient.Configuration {
	cfg := *c.Auth // copy the validated config
	cfg.IssuerURL = c.outboundIssuer()
	cfg.ServiceClientID = c.ServiceClientID
	cfg.ServiceClientSecret = c.ServiceClientSecret

	return &cfg
}

// AccessAuditEnabled reports whether GDPR-audit recording is wired (an
// access-audit URL is set). When off, the recorder is a no-op.
func (c *Configuration) AccessAuditEnabled() bool {
	return strings.TrimSpace(c.AccessAuditURL) != ""
}

// GDPRConfig builds the GDPR-audit client configuration from the access-audit
// settings, using the library defaults for the resilience knobs (timeout, outbox,
// retry, breaker).
func (c *Configuration) GDPRConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:         c.AccessAuditURL,
		Audience:         c.AccessAuditAudience,
		Scope:            c.AccessAuditScope,
		Timeout:          gdpr.DefaultTimeout,
		OutboxCapacity:   gdpr.DefaultOutboxCapacity,
		MaxRetries:       gdpr.DefaultMaxRetries,
		RetryBackoff:     gdpr.DefaultRetryBackoff,
		BreakerThreshold: gdpr.DefaultBreakerThreshold,
		BreakerCooldown:  gdpr.DefaultBreakerCooldown,
	}
}

// loadSecret resolves a secret from the secret store (Vault agent → <NAME>_FILE)
// and registers it as a default so an explicit env value still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}
