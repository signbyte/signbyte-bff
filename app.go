// Package portalapi is the Portal-API (BFF): the single trust boundary between
// the public single-page app and the internal service mesh. It terminates the
// browser session (an opaque cookie; the signing-bound key and tokens stay
// server-side), drives the upstream Auth Service to log the user in, and composes
// the document, envelope, signing, and preview services into coarse-grained
// endpoints — delegating the user's identity downstream so the user's own data is
// reachable. It owns no durable relational data and holds no signing keys.
//
// Cross-cutting concerns (logging with redaction, tracing, correlation) are
// installed once by the shared platform-kit and are never wired per-service.
//
// Status: walking skeleton — it boots, serves liveness/readiness, runs the
// browser login + cookie session against the Auth Service, and exposes the
// session/identity surface; document, envelope, and signing composition are added
// in later increments.
package portalapi

import (
	"fmt"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/signbyte-bff/asclient"
	"github.com/signbyte/signbyte-bff/audit"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"
)

// App is the Portal-API application container.
type App struct {
	*azugo.App

	config *Configuration

	// redisClient backs the session store; held so Stop can close it. Nil when the
	// in-memory store is used (development/test).
	redisClient redis.UniversalClient

	// sessions maps the browser session cookie to the server-held login state: the
	// per-session signing-bound key and the access/refresh tokens.
	sessions session.Store

	// as drives the upstream Auth Service on the user's behalf: the authorization
	// redirect, the code/refresh token exchange, the identity lookup, and step-up.
	as *asclient.Client

	// outboundClient mints downstream tokens carrying the user's identity (token
	// exchange) for the composed service calls. Nil until a collaborator base URL is
	// configured (skeleton/dev).
	outboundClient *authclient.Client

	// documents composes the document service on the user's behalf. Nil until the
	// document base URL + the outbound client are configured.
	documents *clients.Documents

	// envelope composes the envelope service on the user's behalf. Nil until the
	// envelope base URL + the outbound client are configured.
	envelope *clients.Envelope

	// signflow composes the signing orchestrator on the user's behalf. Nil until the
	// signflow base URL + the outbound client are configured.
	signflow *clients.Signflow

	// preview composes the preview/render service on the user's behalf. Nil until the
	// preview base URL + the outbound client are configured.
	preview *clients.Preview

	// verify forwards public verify uploads to the signing service with this
	// service's own identity (no user on that path). Nil until the signer base
	// URL + the outbound client are configured.
	verify *clients.Verify

	// audit records user-facing GDPR personal-data access (e.g. a document
	// download). Never nil after init — a no-op recorder when access-audit is not
	// configured.
	audit *audit.Recorder

	// verifyAudit posts the public verify flow's abuse-evidence events (its own
	// purpose-scoped trail, distinct from the GDPR access records). Never nil
	// after init — a no-op recorder when access-audit is not configured.
	verifyAudit *audit.VerifyRecorder

	// answers is the short-TTL render-recent cache for validation answers
	// (Redis when configured, else in-memory). Nil when disabled.
	answers AnswerCache

	// secEvents emits security events for the refusals only this boundary can
	// see: an anti-forgery rejection on a live session and a public-verify
	// rate-limit trip. Emitted into the structured log stream (the common SIEM
	// path). Never nil after init.
	secEvents *secevents.Emitter
}

// New constructs the application.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Portal-API (BFF)",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	// Platform glue FIRST: logging + redaction, tracing, correlation. As the single
	// public trust boundary, the BFF projects errors to the public envelope — the
	// originating service id and the internal hop chain are stripped, and an
	// occurrence detail is withheld unless the emitter marked it public-safe.
	if err := platform.Setup(a.App, platform.Options{Config: cfg.BaseConfiguration, PublicErrors: true}); err != nil {
		return err
	}

	// Security events: typed refusal records for the SIEM, distinct from plain
	// request logs. The log sink needs no infrastructure — the shipped log
	// stream is the delivery path.
	a.secEvents = secevents.NewEmitter(secevents.NewLogSink())

	// Session store: the cookie-to-session map + per-session key + tokens. Redis in
	// production (survives restarts, shared across instances); in-memory in dev/test.
	if cfg.RedisEnabled() {
		opts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("signbyte-bff: parse redis url: %w", err)
		}
		a.redisClient = redis.NewClient(opts)
		a.sessions = session.NewRedis(a.redisClient, cfg.SessionTTL, cfg.FlowTTL)
	} else {
		a.Log().Warn("no REDIS_URL configured — using an in-memory session store; sessions will NOT survive restarts and do NOT scale past one instance (development only)")
		a.sessions = session.NewMemory(cfg.SessionTTL, cfg.FlowTTL)
	}

	// The render-recent validation-answer cache rides the session Redis when
	// present (shared across instances), else stays in-process.
	if ttl := cfg.ValidationCacheTTL; ttl > 0 {
		if a.redisClient != nil {
			a.answers = &redisAnswerCache{rc: a.redisClient, ttl: ttl}
		} else {
			a.answers = newMemoryAnswerCache(ttl)
		}
	}

	// The upstream Auth Service client: the browser login + token + identity flow.
	a.as = asclient.New(cfg.IssuerURL(), cfg.InternalURL(), cfg.AuthClientID, cfg.AuthRedirectURI)

	// Outbound delegated-token client — mints downstream tokens carrying the user's
	// identity for the composed service calls. Built only when at least one
	// collaborator base URL is configured.
	if cfg.OutboundEnabled() {
		var err error
		a.outboundClient, err = authclient.New(cfg.OutboundAuthClientConfig())
		if err != nil {
			return fmt.Errorf("signbyte-bff: outbound auth client: %w", err)
		}
	} else {
		a.Log().Warn("no collaborator base URLs set (DOCUMENT_BASE_URL / ENVELOPE_BASE_URL / SIGNFLOW_BASE_URL / PREVIEW_BASE_URL) — the Portal-API can run login + session but cannot compose document/signing endpoints yet (skeleton/dev)")
	}

	// Document composition (on the user's behalf). Built only when the document
	// service is configured + the outbound client exists; otherwise the document
	// routes report not-ready.
	if a.outboundClient != nil && cfg.DocumentBaseURL != "" {
		a.documents = clients.NewDocuments(a.outboundClient, cfg.DocumentBaseURL, cfg.DocumentAudience)
	}
	if a.outboundClient != nil && cfg.EnvelopeBaseURL != "" {
		a.envelope = clients.NewEnvelope(a.outboundClient, cfg.EnvelopeBaseURL, cfg.EnvelopeAudience)
	}
	if a.outboundClient != nil && cfg.SignflowBaseURL != "" {
		a.signflow = clients.NewSignflow(a.outboundClient, cfg.SignflowBaseURL, cfg.SignflowAudience)
	}
	if a.outboundClient != nil && cfg.PreviewBaseURL != "" {
		a.preview = clients.NewPreview(a.outboundClient, cfg.PreviewBaseURL, cfg.PreviewAudience)
	}
	if a.outboundClient != nil && cfg.SignerBaseURL != "" {
		a.verify = clients.NewVerify(a.outboundClient, cfg.SignerBaseURL, cfg.SignerAudience)
	}

	// GDPR-audit: the user-facing personal-data access records the Portal-API makes
	// as the human boundary (e.g. a document download). Wired only when access-audit
	// is configured and an outbound service client exists; otherwise a no-op
	// recorder. The records post as this service with its own token.
	a.audit = audit.New(nil, a.Log())
	a.verifyAudit = audit.NewVerifyRecorder(nil, "", "", nil, a.Log())
	if cfg.AccessAuditEnabled() {
		if a.outboundClient == nil {
			a.Log().Warn("ACCESS_AUDIT_URL set but no outbound service client (set a collaborator base URL) — user-facing GDPR access records will NOT be posted")
		} else {
			gc, err := a.buildGDPRAudit(cfg)
			if err != nil {
				return err
			}
			a.audit = audit.New(gc, a.Log())
			// The verify abuse-evidence trail rides the same audit service under
			// its own purpose-scoped endpoint + scope.
			a.verifyAudit = audit.NewVerifyRecorder(a.outboundClient, cfg.AccessAuditURL,
				cfg.AccessAuditAudience, a.BackgroundContext, a.Log())
		}
	} else {
		a.Log().Warn("no ACCESS_AUDIT_URL set — user-facing GDPR access records will NOT be posted (development)")
	}

	return nil
}

// buildGDPRAudit constructs the GDPR-audit client (records post as this service)
// and registers its background outbox drain.
func (a *App) buildGDPRAudit(cfg *Configuration) (*gdpr.Client, error) {
	var outbox gdpr.Outbox
	if dir := cfg.AccessAuditOutboxDir; dir != "" {
		ob, err := gdpr.NewFileOutbox(dir, gdpr.DefaultOutboxCapacity)
		if err != nil {
			return nil, fmt.Errorf("signbyte-bff: audit outbox: %w", err)
		}
		outbox = ob
	}

	gc, err := gdpr.New(
		cfg.GDPRConfig(),
		newAccessAuditPoster(a.outboundClient, cfg.AccessAuditURL, cfg.AccessAuditAudience, cfg.AccessAuditScope),
		gdpr.Options{Outbox: outbox, Logger: a.Log()},
	)
	if err != nil {
		return nil, fmt.Errorf("signbyte-bff: gdpr-audit client: %w", err)
	}
	if err := a.AddTask(audit.NewDrainTask(gc)); err != nil {
		return nil, fmt.Errorf("signbyte-bff: gdpr drain task: %w", err)
	}

	return gc, nil
}

// Start verifies the session store is reachable (non-fatal) then starts the
// server.
func (a *App) Start() error {
	if err := a.sessions.Ping(a.BackgroundContext()); err != nil {
		a.Log().Warn("session store not reachable at start — readiness will report not-ready until it recovers", zap.Error(err))
	}

	return a.App.Start()
}

// Stop stops the server, then closes the session store backend.
func (a *App) Stop() {
	a.App.Stop()
	if a.redisClient != nil {
		_ = a.redisClient.Close()
	}
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Sessions returns the cookie-to-session store.
func (a *App) Sessions() session.Store { return a.sessions }

// SecEvents is the security-event emitter (never nil after init).
func (a *App) SecEvents() *secevents.Emitter { return a.secEvents }

// SetSecEvents replaces the security-event emitter (tests).
func (a *App) SetSecEvents(e *secevents.Emitter) { a.secEvents = e }

// AuthService returns the upstream Auth Service client.
func (a *App) AuthService() *asclient.Client { return a.as }

// OutboundClient returns the outbound delegated-token client (nil until a
// collaborator base URL is configured).
func (a *App) OutboundClient() *authclient.Client { return a.outboundClient }

// Documents returns the document-composition client (nil until the document
// service is configured).
func (a *App) Documents() *clients.Documents { return a.documents }

// Envelope returns the envelope-composition client (nil until the envelope
// service is configured).
func (a *App) Envelope() *clients.Envelope { return a.envelope }

// Signflow returns the signing-composition client (nil until the orchestrator is
// configured).
func (a *App) Signflow() *clients.Signflow { return a.signflow }

// Preview returns the preview-composition client (nil until the preview service is
// configured).
func (a *App) Preview() *clients.Preview { return a.preview }

// Verify returns the public-verify proxy client (nil until the signer base URL
// is configured).
func (a *App) Verify() *clients.Verify { return a.verify }

// Audit returns the GDPR-audit recorder for user-facing personal-data access
// (never nil after init; a no-op when access-audit is not configured).
func (a *App) Audit() *audit.Recorder { return a.audit }

// VerifyAudit returns the verify abuse-evidence recorder (never nil after
// init; a no-op when access-audit is not configured).
func (a *App) VerifyAudit() *audit.VerifyRecorder { return a.verifyAudit }

// AnswerCache returns the render-recent validation-answer cache (nil when
// disabled).
func (a *App) AnswerCache() AnswerCache { return a.answers }

// SetSessions injects the session store (test use only).
func (a *App) SetSessions(s session.Store) { a.sessions = s }

// SetDocuments injects the document-composition client (test use only).
func (a *App) SetDocuments(d *clients.Documents) { a.documents = d }

// SetEnvelope injects the envelope-composition client (test use only).
func (a *App) SetEnvelope(e *clients.Envelope) { a.envelope = e }

// SetSignflow injects the signing-composition client (test use only).
func (a *App) SetSignflow(s *clients.Signflow) { a.signflow = s }

// SetPreview injects the preview-composition client (test use only).
func (a *App) SetPreview(p *clients.Preview) { a.preview = p }

// SetVerify injects the public-verify proxy client (test use only).
func (a *App) SetVerify(v *clients.Verify) { a.verify = v }

// SetAudit injects the GDPR-audit recorder (test use only).
func (a *App) SetAudit(rec *audit.Recorder) { a.audit = rec }

// SetVerifyAudit injects the verify abuse-evidence recorder (test use only).
func (a *App) SetVerifyAudit(rec *audit.VerifyRecorder) { a.verifyAudit = rec }
