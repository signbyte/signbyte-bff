package portalapi

import (
	"testing"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/go-quicktest/qt"

	"github.com/signbyte/signbyte-bff/session"
)

func TestOutboundClientAccessor(t *testing.T) {
	app := TestApp(t)
	qt.Check(t, qt.IsNil(app.OutboundClient())) // no collaborator base URL configured

	ac, err := authclient.New(&authclient.Configuration{IssuerURL: "https://issuer.example", ServiceAudience: "svc:portal-api"})
	qt.Assert(t, qt.IsNil(err))
	app.outboundClient = ac
	qt.Check(t, qt.Equals(app.OutboundClient(), ac))
}

func TestSetSessionsAccessor(t *testing.T) {
	app := TestApp(t)
	mem := session.NewMemory(0, 0)
	app.SetSessions(mem)
	qt.Check(t, qt.Equals(app.Sessions(), mem))
}

// TestBuildGDPRAuditRegistersDrainTask proves the GDPR-audit client is built from
// the access-audit config and its background outbox drain is registered as an app
// task, so buffered access records flush on shutdown without a bespoke
// Start/Stop override.
func TestBuildGDPRAuditRegistersDrainTask(t *testing.T) {
	app := TestApp(t)

	ac, err := authclient.New(&authclient.Configuration{IssuerURL: "https://issuer.example", ServiceAudience: "svc:portal-api"})
	qt.Assert(t, qt.IsNil(err))
	app.outboundClient = ac

	cfg := app.Config()
	cfg.AccessAuditURL = "https://access-audit.example"
	cfg.AccessAuditAudience = "svc:access-audit"
	cfg.AccessAuditScope = "access-audit:write"

	gc, err := app.buildGDPRAudit(cfg)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(gc))
}

// TestBuildGDPRAuditInvalidOutboxDirFails proves a broken durable-outbox
// destination fails closed at build time rather than silently falling back to the
// (non-durable) in-memory outbox.
func TestBuildGDPRAuditInvalidOutboxDirFails(t *testing.T) {
	app := TestApp(t)

	ac, err := authclient.New(&authclient.Configuration{IssuerURL: "https://issuer.example", ServiceAudience: "svc:portal-api"})
	qt.Assert(t, qt.IsNil(err))
	app.outboundClient = ac

	cfg := app.Config()
	cfg.AccessAuditURL = "https://access-audit.example"
	cfg.AccessAuditAudience = "svc:access-audit"
	cfg.AccessAuditScope = "access-audit:write"
	// A file (not a directory) cannot be opened as an outbox directory.
	cfg.AccessAuditOutboxDir = "app_test.go"

	_, err = app.buildGDPRAudit(cfg)
	qt.Check(t, qt.IsNotNil(err))
}
