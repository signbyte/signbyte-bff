package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// The public verify flow keeps its own, purpose-scoped evidence trail —
// separate from the GDPR access records above. Its purpose is abuse evidence:
// answering who drove the anonymous verification surface (and with what), so a
// provider-side complaint about quota abuse is answerable. It carries no
// document content — only request metadata and the upload's hash.

// verifyEventsPath is the purpose-scoped sink endpoint on the audit service.
const verifyEventsPath = "/v1/verify-events"

// scopeVerifyAudit is the write scope for the verify-evidence surface — its
// own scope group, so the grant is separable from the GDPR access-record one.
const scopeVerifyAudit = "verify-audit:write"

// verifyPostTimeout bounds one background evidence delivery.
const verifyPostTimeout = 10 * time.Second

// VerifyEvent is the abuse-evidence record for one public verify request.
type VerifyEvent struct {
	TS            string `json:"ts"`
	IP            string `json:"ip,omitempty"`
	UserAgent     string `json:"userAgent,omitempty"`
	SizeBytes     int64  `json:"sizeBytes"`
	SHA256        string `json:"sha256,omitempty"`
	Verdict       string `json:"verdict"`
	CorrelationID string `json:"correlationId,omitempty"`
	SessionID     string `json:"sessionId,omitempty"`
}

// serviceDoer issues a background DPoP request as this service's own identity.
// *authclient.Client satisfies it; tests inject a stub.
type serviceDoer interface {
	DoService(ctx context.Context, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// VerifyRecorder posts verify abuse-evidence events to the audit service,
// fire-and-forget: evidence delivery must never block or fail a legitimate
// verification (fail-open on evidence; the caps stay fail-closed). A nil
// recorder or an unconfigured one no-ops, so callers never guard the call.
type VerifyRecorder struct {
	doer     serviceDoer
	url      string
	audience string
	bg       func() context.Context
	log      *zap.Logger
}

// NewVerifyRecorder builds a VerifyRecorder posting to the audit service at
// baseURL. doer may be nil or baseURL empty to disable recording. bg supplies
// the background context deliveries run under (never a request context — the
// delivery outlives the response); nil falls back to context.Background. log
// may be nil.
func NewVerifyRecorder(d serviceDoer, baseURL, audience string, bg func() context.Context, log *zap.Logger) *VerifyRecorder {
	if log == nil {
		log = zap.NewNop()
	}
	if bg == nil {
		bg = context.Background
	}

	return &VerifyRecorder{doer: d, url: baseURL, audience: audience, bg: bg, log: log}
}

// Record delivers one event in the background. Returns immediately; a failed
// delivery is logged, never surfaced.
func (r *VerifyRecorder) Record(ev VerifyEvent) {
	if r == nil || r.doer == nil || r.url == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(r.bg(), verifyPostTimeout)
		defer cancel()

		body, err := json.Marshal(ev)
		if err != nil {
			r.log.Warn("verify evidence: marshal failed", zap.Error(err))

			return
		}

		resp, err := r.doer.DoService(ctx, r.audience, scopeVerifyAudit, http.MethodPost, r.url+verifyEventsPath, nil, body)
		if err != nil {
			r.log.Warn("verify evidence: delivery failed", zap.Error(err))

			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			r.log.Warn("verify evidence: sink rejected the event",
				zap.Int("status", resp.StatusCode), zap.ByteString("body", resp.Body))
		}
	}()
}
