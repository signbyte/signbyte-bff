// Package audit records the Portal-API's user-facing GDPR personal-data access
// events — the interactive reveals the backend services cannot characterize on
// their own. The Portal-API is the human trust boundary: when a person downloads
// their document or reveals a personal code through the browser, that interactive
// access is recorded here with the person as the actor, distinct from the
// background service-to-service access the document service records when it fetches
// bytes on the user's behalf. Records post to the access-audit service.
package audit

import (
	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
)

// Recorder emits GDPR-audit access records. The gdpr client is optional: a nil
// client (access-audit not configured) makes every method a no-op, as does a nil
// Recorder, so callers never need to guard the call site.
type Recorder struct {
	gdpr *gdpr.Client
	log  *zap.Logger
}

// New builds a Recorder over the given GDPR-audit client (which may be nil to
// disable recording). log may be nil.
func New(gdprClient *gdpr.Client, log *zap.Logger) *Recorder {
	if log == nil {
		log = zap.NewNop()
	}

	return &Recorder{gdpr: gdprClient, log: log}
}

// DocumentDownloaded records that the signed-in person retrieved a document's
// bytes through the browser — an interactive reveal of personal data. user is the
// person's pseudonymous identity reference (never a national identifier). It is
// both the actor and the data subject: the person accessed their own document.
// No-op when GDPR-audit is off or the subject is unknown. Routine and fail-open —
// audit back-pressure must never break the user's download.
func (r *Recorder) DocumentDownloaded(ctx *azugo.Context, user, documentID string) {
	r.documentRead(ctx, user, documentID)
}

// DocumentPreviewed records that the signed-in person opened a review-only preview
// of their document through the browser — like a download, an interactive reveal
// of personal data the background renderer cannot characterize. The preview service
// is a service-actor; this records the human actor. Recorded once when the preview
// is opened (the manifest fetch), not per page image. No-op when GDPR-audit is off
// or the subject is unknown. Routine and fail-open.
func (r *Recorder) DocumentPreviewed(ctx *azugo.Context, user, documentID string) {
	r.documentRead(ctx, user, documentID)
}

// documentRead posts the interactive personal-data read record for the person's
// own document (download or preview share the same access semantics).
func (r *Recorder) documentRead(ctx *azugo.Context, user, documentID string) {
	if r == nil || r.gdpr == nil || user == "" {
		return
	}
	err := r.gdpr.Record(ctx, gdpr.EventDocumentAccess, gdpr.Access{
		Actor:        broker.Actor{ID: user, Type: "user"},
		DataSubjects: []string{user},
		Resource:     broker.Resource{Type: gdpr.ResourceDocument, ID: documentID},
		Operation:    broker.OpRead,
		LawfulBasis:  gdpr.BasisContract,
		Purpose:      gdpr.PurposeSigning,
		Channel:      gdpr.ChannelInteractive,
	})
	if err != nil {
		r.log.Warn("gdpr access record not persisted (non-fatal)", zap.Error(err))
	}
}
