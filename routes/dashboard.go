package routes

import (
	"time"

	"github.com/signbyte/signbyte-bff/clients"

	"azugo.io/azugo"
)

// dashboardResponse is the composed dashboard read: everything the library
// view renders, in one fetch, with the row model already enforced server-side —
// ONE ROW PER DOCUMENT CHAIN. A chain covered by an envelope is represented by
// that envelope and subtracted from the standalone list, so the browser can
// never render a document next to the envelope that contains it; and where
// several envelopes cover the same document, only the one that acted last
// survives, so signing a document repeatedly does not multiply its rows.
type dashboardResponse struct {
	// Tasks are the envelopes awaiting the user's signature as an invited signer.
	Tasks []clients.SigningTask `json:"tasks"`
	// Envelopes are the user's own envelopes (each carries its progress
	// projection and attached document ids), collapsed to the one that last
	// acted on each document.
	Envelopes []clients.Summary `json:"envelopes"`
	// Chains are the user's standalone document chains, each collapsed to its
	// single live head (the signed artifact where one exists, else the source).
	Chains []clients.ChainRow `json:"chains"`
}

// dashboard returns the composed library view: the signer inbox, the user's
// envelopes, and their standalone document chains. The chain rows come from the
// document service's chains view (one live head per chain), any chain an
// envelope covers is dropped in favor of that envelope's row, and the envelope
// rows are reduced to one per document.
//
// @operationId PortalDashboard
// @title Composed dashboard rows
// @route /api/portal/v1/dashboard [get].
func (r *router) dashboard(ctx *azugo.Context) {
	if !r.documentsReady(ctx) || !r.envelopeReady(ctx) {
		return
	}
	obo, ok := r.onBehalf(ctx)
	if !ok {
		return
	}

	tasks, err := r.Envelope().SigningTasks(ctx, obo, 0, "")
	if err != nil {
		r.relayErr(ctx, err)

		return
	}
	envs, err := r.Envelope().List(ctx, obo, 0, "")
	if err != nil {
		r.relayErr(ctx, err)

		return
	}
	chains, err := r.Documents().ListChains(ctx, obo, 0, "")
	if err != nil {
		r.relayErr(ctx, err)

		return
	}

	// Subtract envelope-covered chains: an attached document id is the chain's
	// root (documents are attached before any signing derives from them), but
	// match the head id too so a chain never double-renders.
	covered := map[string]bool{}
	for _, e := range envs.Envelopes {
		for _, id := range e.DocIDs {
			covered[id] = true
		}
	}
	// ...and the invited-signer envelopes too: a signing task covers the owner's
	// shared chain (readable by the invitee via the access grant made at send),
	// which must not render as the viewer's own standalone document while the
	// invitation is open.
	for _, tk := range tasks.Tasks {
		for _, id := range tk.Envelope.DocIDs {
			covered[id] = true
		}
	}
	standalone := make([]clients.ChainRow, 0, len(chains.Chains))
	for _, c := range chains.Chains {
		if covered[c.ChainRootID] || covered[c.ID] {
			continue
		}
		standalone = append(standalone, c)
	}

	out := dashboardResponse{
		Tasks:     tasks.Tasks,
		Envelopes: withRetention(latestPerChain(withoutDestroyedChains(envs.Envelopes, chains.Chains)), chains.Chains),
		Chains:    standalone,
	}
	if out.Tasks == nil {
		out.Tasks = []clients.SigningTask{}
	}
	if out.Envelopes == nil {
		out.Envelopes = []clients.Summary{}
	}
	ctx.JSON(&out)
}

// withoutDestroyedChains drops a TERMINAL envelope none of whose documents
// resolve in the live chain listing any more: retention has destroyed the
// storage and the durable record's home is history, so a live-looking row would
// only offer actions that answer 410 Gone. Three deliberate keeps, each earning
// its place: an envelope with no documents yet is a row in its own right (a
// draft being built); a NON-terminal envelope stays visible even over destroyed
// storage — what its owner should see in that window is an open product
// question, and silently hiding an in-flight workflow would answer it by
// accident; and when the chain listing is empty nothing is dropped, so a
// listing hiccup degrades to the old behaviour instead of an empty dashboard.
func withoutDestroyedChains(envs []clients.Summary, chains []clients.ChainRow) []clients.Summary {
	if len(envs) == 0 || len(chains) == 0 {
		return envs
	}

	// A chain is addressable by its root or its live head, same as the
	// subtraction and retention joins above.
	live := make(map[string]bool, len(chains)*2)
	for _, c := range chains {
		if c.ChainRootID != "" {
			live[c.ChainRootID] = true
		}
		if c.ID != "" {
			live[c.ID] = true
		}
	}

	terminal := map[string]bool{"completed": true, "declined": true, "cancelled": true, "expired": true}

	out := make([]clients.Summary, 0, len(envs))
	for _, e := range envs {
		if terminal[e.Status] && len(e.DocIDs) > 0 {
			resolved := false
			for _, doc := range e.DocIDs {
				if live[doc] {
					resolved = true

					break
				}
			}
			if !resolved {
				continue
			}
		}
		out = append(out, e)
	}

	return out
}

// withRetention stamps each envelope with the auto-delete instant of the SOONEST
// of its documents, taken from the chain listing this same read already fetched.
// The chain list is the FULL one, before envelope-covered chains are subtracted —
// which is the point: those are exactly the documents whose retention no other row
// is left to state.
//
// The soonest wins because it is the one that decides when the envelope stops
// being about anything. An envelope whose documents are all unknown here keeps the
// field empty rather than claiming an unbounded life.
func withRetention(envs []clients.Summary, chains []clients.ChainRow) []clients.Summary {
	if len(envs) == 0 || len(chains) == 0 {
		return envs
	}

	// A chain is addressable by its root or its live head; an envelope references
	// the root, but match both so a head-referencing envelope resolves too.
	until := make(map[string]time.Time, len(chains)*2)
	for _, c := range chains {
		if c.RetentionUntil.IsZero() {
			continue
		}
		for _, id := range []string{c.ChainRootID, c.ID} {
			if id == "" {
				continue
			}
			if cur, seen := until[id]; !seen || c.RetentionUntil.Before(cur) {
				until[id] = c.RetentionUntil
			}
		}
	}

	out := make([]clients.Summary, 0, len(envs))
	for _, e := range envs {
		var soonest time.Time
		for _, doc := range e.DocIDs {
			t, ok := until[doc]
			if !ok {
				continue
			}
			if soonest.IsZero() || t.Before(soonest) {
				soonest = t
			}
		}
		if !soonest.IsZero() {
			e.RetentionUntil = soonest.UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}

	return out
}

// latestPerChain keeps one envelope row per document chain: a document's row is
// the envelope that last acted on it, and any older envelope over the same
// document is dropped, so one document can never occupy several rows at once.
// Signing a document more than once would otherwise add a row each time while
// the document itself stays single.
//
// An envelope carrying several documents survives while it is the most recent
// for at least one of them — it is still that document's home, and dropping it
// would leave the document with no row at all. An envelope with nothing attached
// yet (created, not sent) is always kept: it is a row in its own right and there
// is no document to collapse it against.
//
// Input order is preserved, so the caller's ordering (most recently touched
// first) survives untouched.
func latestPerChain(envs []clients.Summary) []clients.Summary {
	home := make(map[string]clients.Summary, len(envs))
	for _, e := range envs {
		for _, doc := range e.DocIDs {
			if cur, seen := home[doc]; !seen || actedLater(e, cur) {
				home[doc] = e
			}
		}
	}

	keep := make(map[string]bool, len(home))
	for _, e := range home {
		keep[e.ID] = true
	}

	out := make([]clients.Summary, 0, len(envs))
	for _, e := range envs {
		if len(e.DocIDs) == 0 || keep[e.ID] {
			out = append(out, e)
		}
	}

	return out
}

// actedLater reports whether a was mutated more recently than b, falling back to
// the identifier so the choice is stable when two envelopes share a timestamp
// (identifiers are time-ordered, so the larger one was created later).
func actedLater(a, b clients.Summary) bool {
	if a.UpdatedAt != b.UpdatedAt {
		return a.UpdatedAt > b.UpdatedAt
	}

	return a.ID > b.ID
}
