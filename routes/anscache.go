package routes

import (
	"encoding/json"

	"azugo.io/azugo"
)

// The render-recent answer path: a validation answer that just passed through
// this service is served again from the short-TTL cache instead of re-running
// the full upstream validation round (tens of seconds for long-term-archival
// material). Keys are scoped per user + target so a cached answer can never
// cross users; `?force=1` (the explicit re-validate) bypasses the cache and
// refreshes it; every answer carries its validatedAt, so a cached verdict is
// rendered "as of" that moment, never as current.

// answerKey builds the per-user, per-target cache key.
func answerKey(sub, kind, id string) string {
	return "va:" + sub + ":" + kind + ":" + id
}

// forceRequested reports whether the caller explicitly asked for a fresh
// validation round (?force=1).
func forceRequested(ctx *azugo.Context) bool {
	f, err := ctx.Query.BoolOptional("force")

	return err == nil && f != nil && *f
}

// serveCachedAnswer writes the cached answer for key when one exists and the
// caller did not force a fresh round; it reports whether the response was
// served.
func (r *router) serveCachedAnswer(ctx *azugo.Context, key string) bool {
	c := r.AnswerCache()
	if c == nil || forceRequested(ctx) {
		return false
	}
	b := c.Get(ctx, key)
	if b == nil {
		return false
	}

	ctx.ContentType("application/json")
	ctx.Raw(b)

	return true
}

// storeAnswer refreshes the cache with a just-produced answer (best-effort).
func (r *router) storeAnswer(ctx *azugo.Context, key string, v any) {
	c := r.AnswerCache()
	if c == nil {
		return
	}
	if b, err := json.Marshal(v); err == nil {
		c.Set(ctx, key, b)
	}
}
