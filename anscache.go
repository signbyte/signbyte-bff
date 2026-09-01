package portalapi

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// AnswerCache is the short-TTL render-recent cache for validation answers: an
// answer that just passed through this service (a post-sign validation fetch,
// a doc-scoped validate) is served again without re-running the full upstream
// validation round, which legitimately takes tens of seconds. It is explicitly
// NOT a persisted read path — entries expire in minutes, and an explicit
// re-validate bypasses it. Keys are scoped per user + target by the caller, so
// a cached answer can never cross users (that would bypass the downstream
// ownership check). Values are opaque serialized answers.
type AnswerCache interface {
	// Get returns the cached answer for key, or nil.
	Get(ctx context.Context, key string) []byte
	// Set stores val under key for the cache's TTL. Best-effort: a failed
	// store is a slower next fetch, never an error.
	Set(ctx context.Context, key string, val []byte)
}

// redisAnswerCache backs the cache with the session Redis (already present on
// this service) so instances share it.
type redisAnswerCache struct {
	rc  redis.UniversalClient
	ttl time.Duration
}

func (c *redisAnswerCache) Get(ctx context.Context, key string) []byte {
	b, err := c.rc.Get(ctx, key).Bytes()
	if err != nil {
		return nil
	}

	return b
}

func (c *redisAnswerCache) Set(ctx context.Context, key string, val []byte) {
	_ = c.rc.Set(ctx, key, val, c.ttl).Err()
}

// memoryAnswerCache is the in-process fallback (development/test — no Redis;
// like the in-memory session store it does not survive restarts or scale past
// one instance, which is fine for a cache).
type memoryAnswerCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]memoryAnswerEntry
}

type memoryAnswerEntry struct {
	val []byte
	exp time.Time
}

func newMemoryAnswerCache(ttl time.Duration) *memoryAnswerCache {
	return &memoryAnswerCache{ttl: ttl, m: make(map[string]memoryAnswerEntry)}
}

func (c *memoryAnswerCache) Get(_ context.Context, key string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.m[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.exp) {
		delete(c.m, key)

		return nil
	}

	return e.val
}

func (c *memoryAnswerCache) Set(_ context.Context, key string, val []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Opportunistically drop expired entries so the map tracks live keys.
	now := time.Now()
	for k, e := range c.m {
		if now.After(e.exp) {
			delete(c.m, k)
		}
	}
	c.m[key] = memoryAnswerEntry{val: val, exp: now.Add(c.ttl)}
}
