package session

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisStore is the production session store, backed by Redis so sessions survive
// restarts and are shared across instances.
type redisStore struct {
	c          redis.UniversalClient
	sessionTTL time.Duration
	flowTTL    time.Duration
}

// NewRedis returns a Redis-backed session store.
func NewRedis(c redis.UniversalClient, sessionTTL, flowTTL time.Duration) Store {
	return &redisStore{c: c, sessionTTL: sessionTTL, flowTTL: flowTTL}
}

func flowKey(state string) string { return "portal:flow:" + state }
func sessKey(id string) string    { return "portal:sess:" + id }

func (s *redisStore) PutFlow(ctx context.Context, state string, f *Flow) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}

	return s.c.Set(ctx, flowKey(state), b, s.flowTTL).Err()
}

func (s *redisStore) TakeFlow(ctx context.Context, state string) (*Flow, error) {
	b, err := s.c.GetDel(ctx, flowKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var f Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	return &f, nil
}

func (s *redisStore) PutSession(ctx context.Context, id string, sess *Session) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}

	return s.c.Set(ctx, sessKey(id), b, s.sessionTTL).Err()
}

func (s *redisStore) GetSession(ctx context.Context, id string) (*Session, error) {
	b, err := s.c.Get(ctx, sessKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, err
	}

	return &sess, nil
}

func (s *redisStore) DeleteSession(ctx context.Context, id string) error {
	return s.c.Del(ctx, sessKey(id)).Err()
}

func (s *redisStore) Ping(ctx context.Context) error {
	return s.c.Ping(ctx).Err()
}
