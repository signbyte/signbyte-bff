package session

import (
	"context"
	"sync"
	"time"
)

// memoryStore is an in-process session store for development and tests. It does
// not survive a restart and does not scale past one instance.
type memoryStore struct {
	mu         sync.Mutex
	flows      map[string]entry
	sessions   map[string]entry
	sessionTTL time.Duration
	flowTTL    time.Duration
	now        func() time.Time
}

type entry struct {
	data    []byte
	expires time.Time
}

// NewMemory returns an in-memory session store.
func NewMemory(sessionTTL, flowTTL time.Duration) Store {
	return &memoryStore{
		flows:      make(map[string]entry),
		sessions:   make(map[string]entry),
		sessionTTL: sessionTTL,
		flowTTL:    flowTTL,
		now:        time.Now,
	}
}

func (s *memoryStore) PutFlow(_ context.Context, state string, f *Flow) error {
	b, err := encode(f)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.flows[state] = entry{data: b, expires: s.now().Add(s.flowTTL)}
	s.mu.Unlock()

	return nil
}

func (s *memoryStore) TakeFlow(_ context.Context, state string) (*Flow, error) {
	s.mu.Lock()
	e, ok := s.flows[state]
	delete(s.flows, state)
	s.mu.Unlock()

	if !ok || s.now().After(e.expires) {
		return nil, ErrNotFound
	}

	var f Flow
	if err := decode(e.data, &f); err != nil {
		return nil, err
	}

	return &f, nil
}

func (s *memoryStore) PutSession(_ context.Context, id string, sess *Session) error {
	b, err := encode(sess)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.sessions[id] = entry{data: b, expires: s.now().Add(s.sessionTTL)}
	s.mu.Unlock()

	return nil
}

func (s *memoryStore) GetSession(_ context.Context, id string) (*Session, error) {
	s.mu.Lock()
	e, ok := s.sessions[id]
	s.mu.Unlock()

	if !ok || s.now().After(e.expires) {
		return nil, ErrNotFound
	}

	var sess Session
	if err := decode(e.data, &sess); err != nil {
		return nil, err
	}

	return &sess, nil
}

func (s *memoryStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()

	return nil
}

func (s *memoryStore) Ping(_ context.Context) error { return nil }
