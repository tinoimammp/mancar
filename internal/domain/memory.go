package domain

import (
	"context"
	"sync"
	"time"
)

type memEntry struct {
	owner     string
	kind      string
	tunnelID  string // empty when inactive
	holdUntil time.Time
}

// MemoryRegistry is an in-process Registry used by tests and development
// mode. It follows exactly the same rules as the PostgreSQL implementation.
type MemoryRegistry struct {
	mu      sync.Mutex
	entries map[string]*memEntry
	// Now is the clock; replace it in tests to simulate hold expiry.
	Now func() time.Time
}

// NewMemoryRegistry returns an empty registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{entries: map[string]*memEntry{}, Now: time.Now}
}

// Claim implements Registry.
func (m *MemoryRegistry) Claim(_ context.Context, c Claim) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	e, ok := m.entries[c.Hostname]
	if !ok {
		m.entries[c.Hostname] = &memEntry{owner: c.OwnerID, kind: c.Kind, tunnelID: c.TunnelID, holdUntil: now}
		return c.Kind, nil
	}
	if e.tunnelID != "" {
		return "", ErrHostnameTaken
	}
	held := e.holdUntil.After(now)
	if e.owner != c.OwnerID && held {
		return "", ErrHostnameTaken
	}
	kind := c.Kind
	if e.owner == c.OwnerID && held {
		kind = e.kind
	}
	*e = memEntry{owner: c.OwnerID, kind: kind, tunnelID: c.TunnelID, holdUntil: now}
	return kind, nil
}

// Release implements Registry.
func (m *MemoryRegistry) Release(_ context.Context, hostname, tunnelID string, hold time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[hostname]; ok && e.tunnelID == tunnelID {
		e.tunnelID = ""
		e.holdUntil = m.Now().Add(hold)
	}
	return nil
}

// ReleaseAll implements Registry.
func (m *MemoryRegistry) ReleaseAll(_ context.Context, hold time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.tunnelID != "" {
			e.tunnelID = ""
			e.holdUntil = m.Now().Add(hold)
		}
	}
	return nil
}

// Purge implements Registry.
func (m *MemoryRegistry) Purge(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	for h, e := range m.entries {
		if e.tunnelID == "" && !e.holdUntil.After(now) {
			delete(m.entries, h)
		}
	}
	return nil
}

// Len reports the number of stored reservations (tests).
func (m *MemoryRegistry) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
