// Package store defines the graph persistence abstraction (PRD section
// 30). The in-memory graph remains the default; a Neo4j-backed store
// provides durable, queryable storage for teams that want to keep
// graphs long-term or query them with Cypher.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Store persists and loads graph snapshots.
type Store interface {
	// Name identifies the backend ("memory", "neo4j").
	Name() string
	// Save persists a complete graph snapshot, replacing any previous
	// content with the same key.
	Save(ctx context.Context, key string, g *graph.Graph) error
	// Load reads a graph snapshot by key. Returns an error matching
	// ErrNotFound when the key is unknown.
	Load(ctx context.Context, key string) (*graph.Graph, error)
	// Close releases backend resources.
	Close() error
}

// ErrNotFound is returned by Load for unknown keys.
var ErrNotFound = errors.New("snapshot not found")

// IsNotFound reports whether err is (or wraps) ErrNotFound.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// MemoryStore keeps snapshots in process memory. Useful for tests and
// as the default no-op backend.
type MemoryStore struct {
	snapshots map[string]*graph.Graph
}

// NewMemoryStore returns an empty memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{snapshots: map[string]*graph.Graph{}}
}

// Name implements Store.
func (m *MemoryStore) Name() string { return "memory" }

// Save implements Store.
func (m *MemoryStore) Save(_ context.Context, key string, g *graph.Graph) error {
	m.snapshots[key] = g.Clone()
	return nil
}

// Load implements Store.
func (m *MemoryStore) Load(_ context.Context, key string) (*graph.Graph, error) {
	g, ok := m.snapshots[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return g.Clone(), nil
}

// Close implements Store.
func (m *MemoryStore) Close() error { return nil }
