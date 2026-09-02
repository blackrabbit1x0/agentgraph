package graph

import (
	"encoding/json"
	"fmt"
	"os"
)

// Snapshot is the JSON representation of a complete graph, used for
// --save/--graph persistence and the web API.
type Snapshot struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// Snapshot returns the graph in serializable form.
func (g *Graph) Snapshot() *Snapshot {
	return &Snapshot{
		Nodes: g.Nodes(),
		Edges: g.Edges(),
	}
}

// MarshalJSON renders the graph as a snapshot.
func (g *Graph) MarshalJSON() ([]byte, error) {
	return json.Marshal(g.Snapshot())
}

// FromSnapshot builds a graph from a snapshot.
func FromSnapshot(s *Snapshot) (*Graph, error) {
	g := New()
	for _, n := range s.Nodes {
		if err := g.AddNode(n); err != nil {
			return nil, err
		}
	}
	for _, e := range s.Edges {
		if err := g.AddEdge(e); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// SaveSnapshotFile writes the graph to a JSON file.
func SaveSnapshotFile(g *Graph, path string) error {
	data, err := json.MarshalIndent(g.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadSnapshotFile reads a graph from a JSON file.
func LoadSnapshotFile(path string) (*Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	return FromSnapshot(&s)
}
