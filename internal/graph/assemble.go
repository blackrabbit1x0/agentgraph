package graph

import (
	"fmt"
	"sort"
)

// Assembler collects nodes and edges from multiple sources (YAML config,
// connectors) and builds a single graph. Edge endpoints may be declared in
// any order: validation happens once, at Build time. This lets a static
// config reference node IDs that a connector will discover later.
type Assembler struct {
	nodes map[string]*Node
	edges []*Edge
}

// NewAssembler returns an empty assembler.
func NewAssembler() *Assembler {
	return &Assembler{nodes: map[string]*Node{}}
}

// AddNode registers a node. Later registrations for the same ID update the
// existing node (connector metadata can enrich a config-declared node).
func (a *Assembler) AddNode(n *Node) error {
	if err := n.Validate(); err != nil {
		return err
	}
	cp := *n
	if existing, ok := a.nodes[n.ID]; ok {
		// Merge: non-zero fields on the new node win.
		if cp.Name != "" {
			existing.Name = cp.Name
		}
		if cp.Provider != "" {
			existing.Provider = cp.Provider
		}
		if cp.Criticality != 0 {
			existing.Criticality = cp.Criticality
		}
		if cp.CrownJewel {
			existing.CrownJewel = true
		}
		if cp.Type != existing.Type {
			return fmt.Errorf("node %q declared with conflicting types %s and %s", n.ID, existing.Type, n.Type)
		}
		for k, v := range cp.Metadata {
			if existing.Metadata == nil {
				existing.Metadata = map[string]any{}
			}
			existing.Metadata[k] = v
		}
		return nil
	}
	a.nodes[n.ID] = &cp
	return nil
}

// AddEdge registers an edge for deferred validation.
func (a *Assembler) AddEdge(e *Edge) {
	cp := *e
	a.edges = append(a.edges, &cp)
}

// Build validates all collected relationships and constructs the graph.
func (a *Assembler) Build() (*Graph, error) {
	g := New()
	ids := make([]string, 0, len(a.nodes))
	for id := range a.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := g.AddNode(a.nodes[id]); err != nil {
			return nil, err
		}
	}
	sorted := make([]*Edge, len(a.edges))
	copy(sorted, a.edges)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Source != sorted[j].Source {
			return sorted[i].Source < sorted[j].Source
		}
		if sorted[i].Target != sorted[j].Target {
			return sorted[i].Target < sorted[j].Target
		}
		return sorted[i].Type < sorted[j].Type
	})
	for _, e := range sorted {
		if err := g.AddEdge(e); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// NodeCount returns the number of distinct nodes registered so far.
func (a *Assembler) NodeCount() int { return len(a.nodes) }

// EdgeCount returns the number of edges registered so far.
func (a *Assembler) EdgeCount() int { return len(a.edges) }
