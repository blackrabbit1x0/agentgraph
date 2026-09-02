package graph

import (
	"fmt"
	"sort"
)

// Graph is an in-memory directed multigraph with adjacency indexes.
// It is safe for read-only concurrent use after construction.
type Graph struct {
	nodes map[string]*Node
	edges []*Edge

	// out[source][target] holds all edges from source to target.
	out map[string]map[string][]*Edge
	// in[target][source] holds all edges from source to target.
	in map[string]map[string][]*Edge
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]*Node{},
		out:   map[string]map[string][]*Edge{},
		in:    map[string]map[string][]*Edge{},
	}
}

// AddNode inserts a node. Adding a duplicate ID returns an error to
// prevent silent overwrites between connectors.
func (g *Graph) AddNode(n *Node) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if _, exists := g.nodes[n.ID]; exists {
		return fmt.Errorf("node %q already exists", n.ID)
	}
	cp := *n
	g.nodes[n.ID] = &cp
	return nil
}

// UpsertNode inserts a node or replaces an existing one with the same ID.
func (g *Graph) UpsertNode(n *Node) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if _, exists := g.nodes[n.ID]; exists {
		g.removeNodeEdges(n.ID)
	}
	cp := *n
	g.nodes[n.ID] = &cp
	return nil
}

// AddEdge validates and inserts an edge. Both endpoints must already exist.
// Duplicate edges (same source, target, and type) are ignored so that
// repeated connector runs are idempotent.
func (g *Graph) AddEdge(e *Edge) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if _, ok := g.nodes[e.Source]; !ok {
		return fmt.Errorf("edge references unknown source node %q", e.Source)
	}
	if _, ok := g.nodes[e.Target]; !ok {
		return fmt.Errorf("edge references unknown target node %q", e.Target)
	}
	for _, existing := range g.out[e.Source][e.Target] {
		if existing.Type == e.Type {
			return nil
		}
	}
	cp := *e
	g.edges = append(g.edges, &cp)
	if g.out[e.Source] == nil {
		g.out[e.Source] = map[string][]*Edge{}
	}
	g.out[e.Source][e.Target] = append(g.out[e.Source][e.Target], &cp)
	if g.in[e.Target] == nil {
		g.in[e.Target] = map[string][]*Edge{}
	}
	g.in[e.Target][e.Source] = append(g.in[e.Target][e.Source], &cp)
	return nil
}

func (g *Graph) removeNodeEdges(id string) {
	for _, e := range g.edges {
		if e.Source != id && e.Target != id {
			continue
		}
		g.unlink(e)
	}
	kept := g.edges[:0]
	for _, e := range g.edges {
		if e.Source != id && e.Target != id {
			kept = append(kept, e)
		}
	}
	g.edges = kept
}

func (g *Graph) unlink(e *Edge) {
	if _, ok := g.out[e.Source]; ok {
		g.out[e.Source][e.Target] = removeEdge(g.out[e.Source][e.Target], e)
		if len(g.out[e.Source][e.Target]) == 0 {
			delete(g.out[e.Source], e.Target)
		}
		if len(g.out[e.Source]) == 0 {
			delete(g.out, e.Source)
		}
	}
	if _, ok := g.in[e.Target]; ok {
		g.in[e.Target][e.Source] = removeEdge(g.in[e.Target][e.Source], e)
		if len(g.in[e.Target][e.Source]) == 0 {
			delete(g.in[e.Target], e.Source)
		}
		if len(g.in[e.Target]) == 0 {
			delete(g.in, e.Target)
		}
	}
}

func removeEdge(list []*Edge, e *Edge) []*Edge {
	for i, x := range list {
		if x == e {
			return append(list[:i:i], list[i+1:]...)
		}
	}
	return list
}

// Node returns the node with the given ID.
func (g *Graph) Node(id string) (*Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Nodes returns all nodes sorted by ID for deterministic output.
func (g *Graph) Nodes() []*Node {
	out := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// NodesByType returns all nodes of a given type sorted by ID.
func (g *Graph) NodesByType(t NodeType) []*Node {
	var out []*Node
	for _, n := range g.nodes {
		if n.Type == t {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Edges returns all edges in insertion order.
func (g *Graph) Edges() []*Edge {
	out := make([]*Edge, len(g.edges))
	copy(out, g.edges)
	return out
}

// EdgeCount returns the number of edges.
func (g *Graph) EdgeCount() int { return len(g.edges) }

// NodeCount returns the number of nodes.
func (g *Graph) NodeCount() int { return len(g.nodes) }

// OutEdges returns all edges leaving a node.
func (g *Graph) OutEdges(id string) []*Edge {
	var out []*Edge
	for _, tgts := range g.out[id] {
		out = append(out, tgts...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// InEdges returns all edges entering a node.
func (g *Graph) InEdges(id string) []*Edge {
	var out []*Edge
	for _, srcs := range g.in[id] {
		out = append(out, srcs...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// EdgeBetween returns the edges from source to target, if any.
func (g *Graph) EdgeBetween(source, target string) []*Edge {
	edges := g.out[source][target]
	out := make([]*Edge, len(edges))
	copy(out, edges)
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// RemoveEdge removes the edge from source to target with the given type.
func (g *Graph) RemoveEdge(source, target string, t EdgeType) {
	for _, e := range g.out[source][target] {
		if e.Type == t {
			g.unlink(e)
			kept := g.edges[:0]
			for _, x := range g.edges {
				if x != e {
					kept = append(kept, x)
				}
			}
			g.edges = kept
			return
		}
	}
}

// HasEdge reports whether an edge of the given type exists.
func (g *Graph) HasEdge(source, target string, t EdgeType) bool {
	for _, e := range g.out[source][target] {
		if e.Type == t {
			return true
		}
	}
	return false
}
