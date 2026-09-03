// Package diff implements snapshot comparison: which nodes, edges, and
// attack paths were added or removed between two graph snapshots, with
// attribution of what introduced each new path (PRD sections 43-44).
package diff

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// Change is one added or removed element.
type Change[T any] struct {
	Item T
}

// Report is the full diff between two snapshots.
type Report struct {
	// AddedNodes are nodes present only in the new snapshot.
	AddedNodes []*graph.Node
	// RemovedNodes are nodes present only in the old snapshot.
	RemovedNodes []*graph.Node
	// AddedEdges are edges present only in the new snapshot.
	AddedEdges []*graph.Edge
	// RemovedEdges are edges present only in the old snapshot.
	RemovedEdges []*graph.Edge
	// NewPaths are attack paths present only in the new snapshot.
	NewPaths []*PathSummary
	// GonePaths are attack paths present only in the old snapshot.
	GonePaths []*PathSummary
}

// PathSummary captures the identity of a path without holding the whole
// graph: its node chain and edge types.
type PathSummary struct {
	SourceID   string
	TargetID   string
	NodeChain  []string
	EdgeTypes  []string
	Confidence float64
}

// PathKey is the comparable identity of an attack path.
type PathKey struct {
	Chain string
}

// Key returns the comparable identity of a path.
func Summarize(p *paths.Path) *PathSummary {
	s := &PathSummary{
		SourceID:   p.Source.ID,
		TargetID:   p.Target.ID,
		Confidence: p.Confidence,
	}
	for _, n := range p.Nodes() {
		s.NodeChain = append(s.NodeChain, n.ID)
	}
	for _, e := range p.Edges() {
		s.EdgeTypes = append(s.EdgeTypes, string(e.Type))
	}
	return s
}

// key builds the dedup identity: node chain plus edge types.
func key(s *PathSummary) PathKey {
	k := ""
	for i, n := range s.NodeChain {
		if i > 0 {
			k += "|" + s.EdgeTypes[i-1] + "|"
		}
		k += n
	}
	return PathKey{Chain: k}
}

// String renders a path summary in arrow notation.
func (s *PathSummary) String() string {
	out := s.NodeChain[0]
	for i := 1; i < len(s.NodeChain); i++ {
		out += fmt.Sprintf(" --%s--> %s", s.EdgeTypes[i-1], s.NodeChain[i])
	}
	return out
}

// edgeKey identifies an edge by source, type, and target.
type edgeKey struct {
	source, typ, target string
}

func edgeKeyOf(e *graph.Edge) edgeKey {
	return edgeKey{e.Source, string(e.Type), e.Target}
}

// Compute compares two snapshots. Paths are enumerated from every AI
// agent with a raised MaxPaths cap: a diff built from truncated path
// sets could otherwise report spurious new/gone paths. Truncation is
// surfaced in the returned error when it occurs.
func Compute(oldG, newG *graph.Graph) (*Report, error) {
	r := &Report{}

	diffOpts := paths.Options{MaxPaths: 100000}

	// Node diff.
	oldNodes := map[string]bool{}
	for _, n := range oldG.Nodes() {
		oldNodes[n.ID] = true
	}
	newNodes := map[string]bool{}
	for _, n := range newG.Nodes() {
		newNodes[n.ID] = true
		if !oldNodes[n.ID] {
			r.AddedNodes = append(r.AddedNodes, n)
		}
	}
	for _, n := range oldG.Nodes() {
		if !newNodes[n.ID] {
			r.RemovedNodes = append(r.RemovedNodes, n)
		}
	}

	// Edge diff.
	oldEdges := map[edgeKey]*graph.Edge{}
	for _, e := range oldG.Edges() {
		oldEdges[edgeKeyOf(e)] = e
	}
	newEdges := map[edgeKey]*graph.Edge{}
	for _, e := range newG.Edges() {
		newEdges[edgeKeyOf(e)] = e
		if _, ok := oldEdges[edgeKeyOf(e)]; !ok {
			r.AddedEdges = append(r.AddedEdges, e)
		}
	}
	for k, e := range oldEdges {
		if _, ok := newEdges[k]; !ok {
			r.RemovedEdges = append(r.RemovedEdges, e)
		}
	}

	// Path set diff.
	oldPaths, err := paths.EnumerateAll(oldG, diffOpts)
	if err != nil {
		return nil, err
	}
	newPaths, err := paths.EnumerateAll(newG, diffOpts)
	if err != nil {
		return nil, err
	}

	oldKeys := map[PathKey]bool{}
	for _, p := range oldPaths {
		oldKeys[key(Summarize(p))] = true
	}
	newKeys := map[PathKey]bool{}
	for _, p := range newPaths {
		k := key(Summarize(p))
		newKeys[k] = true
		if !oldKeys[k] {
			r.NewPaths = append(r.NewPaths, Summarize(p))
		}
	}
	for _, p := range oldPaths {
		if k := key(Summarize(p)); !newKeys[k] {
			r.GonePaths = append(r.GonePaths, Summarize(p))
		}
	}

	sort.Slice(r.AddedNodes, func(i, j int) bool { return r.AddedNodes[i].ID < r.AddedNodes[j].ID })
	sort.Slice(r.RemovedNodes, func(i, j int) bool { return r.RemovedNodes[i].ID < r.RemovedNodes[j].ID })
	sortEdges(r.AddedEdges)
	sortEdges(r.RemovedEdges)
	sortPaths(r.NewPaths)
	sortPaths(r.GonePaths)
	return r, nil
}

func sortEdges(es []*graph.Edge) {
	sort.Slice(es, func(i, j int) bool {
		a, b := edgeKeyOf(es[i]), edgeKeyOf(es[j])
		if a.source != b.source {
			return a.source < b.source
		}
		if a.target != b.target {
			return a.target < b.target
		}
		return a.typ < b.typ
	})
}

func sortPaths(ps []*PathSummary) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].SourceID != ps[j].SourceID {
			return ps[i].SourceID < ps[j].SourceID
		}
		if ps[i].TargetID != ps[j].TargetID {
			return ps[i].TargetID < ps[j].TargetID
		}
		return ps[i].String() < ps[j].String()
	})
}

// Attribution explains which structural change most likely introduced a
// new path: the added edge(s) that the path traverses. Returns the best
// single edge plus all matching added edges.
func (r *Report) Attribution(p *PathSummary) []*graph.Edge {
	var matches []*graph.Edge
	for _, e := range r.AddedEdges {
		// Does this path traverse the edge?
		for i := 1; i < len(p.NodeChain); i++ {
			if p.NodeChain[i-1] == e.Source && p.NodeChain[i] == e.Target &&
				p.EdgeTypes[i-1] == string(e.Type) {
				matches = append(matches, e)
				break
			}
		}
	}
	return matches
}

// IsEmpty reports whether the snapshots are graph-identical.
func (r *Report) IsEmpty() bool {
	return len(r.AddedNodes) == 0 && len(r.RemovedNodes) == 0 &&
		len(r.AddedEdges) == 0 && len(r.RemovedEdges) == 0 &&
		len(r.NewPaths) == 0 && len(r.GonePaths) == 0
}
