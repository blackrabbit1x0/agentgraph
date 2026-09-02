// Package paths implements attack-path enumeration and shortest-path
// search over the AgentGraph graph model.
package paths

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// DefaultMaxDepth is the default maximum attack-path depth (PRD section 38).
const DefaultMaxDepth = 10

// DefaultMaxPaths caps enumerated paths to protect against graph explosion.
const DefaultMaxPaths = 1000

// Options controls path enumeration constraints.
type Options struct {
	// MaxDepth is the maximum number of edges in a path.
	MaxDepth int
	// MinConfidence excludes edges below this confidence (0-1).
	MinConfidence float64
	// MaxPaths caps the number of returned paths (0 = DefaultMaxPaths).
	MaxPaths int
	// TargetID restricts results to paths ending at this node ID.
	TargetID string
	// TargetSubstring matches target node ID or name (case-insensitive).
	TargetSubstring string
	// CrownJewelsOnly restricts results to paths ending at crown jewels.
	CrownJewelsOnly bool
	// EdgeTypes is an optional allowlist of edge types.
	EdgeTypes map[graph.EdgeType]bool
}

func (o *Options) normalize() {
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.MaxPaths <= 0 {
		o.MaxPaths = DefaultMaxPaths
	}
	if o.MinConfidence < 0 {
		o.MinConfidence = 0
	}
}

// Step is one hop in a path: the edge taken and the node reached.
type Step struct {
	Edge *graph.Edge
	Node *graph.Node
}

// Path is a single attack path from a source node to a target node.
type Path struct {
	ID     string
	Source *graph.Node
	Target *graph.Node
	Steps  []Step // target is Steps[len-1].Node
	// Confidence is the product of all edge confidences.
	Confidence float64
}

// Length returns the number of edges (hops) in the path.
func (p *Path) Length() int { return len(p.Steps) }

// Nodes returns the full node sequence, source first.
func (p *Path) Nodes() []*graph.Node {
	out := make([]*graph.Node, 0, len(p.Steps)+1)
	out = append(out, p.Source)
	for _, s := range p.Steps {
		out = append(out, s.Node)
	}
	return out
}

// Edges returns the edge sequence.
func (p *Path) Edges() []*graph.Edge {
	out := make([]*graph.Edge, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, s.Edge)
	}
	return out
}

// terminalExcluded are node types that are traversal points rather than
// meaningful attack-path targets.
var terminalExcluded = map[graph.NodeType]bool{
	graph.NodeTool:      true,
	graph.NodeMCPServer: true,
}

// IsTerminal reports whether a node is a valid attack-path target.
func IsTerminal(n *graph.Node) bool {
	return !terminalExcluded[n.Type]
}

// matchesTarget reports whether node n satisfies the target filters.
func (o *Options) matchesTarget(n *graph.Node) bool {
	if o.TargetID != "" {
		return n.ID == o.TargetID
	}
	if o.TargetSubstring != "" {
		return containsFold(n.ID, o.TargetSubstring) || containsFold(n.Name, o.TargetSubstring)
	}
	if o.CrownJewelsOnly {
		return n.CrownJewel
	}
	return true
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 || len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// TruncatedError is returned when enumeration hits the MaxPaths cap.
// Partial results are returned alongside it.
type TruncatedError struct{ Found int }

func (e *TruncatedError) Error() string {
	return fmt.Sprintf("path enumeration truncated at %d paths", e.Found)
}

// Enumerate finds all attack paths from source subject to the options.
// Paths are simple (no repeated nodes), which prevents meaningless loops
// such as Agent -> Tool -> Agent -> Tool. Results are deterministically
// ordered and assigned IDs of the form PATH-0001.
func Enumerate(g *graph.Graph, source string, opts Options) ([]*Path, error) {
	opts.normalize()
	src, ok := g.Node(source)
	if !ok {
		return nil, fmt.Errorf("unknown node %q", source)
	}

	var results []*Path
	truncated := false
	visited := map[string]bool{source: true}

	var dfs func(current *graph.Node, steps []Step, confidence float64)
	dfs = func(current *graph.Node, steps []Step, confidence float64) {
		if truncated {
			return
		}
		if len(steps) > 0 && IsTerminal(current) && opts.matchesTarget(current) {
			results = append(results, &Path{
				Source:     src,
				Target:     current,
				Steps:      append([]Step(nil), steps...),
				Confidence: confidence,
			})
			if len(results) >= opts.MaxPaths {
				truncated = true
				return
			}
		}
		if len(steps) >= opts.MaxDepth {
			return
		}
		for _, e := range g.OutEdges(current.ID) {
			if truncated {
				return
			}
			if opts.EdgeTypes != nil && !opts.EdgeTypes[e.Type] {
				continue
			}
			if e.Confidence < opts.MinConfidence {
				continue
			}
			if visited[e.Target] {
				continue
			}
			target, ok := g.Node(e.Target)
			if !ok {
				continue
			}
			visited[e.Target] = true
			dfs(target, append(steps, Step{Edge: e, Node: target}), confidence*e.Confidence)
			visited[e.Target] = false
		}
	}
	dfs(src, nil, 1.0)

	sortPaths(results)
	assignIDs(results)
	if truncated {
		return results, &TruncatedError{Found: len(results)}
	}
	return results, nil
}

// EnumerateAll enumerates paths from every AI agent in the graph.
// IDs are assigned across the combined, deterministically sorted result.
func EnumerateAll(g *graph.Graph, opts Options) ([]*Path, error) {
	opts.normalize()
	var all []*Path
	for _, agent := range g.NodesByType(graph.NodeAIAgent) {
		ps, err := Enumerate(g, agent.ID, Options{
			MaxDepth:        opts.MaxDepth,
			MinConfidence:   opts.MinConfidence,
			MaxPaths:        opts.MaxPaths,
			TargetID:        opts.TargetID,
			TargetSubstring: opts.TargetSubstring,
			CrownJewelsOnly: opts.CrownJewelsOnly,
			EdgeTypes:       opts.EdgeTypes,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, ps...)
	}
	sortPaths(all)
	assignIDs(all)
	return all, nil
}

func sortPaths(ps []*Path) {
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Source.ID != b.Source.ID {
			return a.Source.ID < b.Source.ID
		}
		if a.Target.ID != b.Target.ID {
			return a.Target.ID < b.Target.ID
		}
		if a.Length() != b.Length() {
			return a.Length() < b.Length()
		}
		for k := range a.Steps {
			if a.Steps[k].Edge.Target != b.Steps[k].Edge.Target {
				return a.Steps[k].Edge.Target < b.Steps[k].Edge.Target
			}
			if a.Steps[k].Edge.Type != b.Steps[k].Edge.Type {
				return a.Steps[k].Edge.Type < b.Steps[k].Edge.Type
			}
		}
		return false
	})
}

func assignIDs(ps []*Path) {
	for i, p := range ps {
		p.ID = fmt.Sprintf("PATH-%04d", i+1)
	}
}
