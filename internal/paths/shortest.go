package paths

import (
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Shortest returns the shortest path (fewest hops) from source to a target
// matching the spec, using breadth-first search. Target resolution:
// if targetSpec exactly matches a node ID, that node is used; otherwise
// the spec is matched case-insensitively as a substring of node ID or name.
// Returns nil if no target matches or no path exists.
func Shortest(g *graph.Graph, source, targetSpec string) *Path {
	if _, ok := g.Node(source); !ok {
		return nil
	}
	target := resolveTarget(g, targetSpec)
	if target == "" {
		return nil
	}
	return bfs(g, source, target)
}

// ShortestToPredicate returns the shortest path from source to any node
// for which match returns true.
func ShortestToPredicate(g *graph.Graph, source string, match func(*graph.Node) bool) *Path {
	if _, ok := g.Node(source); !ok {
		return nil
	}
	var best *Path
	for _, n := range g.Nodes() {
		if !match(n) {
			continue
		}
		p := bfs(g, source, n.ID)
		if p == nil {
			continue
		}
		if best == nil || p.Length() < best.Length() {
			best = p
		}
	}
	return best
}

func resolveTarget(g *graph.Graph, spec string) string {
	if spec == "" {
		return ""
	}
	if _, ok := g.Node(spec); ok {
		return spec
	}
	for _, n := range g.Nodes() {
		if containsFold(n.ID, spec) || containsFold(n.Name, spec) {
			return n.ID
		}
	}
	return ""
}

// bfs finds the shortest hop path from source to target. Ties are broken
// deterministically by iterating OutEdges in sorted order.
func bfs(g *graph.Graph, source, target string) *Path {
	src, _ := g.Node(source)
	tgt, _ := g.Node(target)

	type frontier struct {
		node  *graph.Node
		steps []Step
	}
	visited := map[string]bool{source: true}
	queue := []frontier{{node: src}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.node.ID == target {
			return &Path{
				Source:     src,
				Target:     tgt,
				Steps:      cur.steps,
				Confidence: pathConfidence(cur.steps),
			}
		}
		for _, e := range g.OutEdges(cur.node.ID) {
			if visited[e.Target] {
				continue
			}
			n, ok := g.Node(e.Target)
			if !ok {
				continue
			}
			visited[e.Target] = true
			queue = append(queue, frontier{
				node:  n,
				steps: append(append([]Step(nil), cur.steps...), Step{Edge: e, Node: n}),
			})
		}
	}
	return nil
}

func pathConfidence(steps []Step) float64 {
	c := 1.0
	for _, s := range steps {
		c *= s.Edge.Confidence
	}
	return c
}

// Describe renders a path in the arrow notation used throughout the PRD,
// e.g. "finance-agent -USES-> github-mcp -CAN_WRITE-> payments-repository".
func Describe(p *Path) string {
	if p == nil {
		return ""
	}
	s := p.Source.ID
	for _, step := range p.Steps {
		s += fmt.Sprintf(" --%s--> %s", step.Edge.Type, step.Node.ID)
	}
	return s
}
