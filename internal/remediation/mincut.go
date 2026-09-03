package remediation

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// CutResult is a minimum cut between one agent and one target.
type CutResult struct {
	Agent  string
	Target string
	// CutEdges is the minimum set of edges to remove to disconnect
	// agent from target. When parallel relationship types connect a cut
	// node pair, all of them are included (removing one is not enough).
	CutEdges []*graph.Edge
	// PathsConsidered is the number of enumerated attack paths used to
	// weight edge capacity.
	PathsConsidered int
	// Truncated is true when path enumeration hit the MaxPaths cap; the
	// cut is then computed from a partial path set.
	Truncated bool
}

// Mincut computes a small edge cut separating agent from target using
// max-flow (Edmonds-Karp):
//
//   - every graph edge becomes a capacity edge; capacity is the number
//     of enumerated attack paths traversing it (minimum 1)
//   - max flow agent -> target is computed on the residual network
//   - the minimum cut is the set of saturated edges between the
//     residual-reachable set and its complement
//
// The result is deterministic. When no path exists the cut is empty.
func Mincut(g *graph.Graph, agentID, targetID string, opts paths.Options) (*CutResult, error) {
	if _, ok := g.Node(agentID); !ok {
		return nil, fmt.Errorf("unknown node %q", agentID)
	}
	tgt, ok := g.Node(targetID)
	if !ok {
		return nil, fmt.Errorf("unknown node %q", targetID)
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = paths.DefaultMaxDepth
	}
	opts.TargetID = targetID

	ps, enumErr := paths.Enumerate(g, agentID, opts)
	truncated := enumErr != nil

	// Edge usage counts across enumerated paths (weights capacity).
	type edgeID struct{ src, tgt, typ string }
	usage := map[edgeID]int{}
	for _, p := range ps {
		for _, e := range p.Edges() {
			usage[edgeID{e.Source, e.Target, string(e.Type)}]++
		}
	}

	// Flow network adjacency. Parallel graph edges are aggregated per
	// node pair so the network stays small and the cut picks the
	// highest-usage edge when several exist.
	type netEdge struct {
		to   string
		cap  int
		rev  int // index of reverse edge in net[to]
		orig *graph.Edge
	}
	net := map[string][]*netEdge{}

	pairCap := map[[2]string]int{}
	pairBest := map[[2]string]*graph.Edge{}
	for _, e := range g.Edges() {
		pair := [2]string{e.Source, e.Target}
		id := edgeID{e.Source, e.Target, string(e.Type)}
		pairCap[pair] += max(1, usage[id])
		if best, ok := pairBest[pair]; !ok || usage[id] > usage[edgeID{best.Source, best.Target, string(best.Type)}] {
			pairBest[pair] = e
		}
	}
	for pair, cap := range pairCap {
		a := &netEdge{to: pair[1], cap: cap}
		b := &netEdge{to: pair[0], cap: 0}
		a.orig = pairBest[pair]
		net[pair[0]] = append(net[pair[0]], a)
		net[pair[1]] = append(net[pair[1]], b)
		a.rev = len(net[pair[1]]) - 1
		b.rev = len(net[pair[0]]) - 1
	}

	// Edmonds-Karp max flow.
	for {
		// BFS: find shortest augmenting path, tracking predecessors.
		prevNode := map[string]string{}
		prevEdge := map[string]*netEdge{}
		visited := map[string]bool{agentID: true}
		queue := []string{agentID}
		found := false
		for len(queue) > 0 && !found {
			cur := queue[0]
			queue = queue[1:]
			for _, fe := range net[cur] {
				if fe.cap > 0 && !visited[fe.to] {
					visited[fe.to] = true
					prevNode[fe.to] = cur
					prevEdge[fe.to] = fe
					if fe.to == targetID {
						found = true
						break
					}
					queue = append(queue, fe.to)
				}
			}
		}
		if !found {
			break
		}

		// Bottleneck.
		bottle := 1 << 30
		for v := targetID; v != agentID; v = prevNode[v] {
			if c := prevEdge[v].cap; c < bottle {
				bottle = c
			}
		}
		// Augment.
		for v := targetID; v != agentID; v = prevNode[v] {
			fe := prevEdge[v]
			fe.cap -= bottle
			net[fe.to][fe.rev].cap += bottle
		}
	}

	// Residual reachability from agent.
	reachable := map[string]bool{agentID: true}
	queue := []string{agentID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, fe := range net[cur] {
			if fe.cap > 0 && !reachable[fe.to] {
				reachable[fe.to] = true
				queue = append(queue, fe.to)
			}
		}
	}

	// Cut edges: saturated edges leaving the reachable set. Because the
	// network aggregates parallel graph edges per node pair, a saturated
	// network edge means the PAIR must be severed - removing only one of
	// several parallel relationship types would leave the others intact
	// and the target still reachable. All graph edges of the cut pair
	// are therefore returned.
	var cut []*graph.Edge
	seen := map[edgeID]bool{}
	for u, edges := range net {
		if !reachable[u] {
			continue
		}
		for _, fe := range edges {
			if fe.cap != 0 || reachable[fe.to] || fe.orig == nil {
				continue
			}
			for _, e := range g.EdgeBetween(u, fe.to) {
				id := edgeID{e.Source, e.Target, string(e.Type)}
				if !seen[id] {
					seen[id] = true
					cut = append(cut, e)
				}
			}
		}
	}

	sort.Slice(cut, func(i, j int) bool {
		if cut[i].Source != cut[j].Source {
			return cut[i].Source < cut[j].Source
		}
		if cut[i].Target != cut[j].Target {
			return cut[i].Target < cut[j].Target
		}
		return cut[i].Type < cut[j].Type
	})

	return &CutResult{
		Agent:           agentID,
		Target:          tgt.ID,
		CutEdges:        cut,
		PathsConsidered: len(ps),
		Truncated:       truncated,
	}, nil
}

// MincutToCrownJewels computes cuts separating agent from each crown
// jewel it can reach.
func MincutToCrownJewels(g *graph.Graph, agentID string, opts paths.Options) ([]*CutResult, error) {
	if _, ok := g.Node(agentID); !ok {
		return nil, fmt.Errorf("unknown node %q", agentID)
	}

	cjOpts := opts
	cjOpts.CrownJewelsOnly = true
	ps, _ := paths.Enumerate(g, agentID, cjOpts)

	seen := map[string]bool{}
	var out []*CutResult
	for _, p := range ps {
		if seen[p.Target.ID] {
			continue
		}
		seen[p.Target.ID] = true
		res, err := Mincut(g, agentID, p.Target.ID, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].CutEdges) != len(out[j].CutEdges) {
			return len(out[i].CutEdges) < len(out[j].CutEdges)
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
