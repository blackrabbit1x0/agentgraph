// Package blast implements blast-radius and agent-exposure analysis
// (PRD sections 11, 17, and 25).
package blast

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

// ScoredPath pairs a path with its risk result.
type ScoredPath struct {
	Path *paths.Path
	Risk risk.Result
}

// Radius is the blast-radius result for one agent.
type Radius struct {
	Agent *graph.Node

	// Direct counts: nodes reachable in exactly one hop, by type.
	Direct map[graph.NodeType]int
	// Indirect counts: nodes reachable in two or more hops, by type.
	Indirect map[graph.NodeType]int

	ReachableNodes       int
	ReachableCrownJewels []string
	ReachableSecrets     int
	ReachableIdentities  int
	CloudRoles           int

	HighestPrivilege string
	highestPrivRank  int

	TotalPaths    int
	CriticalPaths int
	HighPaths     int

	// MostDangerous is the highest-scoring attack path, if any.
	MostDangerous *ScoredPath

	ExposureScore int
	ExposureRisk  string
}

// Analyze computes the blast radius of the given agent.
func Analyze(g *graph.Graph, agentID string, opts paths.Options) (*Radius, error) {
	agent, ok := g.Node(agentID)
	if !ok {
		return nil, fmt.Errorf("unknown node %q", agentID)
	}
	if agent.Type != graph.NodeAIAgent {
		return nil, fmt.Errorf("node %q is a %s, not an AI_AGENT", agentID, agent.Type)
	}

	r := &Radius{
		Agent:    agent,
		Direct:   map[graph.NodeType]int{},
		Indirect: map[graph.NodeType]int{},
	}

	// Pure BFS over all edges for direct/indirect reachability layers.
	depth := map[string]int{agentID: 0}
	visited := map[string]bool{agentID: true}
	queue := []string{agentID}
	dangerous := false
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.OutEdges(cur) {
			if e.Type == graph.EdgeCanExecute || e.Type == graph.EdgeCanAdmin ||
				e.Type == graph.EdgeCanImpersonate {
				dangerous = true
			}
			if visited[e.Target] {
				continue
			}
			visited[e.Target] = true
			d := depth[cur] + 1
			depth[e.Target] = d
			queue = append(queue, e.Target)
			n, _ := g.Node(e.Target)
			if d == 1 {
				r.Direct[n.Type]++
			} else {
				r.Indirect[n.Type]++
			}
		}
	}
	r.ReachableNodes = len(visited) - 1

	for id := range visited {
		if id == agentID {
			continue
		}
		n, _ := g.Node(id)
		if n.CrownJewel {
			r.ReachableCrownJewels = append(r.ReachableCrownJewels, n.ID)
		}
		switch n.Type {
		case graph.NodeSecret:
			r.ReachableSecrets++
		case graph.NodeIdentity:
			r.ReachableIdentities++
		case graph.NodeCloudRole:
			r.CloudRoles++
		}
		if lvl, ok := n.Metadata["privilege"].(string); ok {
			if rank := graph.PrivilegeRank(lvl); rank > r.highestPrivRank {
				r.highestPrivRank = rank
				r.HighestPrivilege = lvl
			}
		}
	}
	sort.Strings(r.ReachableCrownJewels)

	// Enumerate attack paths for path counts and the most dangerous path.
	// EnumerateAll is used so that path IDs match the global numbering
	// shown by "agentgraph paths" and "agentgraph explain".
	all, _ := paths.EnumerateAll(g, opts)
	for _, p := range all {
		if p.Source.ID != agentID {
			continue
		}
		res := risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence)
		r.TotalPaths++
		switch res.Severity {
		case risk.SeverityCritical:
			r.CriticalPaths++
		case risk.SeverityHigh:
			r.HighPaths++
		}
		if r.MostDangerous == nil || res.Score > r.MostDangerous.Risk.Score {
			r.MostDangerous = &ScoredPath{Path: p, Risk: res}
		}
	}

	r.ExposureScore, r.ExposureRisk = exposure(r, dangerous)
	return r, nil
}

// exposure computes the agent exposure score (PRD section 17).
func exposure(r *Radius, dangerousCapability bool) (int, string) {
	score := 0

	// Reachable crown jewels: +8 each, capped at +24.
	cj := 8 * len(r.ReachableCrownJewels)
	if cj > 24 {
		cj = 24
	}
	score += cj

	// Dangerous execution/admin capability reachable: +10.
	if dangerousCapability {
		score += 10
	}

	// Cloud reach: +10.
	if r.CloudRoles > 0 {
		score += 10
	}

	// Secrets exposure: +8.
	if r.ReachableSecrets > 0 {
		score += 8
	}

	// Attack-path volume: up to +20.
	pathVolume := r.TotalPaths / 3
	if pathVolume > 20 {
		pathVolume = 20
	}
	score += pathVolume

	// Maximum path severity: up to +15.
	if r.MostDangerous != nil {
		switch r.MostDangerous.Risk.Severity {
		case risk.SeverityCritical:
			score += 15
		case risk.SeverityHigh:
			score += 10
		case risk.SeverityMedium:
			score += 5
		case risk.SeverityLow:
			score += 2
		}
	}

	// Agent posture modifiers.
	if b, _ := r.Agent.Metadata["internet_access"].(bool); b {
		score += 5
	}
	if b, _ := r.Agent.Metadata["requires_approval"].(bool); b {
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, risk.SeverityFor(score)
}
