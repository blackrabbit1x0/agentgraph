// Package remediation implements choke-point analysis and permission
// removal recommendations (PRD sections 15 and 16).
package remediation

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

// ChokePoint identifies a node that appears across many attack paths.
type ChokePoint struct {
	Node          *graph.Node
	PathCount     int
	CriticalCount int
}

// ChokePoints analyzes which intermediate nodes appear most often across
// the supplied paths. Source and target nodes are excluded.
func ChokePoints(g *graph.Graph, scored []*ScoredPath) []*ChokePoint {
	type agg struct {
		node     *graph.Node
		paths    map[string]bool
		critical map[string]bool
	}
	byNode := map[string]*agg{}

	for _, sp := range scored {
		nodes := sp.Path.Nodes()
		for i, n := range nodes {
			if i == 0 || i == len(nodes)-1 {
				continue
			}
			a, ok := byNode[n.ID]
			if !ok {
				a = &agg{node: n, paths: map[string]bool{}, critical: map[string]bool{}}
				byNode[n.ID] = a
			}
			a.paths[sp.Path.ID] = true
			if sp.Risk.Severity == risk.SeverityCritical {
				a.critical[sp.Path.ID] = true
			}
		}
	}

	out := make([]*ChokePoint, 0, len(byNode))
	for _, a := range byNode {
		out = append(out, &ChokePoint{
			Node:          a.node,
			PathCount:     len(a.paths),
			CriticalCount: len(a.critical),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PathCount != out[j].PathCount {
			return out[i].PathCount > out[j].PathCount
		}
		if out[i].CriticalCount != out[j].CriticalCount {
			return out[i].CriticalCount > out[j].CriticalCount
		}
		return out[i].Node.ID < out[j].Node.ID
	})
	return out
}

// ScoredPath is re-declared locally to avoid an import cycle with blast.
type ScoredPath struct {
	Path *paths.Path
	Risk risk.Result
}

// ScoreAll scores a set of paths.
func ScoreAll(ps []*paths.Path) []*ScoredPath {
	out := make([]*ScoredPath, 0, len(ps))
	for _, p := range ps {
		out = append(out, &ScoredPath{
			Path: p,
			Risk: risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence),
		})
	}
	return out
}

// Candidate is one removable relationship considered by the optimizer.
type Candidate struct {
	Edge *graph.Edge
	// Occurrences counts how many of the agent's paths use this edge.
	Occurrences int
}

// Recommendation is the optimizer's best single permission removal.
type Recommendation struct {
	Edge *graph.Edge

	PathsBefore int
	PathsAfter  int

	CriticalBefore int
	CriticalAfter  int

	HighBefore int
	HighAfter  int

	// RiskReductionPct is the percentage drop in the agent's total path
	// risk (sum of path scores).
	RiskReductionPct int
}

// Optimize recommends the single edge whose removal eliminates the most
// attack paths from the given agent. Candidates are limited to the top
// maxCandidates most-frequent edges to bound computation.
func Optimize(g *graph.Graph, agentID string, opts paths.Options, maxCandidates int) (*Recommendation, error) {
	if _, ok := g.Node(agentID); !ok {
		return nil, fmt.Errorf("unknown node %q", agentID)
	}
	if maxCandidates <= 0 {
		maxCandidates = 20
	}

	before, err := paths.Enumerate(g, agentID, opts)
	if err != nil && !isTruncated(err) {
		return nil, err
	}
	scoredBefore := ScoreAll(before)

	rec := &Recommendation{
		PathsBefore:    len(before),
		CriticalBefore: countSeverity(scoredBefore, risk.SeverityCritical),
		HighBefore:     countSeverity(scoredBefore, risk.SeverityHigh),
		PathsAfter:     len(before),
		CriticalAfter:  countSeverity(scoredBefore, risk.SeverityCritical),
		HighAfter:      countSeverity(scoredBefore, risk.SeverityHigh),
	}
	if len(before) == 0 {
		return rec, nil
	}

	// Count edge occurrences across paths.
	type edgeKey struct {
		source, target string
		t              graph.EdgeType
	}
	counts := map[edgeKey]*Candidate{}
	for _, p := range before {
		for _, e := range p.Edges() {
			k := edgeKey{e.Source, e.Target, e.Type}
			if c, ok := counts[k]; ok {
				c.Occurrences++
			} else {
				counts[k] = &Candidate{Edge: e, Occurrences: 1}
			}
		}
	}
	cands := make([]*Candidate, 0, len(counts))
	for _, c := range counts {
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Occurrences != cands[j].Occurrences {
			return cands[i].Occurrences > cands[j].Occurrences
		}
		if cands[i].Edge.Source != cands[j].Edge.Source {
			return cands[i].Edge.Source < cands[j].Edge.Source
		}
		return cands[i].Edge.Target < cands[j].Edge.Target
	})
	if len(cands) > maxCandidates {
		cands = cands[:maxCandidates]
	}

	riskBefore := totalRisk(scoredBefore)
	bestCrit := rec.CriticalBefore
	bestPaths := rec.PathsBefore

	for _, cand := range cands {
		g.RemoveEdge(cand.Edge.Source, cand.Edge.Target, cand.Edge.Type)

		after, err := paths.Enumerate(g, agentID, opts)
		if err != nil && !isTruncated(err) {
			return nil, err
		}
		scoredAfter := ScoreAll(after)

		critAfter := countSeverity(scoredAfter, risk.SeverityCritical)
		highAfter := countSeverity(scoredAfter, risk.SeverityHigh)

		if critAfter < bestCrit || (critAfter == bestCrit && len(after) < bestPaths) {
			bestCrit = critAfter
			bestPaths = len(after)
			rec.Edge = cand.Edge
			rec.PathsAfter = len(after)
			rec.CriticalAfter = critAfter
			rec.HighAfter = highAfter
			riskAfter := totalRisk(scoredAfter)
			if riskBefore > 0 {
				rec.RiskReductionPct = 100 - riskAfter*100/riskBefore
			} else {
				rec.RiskReductionPct = 0
			}
		}

		g.AddEdge(cand.Edge)
	}

	if rec.Edge == nil {
		// No single removal helps; report the most frequent edge with no gain.
		rec.Edge = cands[0].Edge
	}
	return rec, nil
}

func countSeverity(scored []*ScoredPath, severity string) int {
	n := 0
	for _, s := range scored {
		if s.Risk.Severity == severity {
			n++
		}
	}
	return n
}

func totalRisk(scored []*ScoredPath) int {
	t := 0
	for _, s := range scored {
		t += s.Risk.Score
	}
	return t
}

func isTruncated(err error) bool {
	_, ok := err.(*paths.TruncatedError)
	return ok
}
