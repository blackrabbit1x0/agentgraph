// Package risk implements explainable attack-path risk scoring
// (PRD sections 13 and 14).
package risk

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Severity bands (PRD section 13).
const (
	SeverityInformational = "INFORMATIONAL"
	SeverityLow           = "LOW"
	SeverityMedium        = "MEDIUM"
	SeverityHigh          = "HIGH"
	SeverityCritical      = "CRITICAL"
)

// Factor is one explainable contribution to a risk score.
type Factor struct {
	Name   string `json:"name"`
	Delta  int    `json:"delta"`
	Reason string `json:"reason"`
}

// Result is the outcome of scoring a single path.
type Result struct {
	Score      int      `json:"score"`
	Severity   string   `json:"severity"`
	Factors    []Factor `json:"factors"`
	Confidence float64  `json:"confidence"`
}

// Scoring model (additive, then scaled by path confidence):
//
//	target criticality            up to +30
//	max edge (privilege) risk     up to +25
//	production access             +20
//	exec/admin capability         +15
//	crown-jewel target            +10
//	internet-exposed agent        +5
//	approval required             -5
//	indirect path length          -1 per hop beyond 3
//
//	final = clamp(round(raw * pathConfidence), 0, 100)
const (
	factorTargetCriticalityMax = 30
	factorEdgeRiskMax          = 25
	factorProductionAccess     = 20
	factorExecCapability       = 15
	factorCrownJewel           = 10
	factorInternetExposure     = 5
	factorApprovalMitigation   = -5
	factorLengthPenaltyPerHop  = -1
	factorLengthFreeHops       = 3
)

var highPrivilegeEdges = map[graph.EdgeType]bool{
	graph.EdgeCanExecute:     true,
	graph.EdgeCanAdmin:       true,
	graph.EdgeCanImpersonate: true,
}

// ScorePath scores one attack path given its node and edge sequences.
// The returned result includes a full factor breakdown so that every score
// remains explainable (PRD section 13).
func ScorePath(nodes []*graph.Node, edges []*graph.Edge, confidence float64) Result {
	var factors []Factor
	raw := 0

	if len(nodes) == 0 {
		return Result{Score: 0, Severity: SeverityInformational, Confidence: confidence}
	}

	// Target criticality: 0-100 node criticality scaled to max +30.
	target := nodes[len(nodes)-1]
	tc := target.Criticality
	if tc > 100 {
		tc = 100
	}
	if tc > 0 {
		delta := tc * factorTargetCriticalityMax / 100
		raw += delta
		factors = append(factors, Factor{
			Name:   "target_criticality",
			Delta:  delta,
			Reason: fmt.Sprintf("target %s has criticality %d/100", target.ID, tc),
		})
	}

	// Privilege level: highest effective edge risk scaled to max +25.
	maxRisk := 0
	var maxEdge *graph.Edge
	for _, e := range edges {
		if r := e.EffectiveRisk(); r > maxRisk {
			maxRisk = r
			maxEdge = e
		}
	}
	if maxRisk > 0 {
		delta := maxRisk * factorEdgeRiskMax / 100
		raw += delta
		factors = append(factors, Factor{
			Name:  "privilege_level",
			Delta: delta,
			Reason: fmt.Sprintf("highest-privilege step %s --%s--> %s (risk %d/100)",
				maxEdge.Source, maxEdge.Type, maxEdge.Target, maxRisk),
		})
	}

	// Production access anywhere along the path.
	for _, n := range nodes {
		if env, _ := n.Metadata["environment"].(string); env == "production" {
			raw += factorProductionAccess
			factors = append(factors, Factor{
				Name:   "production_access",
				Delta:  factorProductionAccess,
				Reason: fmt.Sprintf("node %s is in the production environment", n.ID),
			})
			break
		}
	}

	// Dangerous execution/admin capabilities.
	for _, e := range edges {
		if highPrivilegeEdges[e.Type] {
			raw += factorExecCapability
			factors = append(factors, Factor{
				Name:   "execution_capability",
				Delta:  factorExecCapability,
				Reason: fmt.Sprintf("path grants %s (%s -> %s)", e.Type, e.Source, e.Target),
			})
			break
		}
	}

	// Crown-jewel target.
	if target.CrownJewel {
		raw += factorCrownJewel
		factors = append(factors, Factor{
			Name:   "crown_jewel",
			Delta:  factorCrownJewel,
			Reason: fmt.Sprintf("target %s is a designated crown jewel", target.ID),
		})
	}

	// Source-agent exposure and mitigations.
	source := nodes[0]
	if b, _ := source.Metadata["internet_access"].(bool); b {
		raw += factorInternetExposure
		factors = append(factors, Factor{
			Name:   "internet_exposure",
			Delta:  factorInternetExposure,
			Reason: fmt.Sprintf("agent %s has internet access", source.ID),
		})
	}
	if b, _ := source.Metadata["requires_approval"].(bool); b {
		raw += factorApprovalMitigation
		factors = append(factors, Factor{
			Name:   "approval_required",
			Delta:  factorApprovalMitigation,
			Reason: fmt.Sprintf("agent %s requires human approval for sensitive actions", source.ID),
		})
	}

	// Indirect-path penalty: longer chains are less reliable for attackers.
	hops := len(edges)
	if hops > factorLengthFreeHops {
		penalty := (hops - factorLengthFreeHops) * factorLengthPenaltyPerHop
		raw += penalty
		factors = append(factors, Factor{
			Name:   "path_length",
			Delta:  penalty,
			Reason: fmt.Sprintf("path spans %d hops", hops),
		})
	}

	score := raw
	if confidence > 0 && confidence < 1 {
		score = int(float64(raw)*confidence + 0.5)
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return Result{
		Score:      score,
		Severity:   SeverityFor(score),
		Factors:    factors,
		Confidence: confidence,
	}
}

// SeverityFor maps a 0-100 score to its severity band.
func SeverityFor(score int) string {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 60:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	case score >= 20:
		return SeverityLow
	default:
		return SeverityInformational
	}
}

// SeverityRank returns an ordinal for comparing severities.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// SortFactors orders a factor breakdown from largest positive contribution
// to largest penalty, for readable explanations.
func SortFactors(fs []Factor) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Delta > fs[j].Delta })
}
