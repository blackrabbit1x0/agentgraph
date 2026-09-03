// Package risk: probabilistic attack-path likelihood (PRD section 68,
// "probabilistic attack paths").
//
// Reachability says a path *can* be walked. Likelihood estimates how
// *plausibly* an attacker walks it. Each edge gets an exploitation
// probability derived from its security cost; the path's likelihood is
// the product of its edges' probabilities.
package risk

import (
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Likelihood thresholds for reporting bands.
const (
	LikelihoodVeryLikely  = "VERY_LIKELY"
	LikelihoodLikely      = "LIKELY"
	LikelihoodPossible    = "POSSIBLE"
	LikelihoodUnlikely    = "UNLIKELY"
	LikelihoodImplausible = "IMPLAUSIBLE"
)

// EdgeLikelihood estimates the probability that an attacker can traverse
// a single edge, given they reached its source.
//
// Inputs:
//   - e.EffectiveRisk(): how privileged/dangerous the relationship is
//     (higher risk = easier or more valuable traversal)
//   - e.Confidence: how certain we are the relationship exists at all
//   - metadata override: an explicit likelihood from configuration
//
// The base probability treats effective risk as ease of abuse (risk 100
// -> 0.90, risk 0 -> 0.10) and multiplies by confidence so speculative
// relationships attenuate likelihood. Configured overrides win outright.
func EdgeLikelihood(e *graph.Edge) float64 {
	if e == nil {
		return 0
	}
	// Explicit override: agents may carry analytics-informed estimates.
	if v, ok := e.Metadata["likelihood"].(float64); ok && v > 0 && v <= 1 {
		return v
	}
	risk := e.EffectiveRisk()
	if risk < 0 {
		risk = 0
	}
	if risk > 100 {
		risk = 100
	}
	// S-curve: mid risks ~0.5, extreme risks 0.1..0.9. A linear map is
	// too flat to separate "trivial" from "hard".
	p := 0.1 + 0.8*(float64(risk)/100.0)

	// Attenuate by existence confidence: a 0.6-confidence edge halves
	// the chance the path is even real.
	if c := e.Confidence; c > 0 && c < 1 {
		p *= (0.5 + 0.5*c)
	}
	if p < 0.01 {
		p = 0.01
	}
	if p > 0.99 {
		p = 0.99
	}
	return p
}

// PathLikelihood returns the probability that an attacker traverses the
// full path in one attempt, assuming independence between edges. Long
// paths attenuate quickly, which is the point: an 8-hop chain of
// 0.5-probability hops is ~0.4% likely even when every hop alone is
// feasible.
func PathLikelihood(edges []*graph.Edge) float64 {
	if len(edges) == 0 {
		return 0
	}
	p := 1.0
	for _, e := range edges {
		p *= EdgeLikelihood(e)
		if p < 1e-9 {
			return 1e-9
		}
	}
	return p
}

// LikelihoodFor maps a probability to its reporting band.
func LikelihoodFor(p float64) string {
	switch {
	case p >= 0.5:
		return LikelihoodVeryLikely
	case p >= 0.15:
		return LikelihoodLikely
	case p >= 0.02:
		return LikelihoodPossible
	case p >= 0.001:
		return LikelihoodUnlikely
	default:
		return LikelihoodImplausible
	}
}

// LikelihoodRank returns an ordinal for comparing bands.
func LikelihoodRank(band string) int {
	switch band {
	case LikelihoodVeryLikely:
		return 4
	case LikelihoodLikely:
		return 3
	case LikelihoodPossible:
		return 2
	case LikelihoodUnlikely:
		return 1
	default:
		return 0
	}
}

// ExpectedThreat combines likelihood with the deterministic risk score:
// the product estimates how much of the path's damage is realistically
// expected. Used to order paths that share a target.
func ExpectedThreat(score int, likelihood float64) int {
	t := float64(score) * likelihood
	if t > 100 {
		t = 100
	}
	if t < 0 {
		t = 0
	}
	return int(t + 0.5)
}
