package risk

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

func mkEdge(risk int, conf float64) *graph.Edge {
	// Uses a low-default edge type so an explicit Risk drives EffectiveRisk.
	return &graph.Edge{Source: "a", Target: "b", Type: graph.EdgeConnectedTo, Confidence: conf, Risk: risk}
}

func TestEdgeLikelihoodBounds(t *testing.T) {
	for _, risk := range []int{0, 25, 50, 75, 100} {
		for _, conf := range []float64{0.1, 0.5, 1.0} {
			p := EdgeLikelihood(mkEdge(risk, conf))
			if p < 0.01 || p > 0.99 {
				t.Fatalf("risk=%d conf=%.2f -> p=%.4f out of bounds", risk, conf, p)
			}
		}
	}
}

func TestEdgeLikelihoodMonotonicInRisk(t *testing.T) {
	// EffectiveRisk() falls back to the type default only when Risk == 0,
	// so the sweep starts at 1 to stay in the explicit-risk domain.
	prev := -1.0
	for risk := 1; risk <= 100; risk += 10 {
		p := EdgeLikelihood(mkEdge(risk, 1.0))
		if p < prev {
			t.Fatalf("likelihood not monotonic in risk at %d: %.4f < %.4f", risk, p, prev)
		}
		prev = p
	}
}

func TestConfidenceAttenuates(t *testing.T) {
	full := EdgeLikelihood(mkEdge(80, 1.0))
	speculative := EdgeLikelihood(mkEdge(80, 0.4))
	if speculative >= full {
		t.Fatalf("speculative edge must attenuate: %.4f >= %.4f", speculative, full)
	}
}

func TestLikelihoodOverride(t *testing.T) {
	e := mkEdge(50, 1.0)
	e.Metadata = map[string]any{"likelihood": 0.25}
	if p := EdgeLikelihood(e); p != 0.25 {
		t.Fatalf("override ignored: %.4f", p)
	}
}

func TestPathLikelihoodProduct(t *testing.T) {
	// Four 0.9-probability hops: 0.9^4 = 0.6561.
	edges := []*graph.Edge{
		mkEdge(100, 1.0), mkEdge(100, 1.0), mkEdge(100, 1.0), mkEdge(100, 1.0),
	}
	// EdgeLikelihood(100,1.0) = 0.9 exactly.
	if p := PathLikelihood(edges); p < 0.656 || p > 0.6562 {
		t.Fatalf("expected ~0.6561, got %.4f", p)
	}
}

func TestPathLikelihoodAttenuatesWithLength(t *testing.T) {
	hop := mkEdge(50, 1.0) // ~0.5 per hop
	short := PathLikelihood([]*graph.Edge{hop, hop})
	long := PathLikelihood([]*graph.Edge{hop, hop, hop, hop, hop, hop, hop, hop})
	if long >= short {
		t.Fatalf("long chains must be less likely: %.4f vs %.4f", long, short)
	}
	if short < 0.15 || short > 0.35 {
		t.Fatalf("two ~0.5 hops should be ~0.25, got %.4f", short)
	}
}

func TestLikelihoodBands(t *testing.T) {
	cases := map[float64]string{
		0.90:    LikelihoodVeryLikely,
		0.50:    LikelihoodVeryLikely,
		0.20:    LikelihoodLikely,
		0.05:    LikelihoodPossible,
		0.005:   LikelihoodUnlikely,
		0.00001: LikelihoodImplausible,
	}
	for p, want := range cases {
		if got := LikelihoodFor(p); got != want {
			t.Errorf("LikelihoodFor(%.5f) = %s, want %s", p, got, want)
		}
	}
}

func TestExpectedThreat(t *testing.T) {
	// A certain-but-low-risk path can rank below a likely high-risk one.
	certain := ExpectedThreat(40, 1.0) // 40
	likely := ExpectedThreat(95, 0.7)  // ~67
	if likely <= certain {
		t.Fatalf("expected threat should combine likelihood with impact: %d vs %d", likely, certain)
	}
	if got := ExpectedThreat(100, 1.0); got != 100 {
		t.Errorf("ExpectedThreat(100, 1.0) = %d, want 100", got)
	}
	if got := ExpectedThreat(100, 0.0); got != 0 {
		t.Errorf("ExpectedThreat(100, 0) = %d, want 0", got)
	}
}
