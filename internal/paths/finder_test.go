package paths

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// buildLinear builds A(agent) -> B(tool) -> C(repo) -> D(database).
func buildLinear() *graph.Graph {
	g := graph.New()
	for _, n := range []*graph.Node{
		{ID: "A", Type: graph.NodeAIAgent, Name: "A"},
		{ID: "B", Type: graph.NodeTool, Name: "B"},
		{ID: "C", Type: graph.NodeRepository, Name: "C"},
		{ID: "D", Type: graph.NodeDatabase, Name: "Production Database", Criticality: 90},
	} {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	for _, e := range []*graph.Edge{
		{Source: "A", Target: "B", Type: graph.EdgeUses, Confidence: 1},
		{Source: "B", Target: "C", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "C", Target: "D", Type: graph.EdgeCanAccess, Confidence: 1},
	} {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestTransitiveResolution(t *testing.T) {
	g := buildLinear()
	ps, err := Enumerate(g, "A", Options{})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}

	// Terminal nodes: C (repository) and D (database); B is a tool.
	if len(ps) != 2 {
		t.Fatalf("expected 2 paths (A->C, A->D), got %d", len(ps))
	}

	var toC, toD *Path
	for _, p := range ps {
		switch p.Target.ID {
		case "C":
			toC = p
		case "D":
			toD = p
		}
	}
	if toC == nil || toD == nil {
		t.Fatalf("missing expected paths, got %v", ps)
	}

	// A -> D must resolve transitively with intermediate nodes and types.
	if got := toD.Length(); got != 3 {
		t.Fatalf("expected path length 3, got %d", got)
	}
	wantNodes := []string{"A", "B", "C", "D"}
	gotNodes := toD.Nodes()
	for i, n := range gotNodes {
		if n.ID != wantNodes[i] {
			t.Fatalf("node %d: want %s got %s", i, wantNodes[i], n.ID)
		}
	}
	wantTypes := []graph.EdgeType{graph.EdgeUses, graph.EdgeCanWrite, graph.EdgeCanAccess}
	for i, e := range toD.Edges() {
		if e.Type != wantTypes[i] {
			t.Fatalf("edge %d: want %s got %s", i, wantTypes[i], e.Type)
		}
	}
}

func TestCyclePrevention(t *testing.T) {
	g := buildLinear()
	// Add edges that would create loops: D -> A and C -> B.
	edges := []*graph.Edge{
		{Source: "D", Target: "A", Type: graph.EdgeTrusts, Confidence: 1},
		{Source: "C", Target: "B", Type: graph.EdgeTrusts, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			t.Fatalf("add edge: %v", err)
		}
	}

	ps, err := Enumerate(g, "A", Options{})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for _, p := range ps {
		seen := map[string]bool{}
		for _, n := range p.Nodes() {
			if seen[n.ID] {
				t.Fatalf("path repeats node %s: %s", n.ID, Describe(p))
			}
			seen[n.ID] = true
		}
	}
	// The same simple paths as before must be found; loops add nothing.
	if len(ps) != 2 {
		t.Fatalf("expected 2 simple paths despite cycles, got %d", len(ps))
	}
}

func TestDepthRestriction(t *testing.T) {
	g := buildLinear()

	ps, err := Enumerate(g, "A", Options{MaxDepth: 2})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for _, p := range ps {
		if p.Length() > 2 {
			t.Fatalf("path exceeds depth 2: %s", Describe(p))
		}
	}
	// Only A->C (2 hops) fits; A->D needs 3 hops.
	if len(ps) != 1 || ps[0].Target.ID != "C" {
		t.Fatalf("expected only A->C, got %d paths", len(ps))
	}
}

func TestConfidenceThreshold(t *testing.T) {
	g := buildLinear()
	// Lower confidence on B->C below threshold.
	g.RemoveEdge("B", "C", graph.EdgeCanWrite)
	if err := g.AddEdge(&graph.Edge{Source: "B", Target: "C", Type: graph.EdgeCanWrite, Confidence: 0.4}); err != nil {
		t.Fatal(err)
	}

	ps, err := Enumerate(g, "A", Options{MinConfidence: 0.5})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for _, p := range ps {
		for _, e := range p.Edges() {
			if e.Confidence < 0.5 {
				t.Fatalf("path includes low-confidence edge: %s", Describe(p))
			}
		}
	}
	if len(ps) != 0 {
		t.Fatalf("expected 0 paths above threshold, got %d", len(ps))
	}
}

func TestPathConfidenceProduct(t *testing.T) {
	g := buildLinear()
	g.RemoveEdge("B", "C", graph.EdgeCanWrite)
	_ = g.AddEdge(&graph.Edge{Source: "B", Target: "C", Type: graph.EdgeCanWrite, Confidence: 0.5})
	g.RemoveEdge("C", "D", graph.EdgeCanAccess)
	_ = g.AddEdge(&graph.Edge{Source: "C", Target: "D", Type: graph.EdgeCanAccess, Confidence: 0.8})

	ps, _ := Enumerate(g, "A", Options{})
	for _, p := range ps {
		if p.Target.ID == "D" && p.Confidence != 0.4 {
			t.Fatalf("expected confidence 0.4 (1.0*0.5*0.8), got %f", p.Confidence)
		}
	}
}

func TestTargetFilters(t *testing.T) {
	g := buildLinear()

	ps, _ := Enumerate(g, "A", Options{TargetID: "D"})
	if len(ps) != 1 || ps[0].Target.ID != "D" {
		t.Fatalf("TargetID filter failed: %d paths", len(ps))
	}

	ps, _ = Enumerate(g, "A", Options{TargetSubstring: "database"})
	if len(ps) != 1 || ps[0].Target.ID != "D" {
		t.Fatalf("substring filter failed: %d paths", len(ps))
	}

	// Crown-jewel filter: D is not one yet.
	ps, _ = Enumerate(g, "A", Options{CrownJewelsOnly: true})
	if len(ps) != 0 {
		t.Fatalf("expected no crown-jewel paths, got %d", len(ps))
	}
}

func TestShortest(t *testing.T) {
	g := buildLinear()
	// Add a shortcut A -> C.
	_ = g.AddEdge(&graph.Edge{Source: "A", Target: "C", Type: graph.EdgeUses, Confidence: 1})

	p := Shortest(g, "A", "D")
	if p == nil {
		t.Fatal("expected a path A->D")
	}
	if p.Length() != 2 {
		t.Fatalf("expected shortest path of 2 hops via shortcut, got %d (%s)",
			p.Length(), Describe(p))
	}

	if p := Shortest(g, "D", "A"); p != nil {
		t.Fatalf("expected no path D->A, got %s", Describe(p))
	}
	if p := Shortest(g, "A", "nonexistent"); p != nil {
		t.Fatal("expected nil for unknown target")
	}
}

func TestDeterministicIDs(t *testing.T) {
	g := buildLinear()
	a, _ := Enumerate(g, "A", Options{})
	b, _ := Enumerate(g, "A", Options{})
	if len(a) != len(b) {
		t.Fatal("enumeration is not deterministic in length")
	}
	for i := range a {
		if a[i].ID != b[i].ID || Describe(a[i]) != Describe(b[i]) {
			t.Fatalf("enumeration order/IDs differ at %d", i)
		}
	}
}
