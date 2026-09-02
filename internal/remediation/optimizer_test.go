package remediation

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// buildChainedGraph builds the canonical chain:
// agent -> mcp -> repo -> ci -> role -> db (crown jewel).
func buildChainedGraph() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "repo", Type: graph.NodeRepository, Name: "repo", Metadata: map[string]any{"environment": "production"}},
		{ID: "ci", Type: graph.NodeCIPipeline, Name: "ci", Metadata: map[string]any{"environment": "production"}},
		{ID: "role", Type: graph.NodeCloudRole, Name: "role", Metadata: map[string]any{"privilege": "admin", "environment": "production"}},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 95, CrownJewel: true, Metadata: map[string]any{"environment": "production"}},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	edges := []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "mcp", Target: "repo", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "repo", Target: "ci", Type: graph.EdgeTriggers, Confidence: 1},
		{Source: "ci", Target: "role", Type: graph.EdgeCanAssume, Confidence: 1},
		{Source: "role", Target: "db", Type: graph.EdgeCanAdmin, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestOptimizeRecommendsCuttingChain(t *testing.T) {
	g := buildChainedGraph()

	beforePaths, err := paths.Enumerate(g, "agent", paths.Options{})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(beforePaths) == 0 {
		t.Fatal("expected paths before remediation")
	}

	rec, err := Optimize(g, "agent", paths.Options{}, 20)
	if err != nil {
		t.Fatalf("optimize: %v", err)
	}
	if rec.Edge == nil {
		t.Fatal("expected a recommendation")
	}
	if rec.PathsAfter >= rec.PathsBefore {
		t.Fatalf("recommendation should reduce paths, before=%d after=%d",
			rec.PathsBefore, rec.PathsAfter)
	}

	// The critical crown-jewel path must be eliminated.
	if rec.CriticalAfter != 0 {
		t.Fatalf("expected 0 critical paths after remediation, got %d", rec.CriticalAfter)
	}

	// The graph must be restored after optimization (edge re-added).
	afterRestore, _ := paths.Enumerate(g, "agent", paths.Options{})
	if len(afterRestore) != rec.PathsBefore {
		t.Fatalf("optimizer must not mutate the graph: %d vs %d",
			len(afterRestore), rec.PathsBefore)
	}
}

func TestOptimizeIsolatedAgent(t *testing.T) {
	g := buildChainedGraph()
	_ = g.AddNode(&graph.Node{ID: "lonely", Type: graph.NodeAIAgent, Name: "lonely"})
	rec, err := Optimize(g, "lonely", paths.Options{}, 20)
	if err != nil {
		t.Fatalf("optimize: %v", err)
	}
	if rec.Edge != nil || rec.PathsBefore != 0 {
		t.Fatalf("isolated agent should yield an empty recommendation, got %+v", rec)
	}
}

func TestChokePoints(t *testing.T) {
	g := buildChainedGraph()
	// Add a second agent sharing mcp -> repo.
	_ = g.AddNode(&graph.Node{ID: "agent2", Type: graph.NodeAIAgent, Name: "agent2"})
	_ = g.AddEdge(&graph.Edge{Source: "agent2", Target: "mcp", Type: graph.EdgeUses, Confidence: 1})

	all, _ := paths.EnumerateAll(g, paths.Options{})
	scored := ScoreAll(all)
	if len(scored) == 0 {
		t.Fatal("expected paths")
	}

	cps := ChokePoints(g, scored)
	if len(cps) == 0 {
		t.Fatal("expected choke points")
	}

	// mcp must be the top choke point: it appears in every path.
	top := cps[0]
	if top.Node.ID != "mcp" {
		t.Fatalf("expected mcp as top choke point, got %s", top.Node.ID)
	}
	if top.PathCount != len(all) {
		t.Fatalf("mcp should appear in all %d paths, got %d", len(all), top.PathCount)
	}

	// Source and target nodes must never be choke points.
	for _, cp := range cps {
		if cp.Node.ID == "agent" || cp.Node.ID == "agent2" || cp.Node.ID == "db" {
			t.Fatalf("endpoint node listed as choke point: %s", cp.Node.ID)
		}
	}
}
