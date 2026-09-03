package remediation

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// diamond builds:
//
//	agent -> mcp -> {repoA, repoB} -> db (crown jewel)
//
// Both branches reach db, so cutting one edge is insufficient: the
// minimum cut must sever both branches (or the single agent->mcp edge).
func diamond() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "repoA", Type: graph.NodeRepository, Name: "repoA"},
		{ID: "repoB", Type: graph.NodeRepository, Name: "repoB"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 95, CrownJewel: true},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	edges := []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "mcp", Target: "repoA", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "mcp", Target: "repoB", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "repoA", Target: "db", Type: graph.EdgeCanAccess, Confidence: 1},
		{Source: "repoB", Target: "db", Type: graph.EdgeCanAccess, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestMincutParallelEdges(t *testing.T) {
	// Regression: when two relationship types connect the cut node pair
	// (e.g. USES + CAN_READ), the cut must sever BOTH - a single edge
	// leaves the target reachable through the other.
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 90},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	for _, e := range []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "agent", Target: "mcp", Type: graph.EdgeCanRead, Confidence: 1},
		{Source: "mcp", Target: "db", Type: graph.EdgeCanAccess, Confidence: 1},
	} {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}

	res, err := Mincut(g, "agent", "db", paths.Options{})
	if err != nil {
		t.Fatalf("mincut: %v", err)
	}
	if len(res.CutEdges) < 2 {
		t.Fatalf("parallel agent->mcp edges both belong to the cut, got %d: %v",
			len(res.CutEdges), res.CutEdges)
	}
	// Applying the full cut must disconnect.
	for _, e := range res.CutEdges {
		g.RemoveEdge(e.Source, e.Target, e.Type)
	}
	if shortestPathExists(g, "agent", "db") {
		t.Fatal("target still reachable after applying the cut")
	}
}

func TestMincutSeversAllBranches(t *testing.T) {
	g := diamond()
	res, err := Mincut(g, "agent", "db", paths.Options{})
	if err != nil {
		t.Fatalf("mincut: %v", err)
	}
	if len(res.CutEdges) == 0 {
		t.Fatal("expected a non-empty cut")
	}

	// Verify: removing the cut edges must disconnect agent from db.
	for _, e := range res.CutEdges {
		g.RemoveEdge(e.Source, e.Target, e.Type)
	}
	if p := shortestPathExists(g, "agent", "db"); p {
		t.Fatal("path still exists after applying the cut - cut is invalid")
	}
}

func TestMincutSingleBottleneck(t *testing.T) {
	g := diamond()
	// Remove one branch: now agent->mcp is the unique bottleneck.
	g.RemoveEdge("mcp", "repoB", graph.EdgeCanWrite)

	res, err := Mincut(g, "agent", "db", paths.Options{})
	if err != nil {
		t.Fatalf("mincut: %v", err)
	}
	if len(res.CutEdges) != 1 {
		t.Fatalf("expected single-edge cut, got %d: %v", len(res.CutEdges), res.CutEdges)
	}
	e := res.CutEdges[0]
	if e.Source != "agent" || e.Target != "mcp" {
		t.Errorf("expected cut at agent->mcp, got %s->%s", e.Source, e.Target)
	}
}

func TestMincutNoPath(t *testing.T) {
	g := graph.New()
	_ = g.AddNode(&graph.Node{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"})
	_ = g.AddNode(&graph.Node{ID: "db", Type: graph.NodeDatabase, Name: "db"})
	res, err := Mincut(g, "agent", "db", paths.Options{})
	if err != nil {
		t.Fatalf("mincut: %v", err)
	}
	if len(res.CutEdges) != 0 {
		t.Fatalf("expected empty cut for disconnected nodes, got %v", res.CutEdges)
	}
}

func TestMincutInvalidNodes(t *testing.T) {
	g := diamond()
	if _, err := Mincut(g, "ghost", "db", paths.Options{}); err == nil {
		t.Error("expected error for unknown agent")
	}
	if _, err := Mincut(g, "agent", "ghost", paths.Options{}); err == nil {
		t.Error("expected error for unknown target")
	}
}

func TestMincutToCrownJewels(t *testing.T) {
	g := diamond()
	results, err := MincutToCrownJewels(g, "agent", paths.Options{})
	if err != nil {
		t.Fatalf("mincut to crown jewels: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 crown jewel result, got %d", len(results))
	}
	if results[0].Target != "db" {
		t.Errorf("expected target db, got %s", results[0].Target)
	}
}

// shortestPathExists reports whether any path src->dst exists.
func shortestPathExists(g *graph.Graph, src, dst string) bool {
	visited := map[string]bool{src: true}
	queue := []string{src}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == dst {
			return true
		}
		for _, e := range g.OutEdges(cur) {
			if !visited[e.Target] {
				visited[e.Target] = true
				queue = append(queue, e.Target)
			}
		}
	}
	return false
}
