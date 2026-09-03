package store

import (
	"context"
	"os"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

func buildStoreGraph() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 95, CrownJewel: true,
			Metadata: map[string]any{"environment": "production"}},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	for _, e := range []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "mcp", Target: "db", Type: graph.EdgeCanAdmin, Confidence: 1, Risk: 90},
	} {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	m := NewMemoryStore()
	g := buildStoreGraph()

	if err := m.Save(context.Background(), "k1", g); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := m.Load(context.Background(), "k1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.NodeCount() != g.NodeCount() || loaded.EdgeCount() != g.EdgeCount() {
		t.Fatalf("round-trip mismatch: %d/%d vs %d/%d",
			loaded.NodeCount(), loaded.EdgeCount(), g.NodeCount(), g.EdgeCount())
	}
	n, _ := loaded.Node("db")
	if !n.CrownJewel || n.Criticality != 95 || n.Metadata["environment"] != "production" {
		t.Fatalf("node properties lost: %+v", n)
	}
	if !loaded.HasEdge("mcp", "db", graph.EdgeCanAdmin) {
		t.Fatal("edge lost in round-trip")
	}
}

func TestMemoryStoreNotFound(t *testing.T) {
	m := NewMemoryStore()
	_, err := m.Load(context.Background(), "ghost")
	if !IsNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStoreIsolation(t *testing.T) {
	m := NewMemoryStore()
	g := buildStoreGraph()
	_ = m.Save(context.Background(), "k", g)

	loaded, _ := m.Load(context.Background(), "k")
	loaded.RemoveEdge("agent", "mcp", graph.EdgeUses)

	again, _ := m.Load(context.Background(), "k")
	if !again.HasEdge("agent", "mcp", graph.EdgeUses) {
		t.Fatal("store must isolate stored graphs from loaded mutations")
	}
}

func TestMemoryStoreSaveReplaces(t *testing.T) {
	m := NewMemoryStore()
	_ = m.Save(context.Background(), "k", buildStoreGraph())

	// A second, smaller graph under the same key replaces the first.
	g2 := graph.New()
	_ = g2.AddNode(&graph.Node{ID: "solo", Type: graph.NodeHost, Name: "solo"})
	_ = m.Save(context.Background(), "k", g2)

	loaded, _ := m.Load(context.Background(), "k")
	if loaded.NodeCount() != 1 {
		t.Fatalf("save must replace, got %d nodes", loaded.NodeCount())
	}
}

// TestNeo4jRoundTrip is an integration test. It is skipped unless
// NEO4J_TEST_URI (and optionally NEO4J_TEST_USER/NEO4J_TEST_PASS) are
// set, e.g.:
//
//	docker run -e NEO4J_AUTH=neo4j/testpass -p 7687:7687 neo4j:5
//	NEO4J_TEST_URI=neo4j://localhost:7687 \
//	NEO4J_TEST_PASS=testpass go test ./internal/store/ -run Neo4j -v
func TestNeo4jRoundTrip(t *testing.T) {
	uri := getenv("NEO4J_TEST_URI")
	if uri == "" {
		t.Skip("NEO4J_TEST_URI not set; skipping neo4j integration test")
	}
	ctx := context.Background()
	s, err := NewNeo4jStore(ctx, Neo4jConfig{
		URI:      uri,
		Username: getenv("NEO4J_TEST_USER"),
		Password: getenv("NEO4J_TEST_PASS"),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	// Clean slate for the test key.
	g := buildStoreGraph()
	if err := s.Save(ctx, "agentgraph-test", g); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := s.Load(ctx, "agentgraph-test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.NodeCount() != g.NodeCount() || loaded.EdgeCount() != g.EdgeCount() {
		t.Fatalf("round-trip mismatch: %d/%d vs %d/%d",
			loaded.NodeCount(), loaded.EdgeCount(), g.NodeCount(), g.EdgeCount())
	}
	n, _ := loaded.Node("db")
	if !n.CrownJewel || n.Criticality != 95 {
		t.Fatalf("node properties lost: %+v", n)
	}
	if !loaded.HasEdge("mcp", "db", graph.EdgeCanAdmin) {
		t.Fatal("edge lost in round-trip")
	}

	// Save replaces: a smaller graph must fully replace the old one.
	g2 := graph.New()
	_ = g2.AddNode(&graph.Node{ID: "solo", Type: graph.NodeHost, Name: "solo"})
	if err := s.Save(ctx, "agentgraph-test", g2); err != nil {
		t.Fatalf("save 2: %v", err)
	}
	loaded2, err := s.Load(ctx, "agentgraph-test")
	if err != nil {
		t.Fatalf("load 2: %v", err)
	}
	if loaded2.NodeCount() != 1 {
		t.Fatalf("save must replace; got %d nodes", loaded2.NodeCount())
	}

	// Unknown key -> ErrNotFound.
	if _, err := s.Load(ctx, "agentgraph-ghost"); !IsNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func getenv(key string) string {
	return os.Getenv(key)
}
