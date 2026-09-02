package blast

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

func buildDemoGraph() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent", Metadata: map[string]any{"internet_access": true}},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "tool", Type: graph.NodeTool, Name: "tool"},
		{ID: "repo", Type: graph.NodeRepository, Name: "repo", Metadata: map[string]any{"environment": "production"}},
		{ID: "slack-api", Type: graph.NodeAPI, Name: "slack"},
		{ID: "role", Type: graph.NodeCloudRole, Name: "role", Metadata: map[string]any{"privilege": "admin", "environment": "production"}},
		{ID: "secret", Type: graph.NodeSecret, Name: "secret"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 95, CrownJewel: true, Metadata: map[string]any{"environment": "production"}},
		{ID: "identity", Type: graph.NodeIdentity, Name: "identity", Metadata: map[string]any{"privilege": "read"}},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	edges := []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "agent", Target: "slack-api", Type: graph.EdgeUses, Confidence: 1},
		{Source: "agent", Target: "identity", Type: graph.EdgeAuthenticatesAs, Confidence: 1},
		{Source: "mcp", Target: "repo", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "repo", Target: "role", Type: graph.EdgeCanAssume, Confidence: 1},
		{Source: "role", Target: "secret", Type: graph.EdgeCanRead, Confidence: 1},
		{Source: "secret", Target: "db", Type: graph.EdgeAuthenticatesAs, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestBlastRadius(t *testing.T) {
	g := buildDemoGraph()
	r, err := Analyze(g, "agent", paths.Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// Direct: mcp, slack-api, identity (3).
	if r.Direct[graph.NodeMCPServer] != 1 || r.Direct[graph.NodeAPI] != 1 || r.Direct[graph.NodeIdentity] != 1 {
		t.Fatalf("direct counts wrong: %v", r.Direct)
	}
	// Indirect: repo, role, secret, db (4).
	if r.Indirect[graph.NodeRepository] != 1 || r.Indirect[graph.NodeDatabase] != 1 {
		t.Fatalf("indirect counts wrong: %v", r.Indirect)
	}
	if r.ReachableNodes != 7 {
		t.Fatalf("expected 7 reachable nodes, got %d", r.ReachableNodes)
	}
	if len(r.ReachableCrownJewels) != 1 || r.ReachableCrownJewels[0] != "db" {
		t.Fatalf("crown jewels wrong: %v", r.ReachableCrownJewels)
	}
	if r.ReachableSecrets != 1 {
		t.Fatalf("expected 1 reachable secret, got %d", r.ReachableSecrets)
	}
	if r.ReachableIdentities != 1 {
		t.Fatalf("expected 1 reachable identity, got %d", r.ReachableIdentities)
	}
	if r.CloudRoles != 1 {
		t.Fatalf("expected 1 cloud role, got %d", r.CloudRoles)
	}
	if r.HighestPrivilege != "admin" {
		t.Fatalf("expected admin as highest privilege, got %q", r.HighestPrivilege)
	}
	if r.TotalPaths == 0 || r.MostDangerous == nil {
		t.Fatal("expected attack paths and a most dangerous path")
	}
	if r.ExposureScore <= 0 || r.ExposureScore > 100 {
		t.Fatalf("exposure score out of range: %d", r.ExposureScore)
	}
}

func TestBlastRadiusRejectsNonAgent(t *testing.T) {
	g := buildDemoGraph()
	if _, err := Analyze(g, "repo", paths.Options{}); err == nil {
		t.Fatal("expected error for non-agent node")
	}
	if _, err := Analyze(g, "ghost", paths.Options{}); err == nil {
		t.Fatal("expected error for unknown node")
	}
}

func TestUnreachableAgent(t *testing.T) {
	g := buildDemoGraph()
	_ = g.AddNode(&graph.Node{ID: "lonely", Type: graph.NodeAIAgent, Name: "lonely"})
	r, err := Analyze(g, "lonely", paths.Options{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if r.ReachableNodes != 0 || r.TotalPaths != 0 {
		t.Fatalf("isolated agent should have no reach, got %d nodes / %d paths",
			r.ReachableNodes, r.TotalPaths)
	}
}
