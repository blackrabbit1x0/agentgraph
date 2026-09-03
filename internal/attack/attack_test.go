package attack

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

func buildPath() *paths.Path {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "repo", Type: graph.NodeRepository, Name: "repo"},
		{ID: "ci", Type: graph.NodeCIPipeline, Name: "ci"},
		{ID: "token", Type: graph.NodeSecret, Name: "token"},
		{ID: "role", Type: graph.NodeCloudRole, Name: "role"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db"},
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
		{Source: "ci", Target: "token", Type: graph.EdgeContainsSecret, Confidence: 1},
		{Source: "token", Target: "role", Type: graph.EdgeAuthenticatesAs, Confidence: 1},
		{Source: "role", Target: "db", Type: graph.EdgeCanAdmin, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	ps, err := paths.Enumerate(g, "agent", paths.Options{})
	if err != nil {
		panic(err)
	}
	for _, p := range ps {
		if p.Target.ID == "db" {
			return p
		}
	}
	panic("path to db not found")
}

func has(items []Technique, id string) bool {
	for _, t := range items {
		if t.ID == id {
			return true
		}
	}
	return false
}

func hasAGT(items []AGT, id string) bool {
	for _, t := range items {
		if t.ID == id {
			return true
		}
	}
	return false
}

func TestAnalyzePathATTCK(t *testing.T) {
	a := AnalyzePath(buildPath())

	// TRIGGERS -> T1072, CONTAINS_SECRET -> T1552, CAN_ADMIN -> T1548,
	// AUTHENTICATES_AS -> T1078, repo write -> T1195.002.
	for _, want := range []string{"T1072", "T1552", "T1548", "T1078", "T1195.002"} {
		if !has(a.Techniques, want) {
			t.Errorf("missing technique %s in %v", want, a.Techniques)
		}
	}

	// USES has no ATT&CK mapping; ensure no technique was invented for it.
	if len(a.Techniques) != 5 {
		t.Errorf("expected exactly 5 techniques, got %d: %v", len(a.Techniques), a.Techniques)
	}
}

func TestAnalyzePathAGT(t *testing.T) {
	a := AnalyzePath(buildPath())

	for _, want := range []string{"AGT-006", "AGT-004", "AGT-010", "AGT-009", "AGT-008"} {
		if !hasAGT(a.AGTs, want) {
			t.Errorf("missing %s in %v", want, a.AGTs)
		}
	}
	// No cross-agent trust on this path.
	if hasAGT(a.AGTs, "AGT-005") {
		t.Error("AGT-005 should not fire without a second agent")
	}
	// No tool node -> no AGT-002/003.
	if hasAGT(a.AGTs, "AGT-002") || hasAGT(a.AGTs, "AGT-003") {
		t.Error("AGT-002/003 should require a TOOL node")
	}
}

func TestCrossAgentTrust(t *testing.T) {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "a", Type: graph.NodeAIAgent, Name: "a"},
		{ID: "b", Type: graph.NodeAIAgent, Name: "b"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db"},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	for _, e := range []*graph.Edge{
		{Source: "a", Target: "b", Type: graph.EdgeTrusts, Confidence: 1},
		{Source: "b", Target: "db", Type: graph.EdgeCanAccess, Confidence: 1},
	} {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	ps, _ := paths.Enumerate(g, "a", paths.Options{})
	if len(ps) == 0 {
		t.Fatal("no path")
	}
	a := AnalyzePath(ps[0])
	if !hasAGT(a.AGTs, "AGT-005") {
		t.Errorf("expected AGT-005 for path through another agent, got %v", a.AGTs)
	}
}
