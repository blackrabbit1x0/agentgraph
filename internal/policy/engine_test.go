package policy

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

func buildPolicyGraph() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "assistant", Type: graph.NodeAIAgent, Name: "assistant"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "repo", Type: graph.NodeRepository, Name: "repo", Metadata: map[string]any{"environment": "production"}},
		{ID: "admin-role", Type: graph.NodeCloudRole, Name: "admin role", Provider: "aws", Metadata: map[string]any{"privilege": "admin", "environment": "production"}},
		{ID: "secret", Type: graph.NodeSecret, Name: "secret"},
		{ID: "calendar", Type: graph.NodeDataset, Name: "calendar", Criticality: 10},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	edges := []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "mcp", Target: "repo", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "repo", Target: "admin-role", Type: graph.EdgeCanAssume, Confidence: 1},
		{Source: "repo", Target: "secret", Type: graph.EdgeContainsSecret, Confidence: 1},
		{Source: "assistant", Target: "calendar", Type: graph.EdgeCanRead, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestDefaultRules(t *testing.T) {
	g := buildPolicyGraph()
	violations, err := Evaluate(g, DefaultRules(), paths.Options{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// agent reaches: repo (production), admin-role (prod + admin
	// privilege), secret. All three default rules fire.
	byRule := map[string]int{}
	for _, v := range violations {
		byRule[v.RuleID]++
		if v.Agent != "agent" {
			t.Errorf("violation attributed to wrong agent %s", v.Agent)
		}
	}
	if byRule["AGENT-001"] == 0 {
		t.Error("AGENT-001 (admin) should fire for agent -> admin-role")
	}
	if byRule["AGENT-002"] == 0 {
		t.Error("AGENT-002 (production) should fire for agent -> repo/admin-role")
	}
	if byRule["AGENT-003"] == 0 {
		t.Error("AGENT-003 (secrets) should fire for agent -> secret")
	}

	// The low-risk assistant must have zero violations.
	for _, v := range violations {
		if v.Agent == "assistant" {
			t.Errorf("assistant should not violate any rule (%s -> %s)", v.Agent, v.Target)
		}
	}

	// Violations carry full path evidence.
	for _, v := range violations {
		if len(v.Path) < 2 || len(v.PathEdgeTypes) != len(v.Path)-1 {
			t.Errorf("violation %s missing path evidence: %v", v.RuleID, v.Path)
		}
	}
}

func TestCustomRule(t *testing.T) {
	set, err := Parse([]byte(`
rules:
  - id: CUST-001
    name: No AWS reach
    severity: high
    when:
      node_type: AI_AGENT
    deny_reach:
      provider: aws
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	violations, err := Evaluate(buildPolicyGraph(), set, paths.Options{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("custom provider rule should fire for agent -> admin-role (aws)")
	}
	for _, v := range violations {
		if v.Target != "admin-role" {
			t.Errorf("unexpected violation target %s", v.Target)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte("rules:\n  - name: no id\n    severity: high\n")); err == nil {
		t.Error("rule without id should be rejected")
	}
	if _, err := Parse([]byte("rules:\n  - id: X\n    severity: banana\n")); err == nil {
		t.Error("invalid severity should be rejected")
	}
	if _, err := Parse([]byte("rules: []")); err != nil {
		t.Errorf("empty rule set should parse: %v", err)
	}
}

func TestMatchesSelector(t *testing.T) {
	n := &graph.Node{
		ID:         "x",
		Type:       graph.NodeCloudRole,
		Provider:   "aws",
		CrownJewel: true,
		Metadata: map[string]any{
			"environment": "production",
			"privilege":   "admin",
			"tags":        "pii, financial",
		},
	}

	cases := []struct {
		name string
		sel  *Selector
		want bool
	}{
		{"type match", &Selector{NodeType: "cloud_role"}, true},
		{"type mismatch", &Selector{NodeType: "secret"}, false},
		{"provider", &Selector{Provider: "aws"}, true},
		{"env", &Selector{Environment: "production"}, true},
		{"env mismatch", &Selector{Environment: "staging"}, false},
		{"privilege case-insensitive", &Selector{Privilege: "Admin"}, true},
		{"metadata", &Selector{HasMetadata: map[string]string{"privilege": "admin"}}, true},
		{"metadata mismatch", &Selector{HasMetadata: map[string]string{"privilege": "read"}}, false},
		{"crown true", &Selector{CrownJewel: boolPtr(true)}, true},
		{"crown false", &Selector{CrownJewel: boolPtr(false)}, false},
		{"tag contains", &Selector{HasMetadata: map[string]string{"tags": "financial"}}, true},
		{"tag absent", &Selector{HasMetadata: map[string]string{"tags": "hr"}}, false},
	}
	for _, c := range cases {
		if got := MatchesSelector(n, c.sel); got != c.want {
			t.Errorf("%s: MatchesSelector = %v, want %v", c.name, got, c.want)
		}
	}
}

func boolPtr(b bool) *bool { return &b }
