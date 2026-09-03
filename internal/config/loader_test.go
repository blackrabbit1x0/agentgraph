package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

const goodConfig = `
agents:
  - id: finance-agent
    name: Finance Agent
    criticality: 60
    metadata:
      internet_access: true

mcp_servers:
  - id: github-mcp
    name: GitHub MCP

secrets:
  - id: db-secret
    name: DB Secret
    metadata:
      type: database_password
      location: secrets-manager

repositories:
  - id: payments-repo
    name: Payments Repo
    metadata:
      environment: production

cloud_roles:
  - id: deploy-role
    name: Deploy Role
    metadata:
      privilege: admin

databases:
  - id: prod-db
    name: Prod DB
    criticality: 95

crown_jewels:
  - prod-db

relationships:
  - source: finance-agent
    target: github-mcp
    type: USES
  - source: github-mcp
    target: payments-repo
    type: can_write
    confidence: 0.9
  - source: payments-repo
    target: deploy-role
    type: TRIGGERS
  - source: deploy-role
    target: prod-db
    type: CAN_ACCESS
  - source: deploy-role
    target: db-secret
    type: CAN_READ
`

func TestLoadGoodConfig(t *testing.T) {
	g, warnings, err := LoadFromBytes([]byte(goodConfig))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if g.NodeCount() != 6 {
		t.Fatalf("expected 6 nodes, got %d", g.NodeCount())
	}
	if g.EdgeCount() != 5 {
		t.Fatalf("expected 5 edges, got %d", g.EdgeCount())
	}

	n, _ := g.Node("prod-db")
	if !n.CrownJewel {
		t.Fatal("prod-db should be a crown jewel")
	}
	if n.Criticality != 95 {
		t.Fatalf("criticality not preserved: %d", n.Criticality)
	}

	// Edge types are normalized to upper case; confidence preserved.
	e := g.EdgeBetween("github-mcp", "payments-repo")
	if len(e) != 1 || e[0].Type != "CAN_WRITE" {
		t.Fatalf("edge type normalization failed: %v", e)
	}
	if e[0].Confidence != 0.9 {
		t.Fatalf("confidence not preserved: %f", e[0].Confidence)
	}

	// Default confidence of 1.0 applied when omitted.
	e = g.EdgeBetween("finance-agent", "github-mcp")
	if e[0].Confidence != 1.0 {
		t.Fatalf("default confidence not applied: %f", e[0].Confidence)
	}
}

func TestSecretRedaction(t *testing.T) {
	cfg := `
secrets:
  - id: leaked
    name: Leaked
    metadata:
      type: api_token
      value: "sk-super-secret-123"
      password: "hunter2"
      location: config-file
`
	g, warnings, err := LoadFromBytes([]byte(cfg))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	n, _ := g.Node("leaked")
	if _, ok := n.Metadata["value"]; ok {
		t.Fatal("secret value must never be stored in the graph")
	}
	if _, ok := n.Metadata["password"]; ok {
		t.Fatal("password must never be stored in the graph")
	}
	if _, ok := n.Metadata["location"]; !ok {
		t.Fatal("benign metadata must be preserved")
	}
	if len(warnings) != 2 {
		t.Fatalf("expected 2 redaction warnings, got %v", warnings)
	}
}

func TestSecretRedactionAllNodeTypesAndEdges(t *testing.T) {
	// Regression: a secret pasted into a non-SECRET node's metadata or an
	// edge's metadata must also be redacted, with key normalization
	// covering camelCase, kebab-case, and compound names.
	cfg := `
agents:
  - id: a
    metadata:
      apiKey: "AKIA123"
      auth_token: "tok"
      client-secret: "cs"
      environment: production
relationships:
  - source: a
    target: m
    type: USES
    metadata:
      api_key: "AKIA456"
      note: benign
nodes:
  - id: m
    type: mcp_server
`
	g, warnings, err := LoadFromBytes([]byte(cfg))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	n, _ := g.Node("a")
	for _, forbidden := range []string{"apiKey", "auth_token", "client-secret"} {
		if _, ok := n.Metadata[forbidden]; ok {
			t.Errorf("agent metadata field %q must be redacted", forbidden)
		}
	}
	if _, ok := n.Metadata["environment"]; !ok {
		t.Error("benign agent metadata must be preserved")
	}
	e := g.EdgeBetween("a", "m")
	if len(e) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(e))
	}
	if _, ok := e[0].Metadata["api_key"]; ok {
		t.Error("edge metadata api_key must be redacted")
	}
	if _, ok := e[0].Metadata["note"]; !ok {
		t.Error("benign edge metadata must be preserved")
	}
	if len(warnings) != 4 {
		t.Fatalf("expected 4 redaction warnings, got %v", warnings)
	}

	// Nothing sensitive anywhere in the serialized graph.
	b, _ := json.Marshal(g.Snapshot())
	for _, needle := range []string{"AKIA123", "AKIA456", "\"tok\"", "\"cs\""} {
		if strings.Contains(string(b), needle) {
			t.Errorf("sensitive value %s leaked into the graph", needle)
		}
	}
}

func TestSecretNodeAggressiveRedaction(t *testing.T) {
	// SECRET nodes get substring matching: any key mentioning secrets.
	cfg := `
secrets:
  - id: s
    metadata:
      signing_key_material: "xyz"
      refresh_token_value: "abc"
`
	g, _, err := LoadFromBytes([]byte(cfg))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	n, _ := g.Node("s")
	if len(n.Metadata) != 0 {
		t.Fatalf("SECRET node keys mentioning secrets must all be redacted, kept: %v", n.Metadata)
	}
}

func TestInvalidConfigsRejected(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"unknown edge type", `
nodes:
  - id: a
    type: ai_agent
  - id: a2
    type: api
relationships:
  - source: a
    target: a2
    type: NOPE
`},
		{"unknown source", `
nodes:
  - id: m
    type: mcp_server
relationships:
  - source: ghost
    target: m
    type: USES
`},
		{"missing relationship type", `
agents:
  - id: a
mcp_servers:
  - id: m
relationships:
  - source: a
    target: m
`},
	}
	for _, c := range cases {
		_, _, err := LoadFromBytes([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s: expected error, got none", c.name)
		}
	}
}

func TestGenericNodesSection(t *testing.T) {
	cfg := `
nodes:
  - id: agent-1
    type: ai_agent
  - id: host-1
    type: host
    criticality: 50
relationships:
  - source: agent-1
    target: host-1
    type: CAN_ACCESS
`
	g, _, err := LoadFromBytes([]byte(cfg))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n, _ := g.Node("host-1"); n.Type != "HOST" || n.Criticality != 50 {
		t.Fatal("generic node section not honored")
	}
}

func TestDuplicateNodeRejected(t *testing.T) {
	cfg := `
agents:
  - id: a
nodes:
  - id: a
    type: host
`
	_, _, err := LoadFromBytes([]byte(cfg))
	if err == nil || !strings.Contains(err.Error(), "conflicting types") {
		t.Fatalf("expected conflicting-types error, got %v", err)
	}
}

func TestMergeEnrichesExistingNode(t *testing.T) {
	// The assembler merge path: re-registering the same ID with the same
	// type enriches metadata instead of failing.
	g := graph.New()
	if err := g.AddNode(&graph.Node{ID: "a", Type: graph.NodeAIAgent, Name: "a"}); err != nil {
		t.Fatal(err)
	}
	_ = g
	asm := graph.NewAssembler()
	if err := asm.AddNode(&graph.Node{ID: "a", Type: graph.NodeAIAgent, Name: "Agent One", Criticality: 50}); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := asm.AddNode(&graph.Node{ID: "a", Type: graph.NodeAIAgent, Metadata: map[string]any{"owner": "sec-team"}}); err != nil {
		t.Fatalf("merge add: %v", err)
	}
	built, err := asm.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	n, _ := built.Node("a")
	if n.Name != "Agent One" || n.Criticality != 50 || n.Metadata["owner"] != "sec-team" {
		t.Fatalf("merge did not enrich node: %+v", n)
	}
}

func TestDeferredEdgeResolution(t *testing.T) {
	// A config may declare an edge whose endpoints a connector discovers
	// later; the assembler validates at Build time, not AddEdge time.
	asm := graph.NewAssembler()
	asm.AddEdge(&graph.Edge{Source: "agent", Target: "github:repo:org/repo", Type: graph.EdgeCanWrite, Confidence: 1})
	asm.AddEdge(&graph.Edge{Source: "agent", Target: "missing-node", Type: graph.EdgeUses, Confidence: 1})

	if err := asm.AddNode(&graph.Node{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"}); err != nil {
		t.Fatal(err)
	}

	if _, err := asm.Build(); err == nil {
		t.Fatal("expected error for unresolved edge endpoint")
	}

	if err := asm.AddNode(&graph.Node{ID: "github:repo:org/repo", Type: graph.NodeRepository, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if err := asm.AddNode(&graph.Node{ID: "missing-node", Type: graph.NodeRepository, Name: "m"}); err != nil {
		t.Fatal(err)
	}
	g, err := asm.Build()
	if err != nil {
		t.Fatalf("build after resolution: %v", err)
	}
	if g.EdgeCount() != 2 {
		t.Fatalf("expected 2 edges, got %d", g.EdgeCount())
	}
}
