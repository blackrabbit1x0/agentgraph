package config

import (
	"strings"
	"testing"
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
agents_extra: []
nodes:
  - id: a
    type: host
`
	_, _, err := LoadFromBytes([]byte(cfg))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate-ID error, got %v", err)
	}
}
