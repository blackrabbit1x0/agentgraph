package graph

import "testing"

func mkNode(id string, t NodeType) *Node {
	return &Node{ID: id, Type: t, Name: id}
}

func mkEdge(s, t string, et EdgeType) *Edge {
	return &Edge{Source: s, Target: t, Type: et, Confidence: 1.0}
}

func TestAddNodeValidation(t *testing.T) {
	g := New()
	if err := g.AddNode(&Node{ID: "", Type: NodeAIAgent}); err == nil {
		t.Fatal("expected error for empty ID")
	}
	if err := g.AddNode(&Node{ID: "x", Type: NodeType("WAT")}); err == nil {
		t.Fatal("expected error for unknown type")
	}
	if err := g.AddNode(&Node{ID: "x", Type: NodeAIAgent, Criticality: 200}); err == nil {
		t.Fatal("expected error for criticality > 100")
	}
	if err := g.AddNode(mkNode("x", NodeAIAgent)); err != nil {
		t.Fatalf("valid node rejected: %v", err)
	}
	if err := g.AddNode(mkNode("x", NodeAIAgent)); err == nil {
		t.Fatal("expected duplicate-ID error")
	}
}

func TestAddEdgeValidation(t *testing.T) {
	g := New()
	_ = g.AddNode(mkNode("a", NodeAIAgent))
	_ = g.AddNode(mkNode("b", NodeTool))

	if err := g.AddEdge(&Edge{Source: "a", Target: "b", Type: EdgeUses, Confidence: 0}); err == nil {
		t.Fatal("expected error for zero confidence")
	}
	if err := g.AddEdge(&Edge{Source: "a", Target: "b", Type: EdgeType("NOPE"), Confidence: 1}); err == nil {
		t.Fatal("expected error for unknown edge type")
	}
	if err := g.AddEdge(&Edge{Source: "a", Target: "c", Type: EdgeUses, Confidence: 1}); err == nil {
		t.Fatal("expected error for unknown target node")
	}
	if err := g.AddEdge(&Edge{Source: "a", Target: "a", Type: EdgeUses, Confidence: 1}); err == nil {
		t.Fatal("expected error for self-loop")
	}

	// Duplicate edges are idempotent.
	if err := g.AddEdge(mkEdge("a", "b", EdgeUses)); err != nil {
		t.Fatalf("valid edge rejected: %v", err)
	}
	if err := g.AddEdge(mkEdge("a", "b", EdgeUses)); err != nil {
		t.Fatalf("duplicate edge should be ignored, got: %v", err)
	}
	if g.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge, got %d", g.EdgeCount())
	}
}

func TestRemoveEdge(t *testing.T) {
	g := New()
	_ = g.AddNode(mkNode("a", NodeAIAgent))
	_ = g.AddNode(mkNode("b", NodeTool))
	_ = g.AddEdge(mkEdge("a", "b", EdgeUses))
	_ = g.AddEdge(mkEdge("a", "b", EdgeCanWrite))

	g.RemoveEdge("a", "b", EdgeUses)
	if g.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge after removal, got %d", g.EdgeCount())
	}
	if !g.HasEdge("a", "b", EdgeCanWrite) {
		t.Fatal("CAN_WRITE edge should remain")
	}
	if g.HasEdge("a", "b", EdgeUses) {
		t.Fatal("USES edge should be gone")
	}

	// Re-add the removed edge (remediation optimizer relies on this).
	if err := g.AddEdge(mkEdge("a", "b", EdgeUses)); err != nil {
		t.Fatalf("re-adding edge failed: %v", err)
	}
	if g.EdgeCount() != 2 {
		t.Fatalf("expected 2 edges after re-add, got %d", g.EdgeCount())
	}
}

func TestEffectiveRisk(t *testing.T) {
	e := &Edge{Source: "a", Target: "b", Type: EdgeCanAdmin, Confidence: 1}
	if e.EffectiveRisk() != 95 {
		t.Fatalf("expected default CAN_ADMIN risk 95, got %d", e.EffectiveRisk())
	}
	e.Risk = 50
	if e.EffectiveRisk() != 50 {
		t.Fatalf("expected explicit risk 50, got %d", e.EffectiveRisk())
	}
}

func TestPrivilegeRank(t *testing.T) {
	if PrivilegeRank("admin") <= PrivilegeRank("write") {
		t.Fatal("admin must outrank write")
	}
	if PrivilegeRank("read") <= PrivilegeRank("none") {
		t.Fatal("read must outrank none")
	}
	if PrivilegeRank("ADMIN") != PrivilegeRank("admin") {
		t.Fatal("privilege comparison must be case-insensitive")
	}
}
