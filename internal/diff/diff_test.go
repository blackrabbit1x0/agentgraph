package diff

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// buildGraph constructs agent -> mcp -> repo -> db.
func buildGraph(dbCrown bool, extraWriteEdge bool) *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "repo", Type: graph.NodeRepository, Name: "repo"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 90, CrownJewel: dbCrown},
	}
	if extraWriteEdge {
		nodes = append(nodes, &graph.Node{ID: "ci", Type: graph.NodeCIPipeline, Name: "ci"})
		nodes = append(nodes, &graph.Node{ID: "role", Type: graph.NodeCloudRole, Name: "role"})
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	edges := []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "mcp", Target: "repo", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "repo", Target: "db", Type: graph.EdgeCanAccess, Confidence: 1},
	}
	if extraWriteEdge {
		// Introduces new paths: agent -> ... -> ci -> role -> db.
		edges = append(edges,
			&graph.Edge{Source: "repo", Target: "ci", Type: graph.EdgeTriggers, Confidence: 1},
			&graph.Edge{Source: "ci", Target: "role", Type: graph.EdgeCanAssume, Confidence: 1},
			&graph.Edge{Source: "role", Target: "db", Type: graph.EdgeCanAdmin, Confidence: 1},
		)
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestComputeIdentical(t *testing.T) {
	r, err := Compute(buildGraph(false, false), buildGraph(false, false))
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if !r.IsEmpty() {
		t.Fatalf("identical graphs should produce empty diff: %+v", r)
	}
}

func TestComputeNewEdgesAndPaths(t *testing.T) {
	oldG := buildGraph(false, false)
	newG := buildGraph(false, true)

	r, err := Compute(oldG, newG)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}

	// Structural diff: 2 new nodes, 3 new edges, nothing removed.
	if len(r.AddedNodes) != 2 {
		t.Errorf("expected 2 added nodes, got %d", len(r.AddedNodes))
	}
	if len(r.AddedEdges) != 3 {
		t.Errorf("expected 3 added edges, got %d", len(r.AddedEdges))
	}
	if len(r.RemovedNodes) != 0 || len(r.RemovedEdges) != 0 {
		t.Error("nothing should be removed")
	}

	// Path diff: the old path (agent->mcp->repo->db) still exists; the
	// longer admin path is new. Both end at db.
	if len(r.GonePaths) != 0 {
		t.Errorf("expected 0 gone paths, got %d", len(r.GonePaths))
	}
	if len(r.NewPaths) == 0 {
		t.Fatal("expected new attack paths")
	}
	found := false
	for _, p := range r.NewPaths {
		if p.TargetID == "db" && p.SourceID == "agent" && len(p.NodeChain) == 6 {
			found = true
			// Attribution: the new path must trace back to an added edge.
			attr := r.Attribution(p)
			if len(attr) == 0 {
				t.Error("new path has no attribution")
			}
			// The TRIGGERS edge into ci should be among them.
			sawTriggers := false
			for _, e := range attr {
				if e.Type == graph.EdgeTriggers && e.Target == "ci" {
					sawTriggers = true
				}
			}
			if !sawTriggers {
				t.Error("attribution should include repo TRIGGERS ci")
			}
		}
	}
	if !found {
		t.Fatal("expected the 6-hop admin path in NewPaths")
	}
}

func TestComputeRemovedPaths(t *testing.T) {
	oldG := buildGraph(false, true)
	newG := buildGraph(false, false)

	r, err := Compute(oldG, newG)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if len(r.NewPaths) != 0 {
		t.Errorf("expected 0 new paths, got %d", len(r.NewPaths))
	}
	if len(r.GonePaths) == 0 {
		t.Fatal("expected gone paths after edge removal")
	}
	if len(r.RemovedEdges) != 3 {
		t.Errorf("expected 3 removed edges, got %d", len(r.RemovedEdges))
	}
}

func TestPathSummaryString(t *testing.T) {
	s := &PathSummary{
		NodeChain: []string{"a", "b", "c"},
		EdgeTypes: []string{"USES", "CAN_WRITE"},
	}
	want := "a --USES--> b --CAN_WRITE--> c"
	if s.String() != want {
		t.Errorf("String() = %s, want %s", s.String(), want)
	}
}

func TestCrownJewelOnlyAffectsFlags(t *testing.T) {
	// Crown-jewel flag flips do not create structural or path changes.
	r, err := Compute(buildGraph(false, false), buildGraph(true, false))
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if len(r.AddedEdges) != 0 || len(r.NewPaths) != 0 || len(r.GonePaths) != 0 {
		t.Errorf("flag-only changes should not alter paths: %+v", r)
	}
}
