package risk

import (
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

func node(id string, t graph.NodeType, criticality int, meta map[string]any) *graph.Node {
	return &graph.Node{ID: id, Type: t, Name: id, Criticality: criticality, Metadata: meta}
}

func edge(s, t string, et graph.EdgeType, conf float64) *graph.Edge {
	return &graph.Edge{Source: s, Target: t, Type: et, Confidence: conf}
}

func TestScoreBoundsAndSeverity(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, SeverityInformational}, {19, SeverityInformational},
		{20, SeverityLow}, {39, SeverityLow},
		{40, SeverityMedium}, {59, SeverityMedium},
		{60, SeverityHigh}, {79, SeverityHigh},
		{80, SeverityCritical}, {100, SeverityCritical},
	}
	for _, c := range cases {
		if got := SeverityFor(c.score); got != c.want {
			t.Errorf("SeverityFor(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestCriticalPathScoresHigh(t *testing.T) {
	agent := node("agent", graph.NodeAIAgent, 0, map[string]any{"internet_access": true})
	repo := node("repo", graph.NodeRepository, 0, map[string]any{"environment": "production"})
	db := node("db", graph.NodeDatabase, 95, map[string]any{"environment": "production"})
	db.CrownJewel = true

	nodes := []*graph.Node{agent, node("mcp", graph.NodeMCPServer, 0, nil), repo, db}
	edges := []*graph.Edge{
		edge("agent", "mcp", graph.EdgeUses, 1.0),
		edge("mcp", "repo", graph.EdgeCanWrite, 1.0),
		edge("repo", "db", graph.EdgeCanAdmin, 1.0),
	}

	res := ScorePath(nodes, edges, 1.0)
	if res.Score < 80 {
		t.Fatalf("production crown-jewel admin path should be CRITICAL, got %d (%s)",
			res.Score, res.Severity)
	}
	if len(res.Factors) == 0 {
		t.Fatal("score must include an explainable factor breakdown")
	}
}

func TestLowValuePathScoresLow(t *testing.T) {
	agent := node("assistant", graph.NodeAIAgent, 0, map[string]any{"requires_approval": true})
	cal := node("events", graph.NodeDataset, 10, nil)

	res := ScorePath([]*graph.Node{agent, cal},
		[]*graph.Edge{edge("assistant", "events", graph.EdgeCanRead, 1.0)}, 1.0)
	if res.Score >= 40 {
		t.Fatalf("calendar read path should score low, got %d (%s)", res.Score, res.Severity)
	}
}

func TestConfidenceScaling(t *testing.T) {
	agent := node("agent", graph.NodeAIAgent, 0, nil)
	db := node("db", graph.NodeDatabase, 90, nil)
	nodes := []*graph.Node{agent, db}
	edges := []*graph.Edge{edge("agent", "db", graph.EdgeCanAccess, 1.0)}

	full := ScorePath(nodes, edges, 1.0)
	scaled := ScorePath(nodes, edges, 0.5)
	if scaled.Score > full.Score {
		t.Fatalf("lower confidence must not increase score (%d vs %d)", scaled.Score, full.Score)
	}
	if scaled.Score != full.Score/2 && scaled.Score != (full.Score+1)/2 {
		t.Fatalf("expected score halved by 0.5 confidence, got %d vs %d", scaled.Score, full.Score)
	}
}

func TestApprovalMitigationReducesScore(t *testing.T) {
	mk := func(approval bool) Result {
		meta := map[string]any{}
		if approval {
			meta["requires_approval"] = true
		}
		agent := node("agent", graph.NodeAIAgent, 0, meta)
		db := node("db", graph.NodeDatabase, 90, nil)
		return ScorePath([]*graph.Node{agent, db},
			[]*graph.Edge{edge("agent", "db", graph.EdgeCanAccess, 1.0)}, 1.0)
	}
	if mk(true).Score >= mk(false).Score {
		t.Fatal("approval requirement must reduce the score")
	}
}

func TestScoreNeverOutOfRange(t *testing.T) {
	agent := node("agent", graph.NodeAIAgent, 100, map[string]any{"internet_access": true})
	db := node("db", graph.NodeDatabase, 100, map[string]any{"environment": "production"})
	db.CrownJewel = true
	res := ScorePath([]*graph.Node{agent, db},
		[]*graph.Edge{edge("agent", "db", graph.EdgeCanExecute, 1.0)}, 1.0)
	if res.Score > 100 || res.Score < 0 {
		t.Fatalf("score out of range: %d", res.Score)
	}
}
