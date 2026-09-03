package svg

import (
	"strings"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

func buildRenderGraph() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "Finance Agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "GitHub MCP"},
		{ID: "repo", Type: graph.NodeRepository, Name: "payments-prod"},
		{ID: "ci", Type: graph.NodeCIPipeline, Name: "deploy.yml"},
		{ID: "role", Type: graph.NodeCloudRole, Name: "aws-deploy"},
		{ID: "db", Type: graph.NodeDatabase, Name: "Prod DB", CrownJewel: true, Criticality: 95},
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
		{Source: "ci", Target: "role", Type: graph.EdgeCanAssume, Confidence: 1},
		{Source: "role", Target: "db", Type: graph.EdgeCanAdmin, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestRenderStructure(t *testing.T) {
	g := buildRenderGraph()
	out := Render(g, "AgentGraph: finance-agent", nil)

	// Well-formed SVG envelope.
	if !strings.HasPrefix(out, "<?xml") || !strings.Contains(out, "<svg") || !strings.Contains(out, "</svg>") {
		t.Fatal("SVG envelope malformed")
	}

	// All six nodes present with labels.
	for _, want := range []string{"Finance Agent", "GitHub MCP", "payments-prod", "deploy.yml", "aws-deploy", "Prod DB"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing node label %s", want)
		}
	}

	// Crown-jewel styling and legend.
	if !strings.Contains(out, "#e3b341") {
		t.Error("crown-jewel gold styling missing")
	}
	if !strings.Contains(out, "CROWN JEWEL") {
		t.Error("legend missing crown-jewel entry")
	}

	// Dangerous CAN_ADMIN edge uses the danger color.
	if !strings.Contains(out, "#f85149") {
		t.Error("danger edge color missing")
	}
}

func TestRenderHighlight(t *testing.T) {
	g := buildRenderGraph()
	ps, _ := paths.Enumerate(g, "agent", paths.Options{})
	if len(ps) == 0 {
		t.Fatal("expected paths")
	}
	// Longest path: agent -> ... -> db.
	var target *paths.Path
	for _, p := range ps {
		if p.Target.ID == "db" {
			target = p
		}
	}
	if target == nil {
		t.Fatal("expected a path to db")
	}

	out := Render(g, "highlighted", NewHighlight(target))
	if !strings.Contains(out, "#58a6ff") {
		t.Error("highlight color missing")
	}
	if strings.Count(out, `stroke="#58a6ff"`) < 7 {
		t.Errorf("expected highlight styling on path nodes and edges, got %d",
			strings.Count(out, `stroke="#58a6ff"`))
	}
}

func TestEscapeXML(t *testing.T) {
	if got := escapeXML(`a<b>&"c"`); got != "a&lt;b&gt;&amp;&quot;c&quot;" {
		t.Errorf("escapeXML = %s", got)
	}
}

func TestRenderEmptyGraph(t *testing.T) {
	out := Render(graph.New(), "empty", nil)
	if !strings.Contains(out, "<svg") {
		t.Error("empty graph should still render an SVG")
	}
}
