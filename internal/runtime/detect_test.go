package runtime

import (
	"testing"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

func buildDemo() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "finance-agent", Type: graph.NodeAIAgent, Name: "Finance Agent"},
		{ID: "github-mcp", Type: graph.NodeMCPServer, Name: "GitHub MCP"},
		{ID: "payments-repository", Type: graph.NodeRepository, Name: "Payments Repo"},
		{ID: "production-ci", Type: graph.NodeCIPipeline, Name: "Production CI"},
		{ID: "aws-deploy-token", Type: graph.NodeSecret, Name: "AWS Deploy Token"},
		{ID: "aws-deploy-role", Type: graph.NodeCloudRole, Name: "AWS Deploy Role"},
		{ID: "customer-database", Type: graph.NodeDatabase, Name: "Customer DB", Criticality: 95},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	edges := []*graph.Edge{
		{Source: "finance-agent", Target: "github-mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "github-mcp", Target: "payments-repository", Type: graph.EdgeCanWrite, Confidence: 1},
		{Source: "payments-repository", Target: "production-ci", Type: graph.EdgeTriggers, Confidence: 1},
		{Source: "production-ci", Target: "aws-deploy-token", Type: graph.EdgeContainsSecret, Confidence: 1},
		{Source: "aws-deploy-token", Target: "aws-deploy-role", Type: graph.EdgeAuthenticatesAs, Confidence: 1},
		{Source: "aws-deploy-role", Target: "customer-database", Type: graph.EdgeCanAdmin, Confidence: 1},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func ts(minute int) time.Time {
	return time.Date(2026, 9, 3, 10, minute, 0, 0, time.UTC)
}

func TestPartialExecution(t *testing.T) {
	d := New(buildDemo(), paths.Options{})

	events := []Event{
		{Timestamp: ts(0), Agent: "finance-agent", Action: "mcp_call", Tool: "github-mcp"},
		{Timestamp: ts(1), Agent: "finance-agent", Action: "tool_call", Tool: "github-mcp", Target: "payments-repository"},
		{Timestamp: ts(2), Agent: "finance-agent", Action: "pipeline_event", Target: "production-ci"},
		{Timestamp: ts(3), Agent: "finance-agent", Action: "secret_read", Target: "aws-deploy-token"},
	}

	alerts, err := d.Process(events)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected alerts for 4/6 stage progress")
	}

	// Expect one HIGH from the database path (fired at 3/6, next hop the
	// deploy token)...
	var dbHigh *Alert
	// ...and COMPLETE alerts for the shorter paths actually finished
	// (production-ci at 3/3, aws-deploy-token at 4/4).
	completes := map[string]bool{}
	for i := range alerts {
		a := alerts[i]
		if a.Agent != "finance-agent" {
			t.Errorf("alert attributed to %s", a.Agent)
		}
		if a.Target == "customer-database" && a.Level == LevelHigh {
			dbHigh = &alerts[i]
		}
		if a.Level == LevelComplete {
			completes[a.Target] = true
		}
	}
	if dbHigh == nil {
		t.Fatalf("expected a HIGH alert on the database path, got %+v", alerts)
	}
	if dbHigh.Stages != 3 || dbHigh.Total != 6 {
		t.Errorf("database HIGH should show 3/6, got %d/%d", dbHigh.Stages, dbHigh.Total)
	}
	if dbHigh.NextNode != "aws-deploy-token" {
		t.Errorf("next node should be aws-deploy-token, got %s", dbHigh.NextNode)
	}
	if !completes["production-ci"] || !completes["aws-deploy-token"] {
		t.Errorf("expected COMPLETE alerts for finished shorter paths, got %v", completes)
	}
}

func TestFullExecution(t *testing.T) {
	d := New(buildDemo(), paths.Options{})

	events := []Event{
		{Timestamp: ts(0), Agent: "finance-agent", Tool: "github-mcp"},
		{Timestamp: ts(1), Agent: "finance-agent", Target: "payments-repository"},
		{Timestamp: ts(2), Agent: "finance-agent", Target: "production-ci"},
		{Timestamp: ts(3), Agent: "finance-agent", Target: "aws-deploy-token"},
		{Timestamp: ts(4), Agent: "finance-agent", Target: "aws-deploy-role"},
		{Timestamp: ts(5), Agent: "finance-agent", Target: "customer-database"},
	}

	alerts, err := d.Process(events)
	if err != nil {
		t.Fatalf("process: %v", err)
	}

	var complete *Alert
	for i := range alerts {
		if alerts[i].Level == LevelComplete {
			complete = &alerts[i]
		}
	}
	if complete == nil {
		t.Fatal("expected a COMPLETE alert after reaching the target")
	}
	if complete.Stages != complete.Total {
		t.Errorf("complete alert should show %d/%d, got %d/%d", complete.Total, complete.Total, complete.Stages, complete.Total)
	}
}

func TestOutOfOrderDoesNotAdvance(t *testing.T) {
	d := New(buildDemo(), paths.Options{})

	// Events jump straight to the secret without traversing earlier nodes.
	events := []Event{
		{Timestamp: ts(0), Agent: "finance-agent", Target: "aws-deploy-token"},
	}
	alerts, err := d.Process(events)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("out-of-order events must not advance paths, got %d alerts", len(alerts))
	}
}

func TestOtherAgentEventsIgnored(t *testing.T) {
	d := New(buildDemo(), paths.Options{})
	events := []Event{
		{Timestamp: ts(0), Agent: "attacker-agent", Target: "customer-database"},
	}
	alerts, err := d.Process(events)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatal("events for unknown agents should be ignored")
	}
}

func TestFuzzyEventMatching(t *testing.T) {
	d := New(buildDemo(), paths.Options{})
	// "github" fuzzy-matches the github-mcp node.
	events := []Event{
		{Timestamp: ts(0), Agent: "finance-agent", Tool: "GitHub MCP"},
	}
	alerts, err := d.Process(events)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	// 1 of 6 stages: below threshold, no alert yet - but no error either.
	if len(alerts) != 0 {
		t.Fatal("single-stage progress should not alert yet")
	}
}

func TestAlertDeduplication(t *testing.T) {
	d := New(buildDemo(), paths.Options{})
	events := []Event{
		{Timestamp: ts(0), Agent: "finance-agent", Tool: "github-mcp"},
		{Timestamp: ts(1), Agent: "finance-agent", Target: "payments-repository"},
		{Timestamp: ts(2), Agent: "finance-agent", Target: "production-ci"},
		// Repeated observation of the same node: cursor doesn't move.
		{Timestamp: ts(3), Agent: "finance-agent", Target: "production-ci"},
		{Timestamp: ts(4), Agent: "finance-agent", Target: "production-ci"},
	}
	alerts, err := d.Process(events)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	// 3/6 = HIGH fires once per path; repeats must not re-fire.
	highsPerPath := map[string]int{}
	for _, a := range alerts {
		if a.Level == LevelHigh {
			highsPerPath[a.PathID]++
		}
	}
	for pathID, n := range highsPerPath {
		if n > 1 {
			t.Fatalf("HIGH fired %d times for path %s (must dedupe per path)", n, pathID)
		}
	}
	if len(highsPerPath) == 0 {
		t.Fatal("expected at least one HIGH alert at 3/6 stage progress")
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]Alert{
		{Level: LevelHigh, PathID: "PATH-0001", Stages: 3},
		{Level: LevelCritical, PathID: "PATH-0002", Stages: 5},
		{Level: LevelComplete, PathID: "PATH-0003", Stages: 6},
	})
	if s.TotalAlerts != 3 || s.High != 1 || s.Critical != 1 || s.Complete != 1 {
		t.Fatalf("summary wrong: %+v", s)
	}
	if len(s.PathsAtRisk) != 3 {
		t.Fatalf("paths at risk wrong: %v", s.PathsAtRisk)
	}
}
