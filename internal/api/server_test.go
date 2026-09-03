package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	rt "github.com/blackrabbit1x0/agentgraph/internal/runtime"
)

func buildTestGraph() *graph.Graph {
	g := graph.New()
	nodes := []*graph.Node{
		{ID: "agent", Type: graph.NodeAIAgent, Name: "agent"},
		{ID: "mcp", Type: graph.NodeMCPServer, Name: "mcp"},
		{ID: "db", Type: graph.NodeDatabase, Name: "db", Criticality: 90},
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			panic(err)
		}
	}
	for _, e := range []*graph.Edge{
		{Source: "agent", Target: "mcp", Type: graph.EdgeUses, Confidence: 1},
		{Source: "mcp", Target: "db", Type: graph.EdgeCanWrite, Confidence: 1},
	} {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

func TestNoTokenRequiredByDefault(t *testing.T) {
	srv := httptest.NewServer(NewServer(buildTestGraph()).Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/api/v1/graph")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200 without token, got %d", res.StatusCode)
	}
}

func TestTokenAuth(t *testing.T) {
	srv := httptest.NewServer(NewServerWithOptions(ServerOptions{
		Graph: buildTestGraph(),
		Token: "sekrit",
	}).Handler())
	defer srv.Close()

	// No token -> 401.
	res, err := http.Get(srv.URL + "/api/v1/graph")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("expected 401 without token, got %d", res.StatusCode)
	}

	// Wrong token -> 401.
	res, _ = http.Get(srv.URL + "/api/v1/graph?token=wrong")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("expected 401 with wrong token, got %d", res.StatusCode)
	}

	// Bearer header -> 200.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/graph", nil)
	req.Header.Set("Authorization", "Bearer sekrit")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("expected 200 with bearer token, got %d", res.StatusCode)
	}

	// Query param -> 200.
	res, _ = http.Get(srv.URL + "/api/v1/graph?token=sekrit")
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("expected 200 with query token, got %d", res.StatusCode)
	}

	// Non-API paths (the dashboard) are not authenticated.
	res, _ = http.Get(srv.URL + "/nope")
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("non-API path should bypass auth (404 here), got %d", res.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	s := NewServerWithOptions(ServerOptions{Graph: buildTestGraph()})
	s.lim = newRateLimiter(1, 5) // tight bucket for the test
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	allowed, limited := 0, 0
	for i := 0; i < 20; i++ {
		res, err := http.Get(srv.URL + "/api/v1/graph")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			allowed++
		} else if res.StatusCode == 429 {
			limited++
		} else {
			t.Fatalf("unexpected status %d", res.StatusCode)
		}
	}
	if allowed == 0 || limited == 0 {
		t.Fatalf("expected some allowed and some limited requests, got %d/%d", allowed, limited)
	}
}

func TestGraphSnapshotJSONIsSafePayload(t *testing.T) {
	// The API serializes node metadata verbatim; it is the dashboard's
	// job to escape it. This test pins the JSON shape so regressions in
	// escaping-relevant fields are caught.
	g := buildTestGraph()
	n, _ := g.Node("db")
	n.Metadata = map[string]any{"note": "<img src=x onerror=alert(1)>"}

	srv := httptest.NewServer(NewServer(g).Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/api/v1/graph")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var snap struct {
		Nodes []struct {
			ID       string         `json:"id"`
			Metadata map[string]any `json:"metadata"`
		} `json:"nodes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range snap.Nodes {
		if n.ID == "db" {
			found = true
			if n.Metadata["note"] != "<img src=x onerror=alert(1)>" {
				t.Error("metadata should round-trip verbatim (dashboard escapes)")
			}
		}
	}
	if !found {
		t.Fatal("db node missing from snapshot")
	}
}

func TestAlertHubSubscriberCap(t *testing.T) {
	hub := NewAlertHub()
	for i := 0; i < maxSubscribers; i++ {
		_, unsub, ok := hub.Subscribe()
		if !ok {
			t.Fatalf("subscriber %d rejected before cap", i)
		}
		defer unsub()
	}
	if _, _, ok := hub.Subscribe(); ok {
		t.Fatal("subscriber beyond cap must be rejected")
	}
}

func TestAlertHubSubscribeBeforeHistory(t *testing.T) {
	hub := NewAlertHub()
	ch, unsub, ok := hub.Subscribe()
	if !ok {
		t.Fatal("subscribe failed")
	}
	defer unsub()
	// Publish AFTER subscribing: must arrive on the channel.
	hub.Publish(rt.Alert{PathID: "PATH-0001"})
	select {
	case a := <-ch:
		if a.PathID != "PATH-0001" {
			t.Fatalf("wrong alert: %+v", a)
		}
	default:
		t.Fatal("alert published after subscribe must be delivered")
	}
}

func TestOptimizeDoesNotMutateGraph(t *testing.T) {
	// The remediation endpoint must never mutate the served graph -
	// concurrent readers would race.
	g := buildTestGraph()
	before := g.EdgeCount()

	rec, err := remediation.Optimize(g, "agent", paths.Options{}, 20)
	if err != nil {
		t.Fatalf("optimize: %v", err)
	}
	_ = rec
	if g.EdgeCount() != before {
		t.Fatalf("graph mutated by Optimize: %d -> %d edges", before, g.EdgeCount())
	}
	if !g.HasEdge("agent", "mcp", graph.EdgeUses) {
		t.Fatal("edge removed from original graph")
	}
}
