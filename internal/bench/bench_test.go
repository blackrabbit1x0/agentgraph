// Package bench generates synthetic graphs and validates the PRD section
// 59 performance targets:
//
//	100,000 nodes / 500,000 edges
//	shortest-path query:      < 2 seconds
//	agent blast-radius:       < 5 seconds
//	graph search (node/edge): < 1 second
//
// The validation tests run only when RUN_PERF=1 is set (they take a few
// seconds); `make bench` runs them plus Go micro-benchmarks.
package bench

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/blast"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// Synthetic topology (deterministic, seed fixed):
//
//	500 agents --USES--> 2,000 MCP servers --CAN_READ/WRITE/MODIFY--> 20,000 repos
//	agents --AUTHENTICATES_AS--> 10,000 identities --CAN_READ--> repos (fanout 30)
//	repos --TRIGGERS--> 20,000 CI pipelines --CONTAINS_SECRET/CAN_ACCESS--> 20,000 secrets
//	CI --CAN_ASSUME--> 20,000 cloud roles; secrets --AUTHENTICATES_AS--> roles
//	roles --CAN_ACCESS/CAN_ADMIN--> 7,500 databases (every 50th a crown jewel)
//	plus role-to-role CAN_ASSUME chains and MCP-to-MCP CONNECTED_TO links.
//
// Totals: 100,000 nodes, ~518,000 edges.
const (
	nAgents     = 500
	nMCP        = 2000
	nIdentities = 10000
	nRepos      = 20000
	nCI         = 20000
	nSecrets    = 20000
	nRoles      = 20000
	nDBs        = 7500
	idFanout    = 30
)

// Generate builds the synthetic benchmark graph.
func Generate() *graph.Graph {
	g := graph.New()

	mk := func(prefix string, n int, t graph.NodeType, meta func(i int) map[string]any) []string {
		ids := make([]string, n)
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("%s-%06d", prefix, i)
			ids[i] = id
			name := fmt.Sprintf("%s %d", prefix, i)
			var m map[string]any
			if meta != nil {
				m = meta(i)
			}
			if err := g.AddNode(&graph.Node{
				ID: id, Type: t, Name: name, Provider: "bench",
				Metadata: m,
			}); err != nil {
				panic(err)
			}
		}
		return ids
	}

	agents := mk("agent", nAgents, graph.NodeAIAgent, func(i int) map[string]any {
		return map[string]any{"internet_access": i%2 == 0}
	})
	mcps := mk("mcp", nMCP, graph.NodeMCPServer, nil)
	identities := mk("identity", nIdentities, graph.NodeIdentity, func(i int) map[string]any {
		return map[string]any{"privilege": []string{"read", "write"}[i%2]}
	})
	repos := mk("repo", nRepos, graph.NodeRepository, func(i int) map[string]any {
		if i%5 == 0 {
			return map[string]any{"environment": "production"}
		}
		return nil
	})
	cis := mk("ci", nCI, graph.NodeCIPipeline, func(i int) map[string]any {
		if i%4 == 0 {
			return map[string]any{"environment": "production"}
		}
		return nil
	})
	secrets := mk("secret", nSecrets, graph.NodeSecret, func(i int) map[string]any {
		return map[string]any{"type": "bench_secret", "location": "bench"}
	})
	roles := mk("role", nRoles, graph.NodeCloudRole, func(i int) map[string]any {
		m := map[string]any{"privilege": []string{"read", "write", "admin"}[i%3]}
		if i%3 == 2 {
			m["environment"] = "production"
		}
		return m
	})
	dbs := mk("db", nDBs, graph.NodeDatabase, func(i int) map[string]any {
		return map[string]any{"environment": "production", "classification": "customer_data"}
	})
	for i, id := range dbs {
		if i%50 == 0 {
			n, _ := g.Node(id)
			n.CrownJewel = true
		}
	}

	add := func(src, tgt string, t graph.EdgeType) {
		if err := g.AddEdge(&graph.Edge{Source: src, Target: tgt, Type: t, Confidence: 1.0}); err != nil {
			panic(err)
		}
	}

	// Agents use MCP servers (4 each) and authenticate as identities.
	for i, a := range agents {
		for k := 0; k < 4; k++ {
			add(a, mcps[(i*4+k)%nMCP], graph.EdgeUses)
		}
		add(a, identities[i%nIdentities], graph.EdgeAuthenticatesAs)
		add(a, identities[(i+317)%nIdentities], graph.EdgeAuthenticatesAs)
	}

	// Identity -> repo reads (fanout 30): the bulk of the edges.
	for i, id := range identities {
		for k := 0; k < idFanout; k++ {
			add(id, repos[(i*idFanout+k)%nRepos], graph.EdgeCanRead)
		}
	}

	// MCP -> repos with three edge types.
	for i, r := range repos {
		m := mcps[i%nMCP]
		add(m, r, graph.EdgeCanRead)
		add(m, r, graph.EdgeCanWrite)
		add(m, r, graph.EdgeCanModify)
	}

	// Repo -> CI; CI -> secrets (two types); CI -> roles.
	for i, r := range repos {
		add(r, cis[i%nCI], graph.EdgeTriggers)
	}
	for i, c := range cis {
		add(c, secrets[i%nSecrets], graph.EdgeContainsSecret)
		add(c, secrets[(i+97)%nSecrets], graph.EdgeCanAccess)
		add(c, roles[i%nRoles], graph.EdgeCanAssume)
		add(c, repos[(i*7+3)%nRepos], graph.EdgeCanRead)
	}

	// Secrets -> roles; roles -> databases; role chains.
	for i, s := range secrets {
		add(s, roles[i%nRoles], graph.EdgeAuthenticatesAs)
	}
	for i, r := range roles {
		add(r, dbs[i%nDBs], graph.EdgeCanAccess)
		add(r, dbs[(i+11)%nDBs], graph.EdgeCanAdmin)
		add(r, roles[(i+7)%nRoles], graph.EdgeCanAssume)
	}

	// MCP clustering links.
	for i := 0; i < 10000; i++ {
		add(mcps[i%nMCP], mcps[(i+37)%nMCP], graph.EdgeConnectedTo)
	}

	return g
}

func requirePerf(t *testing.T) *graph.Graph {
	t.Helper()
	if os.Getenv("RUN_PERF") != "1" {
		t.Skip("performance validation skipped (set RUN_PERF=1 to run)")
	}
	return Generate()
}

func TestPerfGraphSize(t *testing.T) {
	if os.Getenv("RUN_PERF") != "1" && testing.Short() {
		t.Skip("short mode")
	}
	g := Generate()
	if g.NodeCount() != 100000 {
		t.Errorf("expected 100000 nodes, got %d", g.NodeCount())
	}
	if g.EdgeCount() < 500000 {
		t.Errorf("PRD target requires >= 500000 edges, got %d", g.EdgeCount())
	}
	t.Logf("graph: %d nodes / %d edges", g.NodeCount(), g.EdgeCount())
}

func TestPerfShortestPath(t *testing.T) {
	g := requirePerf(t)
	start := time.Now()
	p := paths.Shortest(g, "agent-000000", "db-007499")
	elapsed := time.Since(start)
	if p == nil {
		t.Fatal("expected a path from agent to database")
	}
	t.Logf("shortest path: %d hops in %s", p.Length(), elapsed)
	if elapsed > 2*time.Second {
		t.Errorf("PRD target: shortest path < 2s, took %s", elapsed)
	}
}

func TestPerfBlastRadius(t *testing.T) {
	g := requirePerf(t)
	start := time.Now()
	r, err := blast.Analyze(g, "agent-000000", paths.Options{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("blast radius: %v", err)
	}
	t.Logf("blast radius: %d reachable nodes, %d paths in %s",
		r.ReachableNodes, r.TotalPaths, elapsed)
	if elapsed > 5*time.Second {
		t.Errorf("PRD target: blast radius < 5s, took %s", elapsed)
	}
}

func TestPerfGraphSearch(t *testing.T) {
	g := requirePerf(t)
	start := time.Now()
	// Node lookup + adjacency + existence scan across the graph.
	n, ok := g.Node("role-012345")
	if !ok {
		t.Fatal("node lookup failed")
	}
	edges := g.OutEdges(n.ID)
	found := 0
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeCanAdmin {
			found++
		}
	}
	elapsed := time.Since(start)
	t.Logf("search: %d out-edges, %d CAN_ADMIN edges scanned in %s", len(edges), found, elapsed)
	if elapsed > time.Second {
		t.Errorf("PRD target: graph search < 1s, took %s", elapsed)
	}
}

func BenchmarkShortestPath(b *testing.B) {
	g := Generate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if paths.Shortest(g, "agent-000000", "db-007499") == nil {
			b.Fatal("no path")
		}
	}
}

func BenchmarkBlastRadius(b *testing.B) {
	g := Generate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := blast.Analyze(g, "agent-000000", paths.Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGraphBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Generate()
	}
}
