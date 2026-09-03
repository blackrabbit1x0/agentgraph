package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// fakeGitLab serves canned API responses. The variables endpoint
// deliberately includes `value` fields to prove they are dropped.
func fakeGitLab(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") == "" {
			w.WriteHeader(401)
			return
		}
		writeJSON(w, map[string]any{"username": "blackrabbit", "name": "Black Rabbit"})
	})
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{
				"name": "payments-prod-api", "path_with_namespace": "acme/payments-prod-api",
				"visibility": "private", "default_branch": "main",
				"permissions": map[string]any{
					"project_access": map[string]any{"access_level": 50},
				},
			},
			{
				"name": "internal-tools", "path_with_namespace": "acme/internal-tools",
				"visibility": "internal", "default_branch": "main",
				"permissions": map[string]any{
					"group_access": map[string]any{"access_level": 30},
				},
			},
			{
				"name": "docs", "path_with_namespace": "acme/docs",
				"visibility": "public", "default_branch": "main",
				"permissions": map[string]any{
					"project_access": map[string]any{"access_level": 20},
				},
			},
		})
	})
	mux.HandleFunc("/api/v4/projects/acme%2Fpayments-prod-api/variables", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{"key": "AWS_DEPLOY_KEY", "value": "AKIA_SUPER_SECRET_VALUE", "masked": true, "protected": true},
			{"key": "DB_PASSWORD", "value": "hunter2-prod-db-pw", "masked": true, "protected": false},
		})
	})
	mux.HandleFunc("/api/v4/projects/acme%2Finternal-tools/variables", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{})
	})
	mux.HandleFunc("/api/v4/projects/acme%2Fdocs/variables", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{})
	})

	return httptest.NewServer(mux)
}

func TestDiscover(t *testing.T) {
	srv := fakeGitLab(t)
	defer srv.Close()

	api, err := NewRestAPI(srv.URL, "glpat-test-token")
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{API: api})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	nodes := map[string]*graph.Node{}
	for _, n := range res.Nodes {
		nodes[n.ID] = n
	}

	for _, want := range []string{
		"gitlab:user:blackrabbit",
		"gitlab:repo:acme/payments-prod-api",
		"gitlab:repo:acme/internal-tools",
		"gitlab:repo:acme/docs",
		"gitlab:secret:acme/payments-prod-api/AWS_DEPLOY_KEY",
		"gitlab:secret:acme/payments-prod-api/DB_PASSWORD",
	} {
		if _, ok := nodes[want]; !ok {
			t.Errorf("missing node %s", want)
		}
	}

	// Access-level mapping.
	hasEdge := func(src, tgt string, et graph.EdgeType) bool {
		for _, e := range res.Edges {
			if e.Source == src && e.Target == tgt && e.Type == et {
				return true
			}
		}
		return false
	}
	if !hasEdge("gitlab:user:blackrabbit", "gitlab:repo:acme/payments-prod-api", graph.EdgeCanAdmin) {
		t.Error("owner (50) should map to CAN_ADMIN")
	}
	if !hasEdge("gitlab:user:blackrabbit", "gitlab:repo:acme/internal-tools", graph.EdgeCanWrite) {
		t.Error("developer (30) should map to CAN_WRITE")
	}
	if !hasEdge("gitlab:user:blackrabbit", "gitlab:repo:acme/docs", graph.EdgeCanRead) {
		t.Error("reporter (20) should map to CAN_READ")
	}
	if !hasEdge("gitlab:repo:acme/payments-prod-api", "gitlab:secret:acme/payments-prod-api/AWS_DEPLOY_KEY", graph.EdgeContainsSecret) {
		t.Error("repo -> variable CONTAINS_SECRET edge missing")
	}

	// CRITICAL: variable values must never reach the graph, even though
	// the API returns them.
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), "AKIA_SUPER_SECRET_VALUE") || strings.Contains(string(blob), "hunter2-prod-db-pw") {
		t.Fatal("variable value leaked into the graph")
	}

	// Production inference + variable metadata.
	if n := nodes["gitlab:repo:acme/payments-prod-api"]; n.Metadata["environment"] != "production" {
		t.Error("prod path should be tagged production")
	}
	if n := nodes["gitlab:secret:acme/payments-prod-api/AWS_DEPLOY_KEY"]; n.Metadata["masked"] != true || n.Metadata["protected"] != true {
		t.Error("variable flags not preserved")
	}

	// Provenance on every edge.
	for _, e := range res.Edges {
		if e.Provenance.Connector != "gitlab" {
			t.Errorf("edge %s->%s missing provenance", e.Source, e.Target)
		}
	}
}

func TestDiscoverRequiresAPI(t *testing.T) {
	if _, err := New(Options{}).Discover(context.Background()); err == nil {
		t.Fatal("expected error with nil API")
	}
}

func TestNewRestAPIRequiresToken(t *testing.T) {
	if _, err := NewRestAPI("", ""); err == nil {
		t.Fatal("expected error without token")
	}
}

func TestAccessEdgeMapping(t *testing.T) {
	cases := map[int]graph.EdgeType{
		50: graph.EdgeCanAdmin,
		40: graph.EdgeCanWrite,
		30: graph.EdgeCanWrite,
		20: graph.EdgeCanRead,
		10: graph.EdgeConnectedTo,
		0:  graph.EdgeConnectedTo,
	}
	for level, want := range cases {
		if got := accessEdge(level); got != want {
			t.Errorf("accessEdge(%d) = %s, want %s", level, got, want)
		}
	}
}
