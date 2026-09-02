package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gh "github.com/google/go-github/v74/github"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// fakeGitHub serves canned REST responses for the endpoints the connector
// uses. repos list "payments-prod-api" (admin), "internal-tools" (push) and a
// fork that should be excluded.
func fakeGitHub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"login": "blackrabbit1x0", "name": "Black Rabbit", "type": "User"})
	})
	mux.HandleFunc("/users/blackrabbit1x0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"login": "blackrabbit1x0", "name": "Black Rabbit", "type": "User"})
	})
	mux.HandleFunc("/users/blackrabbit1x0/repos", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{
				"name": "payments-prod-api", "full_name": "blackrabbit1x0/payments-prod-api",
				"private": true, "fork": false, "default_branch": "main",
				"owner":       map[string]any{"login": "blackrabbit1x0"},
				"permissions": map[string]bool{"admin": true, "push": true, "pull": true},
			},
			{
				"name": "internal-tools", "full_name": "blackrabbit1x0/internal-tools",
				"private": true, "fork": false, "default_branch": "main",
				"owner":       map[string]any{"login": "blackrabbit1x0"},
				"permissions": map[string]bool{"admin": false, "push": true, "pull": true},
			},
			{
				"name": "some-fork", "full_name": "blackrabbit1x0/some-fork",
				"private": false, "fork": true,
				"owner":       map[string]any{"login": "blackrabbit1x0"},
				"permissions": map[string]bool{"admin": false, "push": true, "pull": true},
			},
		})
	})
	mux.HandleFunc("/repos/blackrabbit1x0/payments-prod-api/actions/workflows", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"workflows": []map[string]any{
			{"id": 1, "name": "Deploy Production", "path": "deploy-production.yml", "state": "active"},
		}})
	})
	mux.HandleFunc("/repos/blackrabbit1x0/internal-tools/actions/workflows", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"workflows": []map[string]any{}})
	})
	mux.HandleFunc("/repos/blackrabbit1x0/payments-prod-api/actions/secrets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"secrets": []map[string]any{
			{"name": "AWS_DEPLOY_TOKEN", "updated_at": "2026-08-01T00:00:00Z"},
		}})
	})
	mux.HandleFunc("/repos/blackrabbit1x0/internal-tools/actions/secrets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"secrets": []map[string]any{}})
	})

	// NewEnterpriseClient prefixes all paths with /api/v3/, so strip it.
	prefix := http.StripPrefix("/api/v3", mux)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			prefix.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func newTestClient(t *testing.T, srv *httptest.Server) *gh.Client {
	t.Helper()
	client, err := newEnterpriseClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func newEnterpriseClient(baseURL string) (*gh.Client, error) {
	return gh.NewEnterpriseClient(baseURL, baseURL, nil)
}

func TestDiscover(t *testing.T) {
	srv := fakeGitHub(t)
	defer srv.Close()

	c := New(Options{Client: newTestClient(t, srv)})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	ids := map[string]*graph.Node{}
	for _, n := range res.Nodes {
		ids[n.ID] = n
	}

	// Node expectations.
	for _, want := range []string{
		"github:user:blackrabbit1x0",
		"github:repo:blackrabbit1x0/payments-prod-api",
		"github:repo:blackrabbit1x0/internal-tools",
		"github:workflow:blackrabbit1x0/payments-prod-api/deploy-production.yml",
		"github:secret:blackrabbit1x0/payments-prod-api/AWS_DEPLOY_TOKEN",
	} {
		if _, ok := ids[want]; !ok {
			t.Errorf("missing node %s", want)
		}
	}

	// Fork excluded.
	if _, ok := ids["github:repo:blackrabbit1x0/some-fork"]; ok {
		t.Error("fork should be excluded")
	}

	// Secret node must not carry a value field (API gives none; guard anyway).
	for _, n := range res.Nodes {
		if n.Type == graph.NodeSecret {
			for k := range n.Metadata {
				lk := strings.ToLower(k)
				if lk == "value" || lk == "plaintext" || lk == "token" {
					t.Errorf("secret node %s carries forbidden field %s", n.ID, k)
				}
			}
		}
	}

	// Edge expectations.
	has := func(src string, tgt string, et graph.EdgeType) bool {
		for _, e := range res.Edges {
			if e.Source == src && e.Target == tgt && e.Type == et {
				return true
			}
		}
		return false
	}
	if !has("github:user:blackrabbit1x0", "github:repo:blackrabbit1x0/payments-prod-api", graph.EdgeCanAdmin) {
		t.Error("admin permission on payments-prod-api not modeled as CAN_ADMIN")
	}
	if !has("github:user:blackrabbit1x0", "github:repo:blackrabbit1x0/internal-tools", graph.EdgeCanWrite) {
		t.Error("push permission on internal-tools not modeled as CAN_WRITE")
	}
	if !has("github:repo:blackrabbit1x0/payments-prod-api", "github:workflow:blackrabbit1x0/payments-prod-api/deploy-production.yml", graph.EdgeTriggers) {
		t.Error("repo -> workflow TRIGGERS edge missing")
	}
	if !has("github:repo:blackrabbit1x0/payments-prod-api", "github:secret:blackrabbit1x0/payments-prod-api/AWS_DEPLOY_TOKEN", graph.EdgeContainsSecret) {
		t.Error("repo -> secret CONTAINS_SECRET edge missing")
	}

	// Provenance on every edge.
	for _, e := range res.Edges {
		if e.Provenance.Connector != "github" {
			t.Errorf("edge %s->%s missing provenance", e.Source, e.Target)
		}
	}
}

func TestDiscoverProductionRepoMetadata(t *testing.T) {
	srv := fakeGitHub(t)
	defer srv.Close()

	c := New(Options{Client: newTestClient(t, srv)})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	for _, n := range res.Nodes {
		if n.ID == "github:repo:blackrabbit1x0/payments-prod-api" {
			if n.Metadata["environment"] != "production" {
				t.Errorf("payments-prod-api should be tagged production, got %v", n.Metadata["environment"])
			}
			return
		}
	}
	t.Fatal("payments-prod-api repo node not found")
}

func TestDiscoverRequiresClient(t *testing.T) {
	c := New(Options{})
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected error with nil client")
	}
}

func TestNodeIDStability(t *testing.T) {
	// YAML configs reference connector node IDs; assert the scheme.
	if !strings.HasPrefix(fmt.Sprintf("%s", idRepo), "github:repo:") {
		t.Fatal("repo ID scheme changed")
	}
}
