package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// fakeSlack serves canned Web API responses.
func fakeSlack(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	requireAuth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer xoxb-test-token" {
			w.WriteHeader(401)
			return false
		}
		return true
	}

	mux.HandleFunc("/api/auth.test", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"ok": true, "user_id": "B07AGENT01", "user": "finance-agent",
			"team_id": "T123", "team": "acme", "is_bot": true,
		})
	})
	mux.HandleFunc("/api/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"ok": true,
			"channels": []map[string]any{
				{"id": "C001", "name": "finance", "is_member": true},
				{"id": "C002", "name": "prod-incidents", "is_member": true},
				{"id": "C003", "name": "random", "is_member": false},
			},
			"response_metadata": map[string]any{"next_cursor": ""},
		})
	})
	mux.HandleFunc("/api/conversations.members", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		members := map[string][]string{
			"C001": {"B07AGENT01", "U001"},
			"C002": {"B07AGENT01"},
			"C003": {},
		}
		writeJSON(w, map[string]any{
			"ok": true, "members": members[r.URL.Query().Get("channel")],
			"response_metadata": map[string]any{"next_cursor": ""},
		})
	})
	mux.HandleFunc("/api/users.list", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"ok": true,
			"members": []map[string]any{
				{"id": "B07AGENT01", "name": "finance-agent", "real_name": "Finance Agent", "is_bot": true},
				{"id": "U001", "name": "alice", "real_name": "Alice", "is_bot": false},
				{"id": "UDEL", "name": "gone", "deleted": true},
			},
			"response_metadata": map[string]any{"next_cursor": ""},
		})
	})
	mux.HandleFunc("/api/apps.permissions.info", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"ok": true,
			"info": map[string]any{
				"app_scopes": []map[string]any{
					{"scope": "channels:read"},
					{"scope": "chat:write"},
					{"scope": "users:read"},
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestDiscover(t *testing.T) {
	srv := fakeSlack(t)
	defer srv.Close()

	api, err := NewRestAPI(srv.URL, "xoxb-test-token")
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
		"slack:identity:B07AGENT01",
		"slack:identity:U001",
		"slack:channel:C001",
		"slack:channel:C002",
		"slack:channel:C003",
	} {
		if _, ok := nodes[want]; !ok {
			t.Errorf("missing node %s", want)
		}
	}
	if _, ok := nodes["slack:identity:UDEL"]; ok {
		t.Error("deleted users should be skipped")
	}
	if n := nodes["slack:identity:B07AGENT01"]; n.Metadata["identity_type"] != "bot_or_user" {
		t.Errorf("caller identity wrong: %v", n.Metadata)
	}
	// prod-incidents is security-relevant: criticality raised.
	if n := nodes["slack:channel:C002"]; n.Criticality != 75 {
		t.Errorf("prod-incidents channel criticality = %d, want 75", n.Criticality)
	}

	hasEdge := func(src, tgt string, et graph.EdgeType) bool {
		for _, e := range res.Edges {
			if e.Source == src && e.Target == tgt && e.Type == et {
				return true
			}
		}
		return false
	}
	// Caller is a member with chat:write -> CAN_READ + CAN_WRITE on C001/C002.
	if !hasEdge("slack:identity:B07AGENT01", "slack:channel:C001", graph.EdgeCanRead) {
		t.Error("caller -> #finance CAN_READ missing")
	}
	if !hasEdge("slack:identity:B07AGENT01", "slack:channel:C001", graph.EdgeCanWrite) {
		t.Error("caller -> #finance CAN_WRITE missing (chat:write + member)")
	}

	// Member edges: U001 sees #finance; B07 also listed but must not duplicate caller edge counting wrongly.
	count := 0
	for _, e := range res.Edges {
		if e.Source == "slack:identity:U001" && e.Target == "slack:channel:C001" && e.Type == graph.EdgeCanRead {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 U001 -> #finance read edge, got %d", count)
	}

	// Non-member channel: no edges from the caller.
	for _, e := range res.Edges {
		if e.Source == "slack:identity:B07AGENT01" && e.Target == "slack:channel:C003" {
			t.Error("non-member channel must have no caller edges")
		}
	}

	// Scope-derived privilege.
	if n := nodes["slack:identity:B07AGENT01"]; n.Metadata["privilege"] != "write" {
		t.Errorf("token privilege = %v, want write", n.Metadata["privilege"])
	}
	for _, e := range res.Edges {
		if e.Provenance.Connector != "slack" {
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

func TestScopesPrivilege(t *testing.T) {
	cases := map[string]string{
		"admin":       "admin",
		"chat:write": "write",
		"files:write": "write",
		"channels:read": "read",
	}
	for scope, want := range cases {
		if got := scopesPrivilege([]string{scope}); got != want {
			t.Errorf("scopesPrivilege([%s]) = %s, want %s", scope, got, want)
		}
	}
	if got := scopesPrivilege(nil); got != "none" {
		t.Errorf("empty scopes = %s, want none", got)
	}
}

func TestTokenNeverInGraph(t *testing.T) {
	srv := fakeSlack(t)
	defer srv.Close()
	api, _ := NewRestAPI(srv.URL, "xoxb-test-token")
	res, err := New(Options{API: api}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), "xoxb-test-token") {
		t.Fatal("token leaked into discovery result")
	}
}
