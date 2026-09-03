package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// fakeCluster simulates a small cluster:
//   - prod namespace with a payments pod running as the deploy SA
//   - deploy SA bound to the prod-admin role (escalate verb)
//   - a group subject bound to a read-only cluster role
//   - an opaque prod secret
func fakeCluster(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/api/v1/pods", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{
				"metadata": map[string]any{"name": "payments-api-7d9f", "namespace": "prod"},
				"spec":     map[string]any{"serviceAccountName": "payments-deployer"},
			},
			{
				"metadata": map[string]any{"name": "tooling", "namespace": "default"},
				"spec":     map[string]any{"serviceAccountName": ""},
			},
		}})
	})
	mux.HandleFunc("/api/v1/serviceaccounts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{"metadata": map[string]any{"name": "payments-deployer", "namespace": "prod"}},
			{"metadata": map[string]any{"name": "default", "namespace": "default"}},
		}})
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{"metadata": map[string]any{"name": "db-credentials", "namespace": "prod"}, "type": "Opaque"},
			{"metadata": map[string]any{"name": "default-token-abc", "namespace": "prod"}, "type": "kubernetes.io/service-account-token"},
		}})
	})
	mux.HandleFunc("/apis/rbac.authorization.k8s.io/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{
				"metadata": map[string]any{"name": "prod-admin", "namespace": "prod"},
				"rules": []map[string]any{
					{"verbs": []string{"get", "list", "escalate"}, "resources": []string{"roles", "rolebindings"}},
				},
			},
		}})
	})
	mux.HandleFunc("/apis/rbac.authorization.k8s.io/v1/clusterroles", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{
				"metadata": map[string]any{"name": "view-all"},
				"rules": []map[string]any{
					{"verbs": []string{"get", "list", "watch"}, "resources": []string{"*"}},
				},
			},
		}})
	})
	mux.HandleFunc("/apis/rbac.authorization.k8s.io/v1/rolebindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{
				"metadata": map[string]any{"name": "payments-deployer-binding", "namespace": "prod"},
				"subjects": []map[string]any{{"kind": "ServiceAccount", "name": "payments-deployer", "namespace": "prod"}},
				"roleRef":  map[string]any{"kind": "Role", "name": "prod-admin"},
			},
		}})
	})
	mux.HandleFunc("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{
			{
				"metadata": map[string]any{"name": "platform-viewers"},
				"subjects": []map[string]any{{"kind": "Group", "name": "platform-team"}},
				"roleRef":  map[string]any{"kind": "ClusterRole", "name": "view-all"},
			},
		}})
	})
	// Cover the unused generic list path.
	mux.HandleFunc("/api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"items": []map[string]any{}})
	})

	return httptest.NewTLSServer(mux)
}

func newTestConnector(t *testing.T) *Connector {
	t.Helper()
	srv := fakeCluster(t)
	t.Cleanup(srv.Close)
	api, err := NewRestAPI(RestOptions{Server: srv.URL, InsecureSkipTLSVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{API: api})
}

func TestDiscoverKubernetes(t *testing.T) {
	c := newTestConnector(t)
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	nodes := map[string]*graph.Node{}
	for _, n := range res.Nodes {
		nodes[n.ID] = n
	}

	// Core nodes.
	for _, id := range []string{
		"k8s:pod:prod/payments-api-7d9f",
		"k8s:sa:prod/payments-deployer",
		"k8s:sa:default/default",
		"k8s:role:prod/prod-admin",
		"k8s:clusterrole:view-all",
		"k8s:secret:prod/db-credentials",
		"k8s:identity:group/platform-team",
	} {
		if _, ok := nodes[id]; !ok {
			t.Errorf("missing node %s", id)
		}
	}

	// SA-token secrets are skipped.
	if _, ok := nodes["k8s:secret:prod/default-token-abc"]; ok {
		t.Error("service-account-token secret should be skipped")
	}

	// Pod authenticates as its SA.
	hasEdge := func(src, tgt string, et graph.EdgeType) bool {
		for _, e := range res.Edges {
			if e.Source == src && e.Target == tgt && e.Type == et {
				return true
			}
		}
		return false
	}
	if !hasEdge("k8s:pod:prod/payments-api-7d9f", "k8s:sa:prod/payments-deployer", graph.EdgeAuthenticatesAs) {
		t.Error("pod -> SA AUTHENTICATES_AS edge missing")
	}
	// Pod without explicit SA falls back to default.
	if !hasEdge("k8s:pod:default/tooling", "k8s:sa:default/default", graph.EdgeAuthenticatesAs) {
		t.Error("default SA fallback edge missing")
	}

	// Binding edges with verb-derived risk.
	var adminEdge, viewEdge *graph.Edge
	for _, e := range res.Edges {
		if e.Target == "k8s:role:prod/prod-admin" && e.Source == "k8s:sa:prod/payments-deployer" {
			adminEdge = e
		}
		if e.Target == "k8s:clusterrole:view-all" && e.Source == "k8s:identity:group/platform-team" {
			viewEdge = e
		}
	}
	if adminEdge == nil {
		t.Fatal("SA -> prod-admin binding edge missing")
	}
	if adminEdge.Risk != 95 {
		t.Errorf("escalate-verb role should carry risk 95, got %d", adminEdge.Risk)
	}
	if viewEdge == nil {
		t.Fatal("group -> view-all binding edge missing")
	}
	if viewEdge.Risk != 40 {
		t.Errorf("read-only role should carry risk 40, got %d", viewEdge.Risk)
	}

	// Privilege inference.
	if n := nodes["k8s:role:prod/prod-admin"]; n.Metadata["privilege"] != "admin" {
		t.Errorf("escalate role should be admin, got %v", n.Metadata["privilege"])
	}
	if n := nodes["k8s:clusterrole:view-all"]; n.Metadata["privilege"] != "read" {
		t.Errorf("view role should be read, got %v", n.Metadata["privilege"])
	}

	// Production inference by namespace.
	if n := nodes["k8s:sa:prod/payments-deployer"]; n.Metadata["environment"] != "production" {
		t.Error("prod namespace should map to production environment")
	}
	if n := nodes["k8s:secret:prod/db-credentials"]; n.Criticality < 80 {
		t.Error("prod secret should carry high criticality")
	}

	// External group subject flagged.
	if n := nodes["k8s:identity:group/platform-team"]; n.Metadata["external"] != true {
		t.Error("group subject should be flagged external")
	}

	// Secrets never carry values.
	for _, n := range res.Nodes {
		if n.Type == graph.NodeSecret {
			for k := range n.Metadata {
				if k == "value" || k == "data" || k == "stringData" {
					t.Errorf("secret node carries forbidden field %s", k)
				}
			}
		}
	}

	// Provenance on every edge.
	for _, e := range res.Edges {
		if e.Provenance.Connector != "kubernetes" {
			t.Errorf("edge %s->%s missing provenance", e.Source, e.Target)
		}
	}
}

func TestAnalyzeRules(t *testing.T) {
	cases := []struct {
		verbs []string
		level string
		risk  int
	}{
		{[]string{"*"}, "admin", 95},
		{[]string{"get", "escalate"}, "admin", 95},
		{[]string{"create", "update"}, "write", 70},
		{[]string{"get", "list"}, "read", 40},
		{[]string{}, "none", 30},
	}
	for _, c := range cases {
		level, risk := AnalyzeRules([]PolicyRule{{Verbs: c.verbs}})
		if level != c.level || risk != c.risk {
			t.Errorf("AnalyzeRules(%v) = (%s,%d), want (%s,%d)", c.verbs, level, risk, c.level, c.risk)
		}
	}
}

func TestDiscoverRequiresAPI(t *testing.T) {
	c := New(Options{})
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected error with nil API")
	}
}

func TestParseKubeconfig(t *testing.T) {
	cfg, err := parseKubeconfig([]byte(`
current-context: prod
contexts:
  - name: prod
    context: {cluster: prod-cluster, user: prod-user}
clusters:
  - name: prod-cluster
    cluster:
      server: https://k8s.example.com:6443
      insecure-skip-tls-verify: true
users:
  - name: prod-user
    user: {token: sekrit-token}
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Server != "https://k8s.example.com:6443" || cfg.Token != "sekrit-token" || !cfg.Insecure {
		t.Errorf("kubeconfig parsed wrong: %+v", cfg)
	}
}
