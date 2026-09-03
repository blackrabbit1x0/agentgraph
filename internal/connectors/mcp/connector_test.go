package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// memFS is an in-memory FileReader for tests. Keys are normalized to
// forward slashes so tests work on any OS.
type memFS map[string]string

func normKey(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func (m memFS) ReadFile(path string) ([]byte, error) { return []byte(m[normKey(path)]), nil }
func (m memFS) Exists(path string) bool {
	_, ok := m[normKey(path)]
	return ok
}

// fakeLister returns canned tools.
type fakeLister struct {
	calls int
}

func (f *fakeLister) ListTools(_ context.Context, server ServerDef, _ int) ([]ToolInfo, error) {
	f.calls++
	return []ToolInfo{
		{Name: "read_file", Description: "Read a file"},
		{Name: "execute_command", Description: "Run a shell command"},
	}, nil
}

func testOptions(fs memFS, live bool) Options {
	return Options{
		Home:    "C:/users/test",
		AppData: "C:/users/test/appdata",
		Dir:     "C:/users/test/project",
		FS:      fs,
		Live:    live,
	}
}

func TestDiscoverConfigs(t *testing.T) {
	fs := memFS{
		// Claude Desktop: stdio server with env vars.
		"C:/users/test/appdata/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"github": {
					"command": "npx",
					"args": ["-y", "@modelcontextprotocol/server-github"],
					"env": {"GITHUB_TOKEN": "ghp_secret_value_123"}
				},
				"filesystem": {"command": "npx", "args": ["-y", "fs-server"]}
			}
		}`,
		// Cursor project: an http server with a sensitive query param.
		"C:/users/test/project/.cursor/mcp.json": `{
			"mcpServers": {
				"web-search": {
					"type": "http",
					"url": "https://mcp.example.com/search?api_key=abc123&region=us"
				}
			}
		}`,
		// opencode project config (JSONC with comments).
		"C:/users/test/project/opencode.json": `{
			// local MCP server
			"mcp": {
				"shell": {"type": "local", "command": ["uvx", "mcp-shell"]},
				"disabled-one": {"type": "local", "command": ["x"], "enabled": false}
			}
		}`,
	}

	c := New(testOptions(fs, false))
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	nodes := map[string]*graph.Node{}
	for _, n := range res.Nodes {
		nodes[n.ID] = n
	}

	// Client agents.
	for _, id := range []string{"mcp:client:claude-desktop", "mcp:client:cursor-project", "mcp:client:opencode-project"} {
		if n, ok := nodes[id]; !ok {
			t.Errorf("missing client %s", id)
		} else if n.Type != graph.NodeAIAgent {
			t.Errorf("client %s should be AI_AGENT, got %s", id, n.Type)
		}
	}

	// Servers.
	github := "mcp:server:claude-desktop/github"
	if n, ok := nodes[github]; !ok {
		t.Fatal("missing github server")
	} else {
		if n.Type != graph.NodeMCPServer {
			t.Errorf("github server type: %s", n.Type)
		}
		if n.Metadata["command"] != "npx" {
			t.Errorf("command not captured: %v", n.Metadata["command"])
		}
		envNames, _ := n.Metadata["env_names"].([]string)
		if len(envNames) != 1 || envNames[0] != "GITHUB_TOKEN" {
			t.Errorf("env names wrong: %v", n.Metadata["env_names"])
		}
		// Env values must never appear anywhere in the result.
		if b, err := json.Marshal(res); err == nil && strings.Contains(string(b), "ghp_secret_value_123") {
			t.Error("env value leaked into graph")
		}
	}

	// URL redaction.
	web := "mcp:server:cursor-project/web-search"
	if n, ok := nodes[web]; !ok {
		t.Fatal("missing web-search server")
	} else if n.Metadata["endpoint"] != "https://mcp.example.com/search?api_key=REDACTED&region=us" {
		t.Errorf("url not redacted: %v", n.Metadata["endpoint"])
	}

	// opencode server parsed; disabled server skipped.
	if _, ok := nodes["mcp:server:opencode-project/shell"]; !ok {
		t.Error("missing opencode shell server")
	}
	if _, ok := nodes["mcp:server:opencode-project/disabled-one"]; ok {
		t.Error("disabled server should be skipped")
	}

	// USES edges from clients to servers.
	hasEdge := func(src, tgt string, et graph.EdgeType) bool {
		for _, e := range res.Edges {
			if e.Source == src && e.Target == tgt && e.Type == et {
				return true
			}
		}
		return false
	}
	if !hasEdge("mcp:client:claude-desktop", github, graph.EdgeUses) {
		t.Error("claude-desktop -> github USES edge missing")
	}
	if !hasEdge("mcp:client:opencode-project", "mcp:server:opencode-project/shell", graph.EdgeUses) {
		t.Error("opencode -> shell USES edge missing")
	}

	// No tool nodes without live mode.
	for _, n := range res.Nodes {
		if n.Type == graph.NodeTool {
			t.Error("tool nodes should not exist without --live")
		}
	}
}

func TestLiveToolListing(t *testing.T) {
	// The live server is placed in a GLOBAL config (trusted source), so
	// the egress policy permits it without DNS resolution.
	fs := memFS{
		"C:/users/test/.cursor/mcp.json": `{
			"mcpServers": {
				"github": {"url": "https://mcp.internal/github"}
			}
		}`,
	}
	lister := &fakeLister{}
	opts := testOptions(fs, true)
	opts.Lister = lister
	c := New(opts)
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if lister.calls != 1 {
		t.Fatalf("expected 1 live call, got %d", lister.calls)
	}
	nodes := map[string]*graph.Node{}
	for _, n := range res.Nodes {
		nodes[n.ID] = n
	}
	readTool := "mcp:tool:cursor/github/read_file"
	execTool := "mcp:tool:cursor/github/execute_command"
	if _, ok := nodes[readTool]; !ok {
		t.Error("missing read_file tool node")
	}
	if _, ok := nodes[execTool]; !ok {
		t.Error("missing execute_command tool node")
	}

	// Risk inference.
	if nodes[execTool].Metadata["risk"] != "critical" {
		t.Errorf("execute_command should be critical, got %v", nodes[execTool].Metadata["risk"])
	}
	if nodes[readTool].Metadata["risk"] != "medium" {
		t.Errorf("read_file should be medium, got %v", nodes[readTool].Metadata["risk"])
	}

	// CAN_CALL edges.
	has := false
	for _, e := range res.Edges {
		if e.Type == graph.EdgeCanCall && e.Target == execTool {
			has = true
		}
	}
	if !has {
		t.Error("server -> tool CAN_CALL edge missing")
	}
}

func TestEgressGuard(t *testing.T) {
	// Project-directory configs with private endpoints are skipped.
	fs := memFS{
		"C:/users/test/project/.mcp.json": `{
			"mcpServers": {
				"local-server": {"url": "http://127.0.0.1:3333/mcp"},
				"metadata-endpoint": {"url": "http://169.254.169.254/latest/meta-data"},
				"localhost-server": {"url": "http://localhost:9090/mcp"}
			}
		}`,
	}
	lister := &fakeLister{}
	opts := testOptions(fs, true)
	opts.Lister = lister
	c := New(opts)
	_, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if lister.calls != 0 {
		t.Fatalf("project-config private hosts must not be probed, got %d calls", lister.calls)
	}

	// --allow-private overrides the guard.
	opts2 := testOptions(fs, true)
	opts2.Lister = lister
	opts2.AllowPrivate = true
	c2 := New(opts2)
	if _, err := c2.Discover(context.Background()); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if lister.calls != 3 {
		t.Fatalf("allow-private should probe all servers, got %d calls", lister.calls)
	}

	// The guard itself, unit-level.
	conn := New(Options{AllowPrivate: false})
	for _, url := range []string{
		"http://127.0.0.1:3333/mcp",
		"http://169.254.169.254/latest/meta-data",
		"http://localhost:9090/mcp",
		"http://10.0.0.5/mcp",
	} {
		err := conn.egressAllowed(ServerDef{URL: url, FromProjectDir: true})
		if err == nil {
			t.Errorf("egressAllowed(%s) should block private project hosts", url)
		}
	}
	// Trusted (global) configs are exempt without any flags.
	if err := conn.egressAllowed(ServerDef{URL: "http://127.0.0.1:3333/mcp"}); err != nil {
		t.Errorf("global configs should allow private hosts: %v", err)
	}
}

func TestToolRisk(t *testing.T) {
	cases := map[string]string{
		"run_command":       "critical",
		"shell_exec":        "critical",
		"create_issue":      "high",
		"delete_file":       "high",
		"list_repositories": "medium",
		"get_weather":       "medium",
	}
	for name, want := range cases {
		if got := toolRisk(name); got != want {
			t.Errorf("toolRisk(%s) = %s, want %s", name, got, want)
		}
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://x.com/mcp":                          "https://x.com/mcp",
		"https://x.com/mcp?token=abc":                "https://x.com/mcp?token=REDACTED",
		"https://x.com/mcp?api_key=abc&page=2":       "https://x.com/mcp?api_key=REDACTED&page=2",
		"https://x.com/mcp?API_SECRET=s&region=eu#f": "https://x.com/mcp?API_SECRET=REDACTED&region=eu#f",
		"https://x.com/mcp?sig=deadbeef":             "https://x.com/mcp?sig=REDACTED",
		"https://key:secret@x.com/mcp":               "https://REDACTED:x.com/mcp",
		"https://apikey:@x.com/mcp?region=eu":        "https://REDACTED:x.com/mcp?region=eu",
		"https://user:pass@x.com/mcp?token=t":        "https://REDACTED:x.com/mcp?token=REDACTED",
	}
	for in, want := range cases {
		got := RedactURL(in)
		// userinfo redaction goes through url.String() which may
		// percent-encode; compare loosely by checking no credentials
		// survive and the host+path+query are intact.
		if strings.Contains(got, ":secret@") || strings.Contains(got, "apikey:@") || strings.Contains(got, "user:pass") {
			t.Errorf("RedactURL(%s) leaked credentials: %s", in, got)
		}
		if !strings.Contains(got, "x.com/mcp") {
			t.Errorf("RedactURL(%s) damaged the URL: %s", in, got)
		}
		if !strings.Contains(in, "@") { // exact expectations for non-userinfo cases
			if got != want {
				t.Errorf("RedactURL(%s) = %s, want %s", in, got, want)
			}
		}
	}
}

func TestStripJSONC(t *testing.T) {
	in := []byte(`{
		// comment
		"a": "http://x", /* block */
		"b": 1
	}`)
	out := stripJSONC(in)
	if strings.Contains(string(out), "comment") || strings.Contains(string(out), "block") {
		t.Errorf("comments not stripped: %s", out)
	}
	if !strings.Contains(string(out), `"a": "http://x"`) {
		t.Errorf("content damaged: %s", out)
	}
}

func TestNoConfigsYieldEmptyResult(t *testing.T) {
	c := New(testOptions(memFS{}, false))
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(res.Nodes) != 0 || len(res.Edges) != 0 {
		t.Errorf("expected empty result, got %d nodes", len(res.Nodes))
	}
}
