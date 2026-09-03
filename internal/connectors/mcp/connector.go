// Package mcp implements the MCP connector: discovery of MCP servers and
// tools from local AI-client configurations (PRD sections 19 and 21).
//
// Supported configuration sources:
//
//	Claude Desktop   claude_desktop_config.json
//	Cursor           ~/.cursor/mcp.json and .cursor/mcp.json
//	VS Code          .vscode/mcp.json
//	opencode         opencode.json / opencode.jsonc and ~/.config/opencode/
//	Generic          .mcp.json / mcp.json in the working directory
//
// Safety properties:
//   - stdio servers are never spawned; only their configuration is read
//   - environment variable names are recorded, values are never stored
//   - header names are recorded, values are never stored
//   - URLs are redacted of sensitive query parameters
package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Node ID scheme (stable, referenceable from agentgraph.yaml):
//
//	mcp:client:<client>          the AI client (modeled as an AI_AGENT)
//	mcp:server:<client>/<name>   an MCP server configured by that client
//	mcp:tool:<client>/<server>/<tool>
const (
	idClient = "mcp:client:"
	idServer = "mcp:server:"
	idTool   = "mcp:tool:"
)

// ServerDef is one MCP server entry parsed from a client configuration.
type ServerDef struct {
	Name        string
	Transport   string // stdio | http | sse | remote | local
	Command     string // stdio: the executable (never executed)
	URL         string // http/sse: endpoint (sensitive params redacted)
	EnvNames    []string
	HeaderNames []string
}

// ClientDef is a discovered client configuration file.
type ClientDef struct {
	ID      string // stable client id, e.g. "claude-desktop"
	Name    string
	Source  string // config file path
	Servers []ServerDef
}

// Options configures the connector.
type Options struct {
	// Dir is an optional directory to search for project-level configs
	// (.cursor/, .vscode/, .mcp.json). Defaults to the working directory.
	Dir string
	// Home overrides the user home directory (tests).
	Home string
	// AppData overrides the platform app-data directory (tests).
	AppData string
	// Live enables live tool listing for http/sse servers (default off).
	Live bool
	// Timeout per live server query.
	TimeoutSeconds int
	// FileSystem abstraction (tests). nil = real filesystem.
	FS FileReader
	// Lister performs live tool listing (tests). nil = HTTPLister.
	Lister ToolLister
}

// FileReader abstracts config file access.
type FileReader interface {
	ReadFile(path string) ([]byte, error)
	Exists(path string) bool
}

// ToolLister lists tools from a live MCP server.
type ToolLister interface {
	ListTools(ctx context.Context, server ServerDef, timeoutSeconds int) ([]ToolInfo, error)
}

// ToolInfo is a tool discovered from a live MCP server.
type ToolInfo struct {
	Name        string
	Description string
}

// Connector discovers MCP configuration.
type Connector struct {
	opts Options
}

// New returns an MCP connector.
func New(opts Options) *Connector {
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 5
	}
	return &Connector{opts: opts}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return "mcp" }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	fs := c.fs()
	clients := c.discoverClients(fs)

	res := &connectors.DiscoveryResult{}
	lister := c.lister()

	for _, client := range clients {
		clientNode := &graph.Node{
			ID:       idClient + client.ID,
			Type:     graph.NodeAIAgent,
			Name:     client.Name,
			Provider: "mcp",
			Metadata: map[string]any{
				"config_source": client.Source,
				"discovered_by": "mcp-connector",
			},
		}
		res.Nodes = append(res.Nodes, clientNode)

		for _, srv := range client.Servers {
			srvNode := serverNode(client.ID, srv)
			res.Nodes = append(res.Nodes, srvNode)
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     clientNode.ID,
				Target:     srvNode.ID,
				Type:       graph.EdgeUses,
				Confidence: 1.0,
				Provenance: provenance(client.Source),
			})

			// Live tool listing (http/sse only, best effort).
			if c.opts.Live && lister != nil && srv.URL != "" {
				tools, err := lister.ListTools(ctx, srv, c.opts.TimeoutSeconds)
				if err == nil {
					for _, t := range tools {
						toolNode := toolNode(client.ID, srv.Name, t)
						res.Nodes = append(res.Nodes, toolNode)
						res.Edges = append(res.Edges, &graph.Edge{
							Source:     srvNode.ID,
							Target:     toolNode.ID,
							Type:       graph.EdgeCanCall,
							Confidence: 1.0,
							Provenance: provenance(srv.URL),
						})
					}
				}
			}
		}
	}
	return res, nil
}

func (c *Connector) fs() FileReader {
	if c.opts.FS != nil {
		return c.opts.FS
	}
	return realFS{}
}

func (c *Connector) lister() ToolLister {
	if c.opts.Lister != nil {
		return c.opts.Lister
	}
	return HTTPLister{}
}

func serverNode(clientID string, srv ServerDef) *graph.Node {
	meta := map[string]any{
		"transport": srv.Transport,
	}
	if srv.Command != "" {
		meta["command"] = srv.Command
	}
	if srv.URL != "" {
		meta["endpoint"] = srv.URL
	}
	if len(srv.EnvNames) > 0 {
		meta["env_names"] = srv.EnvNames
	}
	if len(srv.HeaderNames) > 0 {
		meta["header_names"] = srv.HeaderNames
	}
	return &graph.Node{
		ID:       idServer + clientID + "/" + srv.Name,
		Type:     graph.NodeMCPServer,
		Name:     srv.Name,
		Provider: "mcp",
		Metadata: meta,
	}
}

func toolNode(clientID, server string, t ToolInfo) *graph.Node {
	risk := toolRisk(t.Name)
	meta := map[string]any{
		"risk": risk,
	}
	if t.Description != "" {
		meta["description"] = truncate(t.Description, 200)
	}
	return &graph.Node{
		ID:       idTool + clientID + "/" + server + "/" + t.Name,
		Type:     graph.NodeTool,
		Name:     t.Name,
		Provider: "mcp",
		Metadata: meta,
	}
}

// toolRisk infers intrinsic risk from tool naming (PRD section 39).
func toolRisk(name string) string {
	n := strings.ToLower(name)
	switch {
	case containsAny(n, "exec", "shell", "command", "run_command", "terminal", "eval"):
		return "critical"
	case containsAny(n, "write", "create", "delete", "update", "modify", "deploy", "push", "commit"):
		return "high"
	case containsAny(n, "admin", "sudo", "root", "assume", "credential", "secret", "token"):
		return "critical"
	case containsAny(n, "read", "list", "get", "search", "query", "fetch"):
		return "medium"
	default:
		return "medium"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// discoverClients finds and parses all known client configurations.
func (c *Connector) discoverClients(fs FileReader) []ClientDef {
	var clients []ClientDef

	home := c.opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	appData := c.opts.AppData
	if appData == "" {
		appData = defaultAppData()
	}
	dir := c.opts.Dir
	if dir == "" {
		dir, _ = os.Getwd()
	}

	// Claude Desktop.
	for _, p := range []string{
		filepath.Join(appData, "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
	} {
		if cl, ok := parseStdClient(fs, p, "claude-desktop", "Claude Desktop"); ok {
			clients = append(clients, cl)
			break
		}
	}

	// Cursor: global then project.
	if cl, ok := parseStdClient(fs, filepath.Join(home, ".cursor", "mcp.json"), "cursor", "Cursor"); ok {
		clients = append(clients, cl)
	}
	if cl, ok := parseStdClient(fs, filepath.Join(dir, ".cursor", "mcp.json"), "cursor-project", "Cursor (project)"); ok {
		clients = append(clients, cl)
	}

	// VS Code (project).
	if cl, ok := parseVSCodeClient(fs, filepath.Join(dir, ".vscode", "mcp.json")); ok {
		clients = append(clients, cl)
	}

	// opencode: global then project (JSONC tolerated).
	for _, p := range []string{
		filepath.Join(home, ".config", "opencode", "opencode.json"),
		filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
		filepath.Join(dir, "opencode.json"),
		filepath.Join(dir, "opencode.jsonc"),
	} {
		if cl, ok := parseOpenCodeClient(fs, p); ok {
			clients = append(clients, cl)
		}
	}

	// Generic .mcp.json / mcp.json.
	for _, name := range []string{".mcp.json", "mcp.json"} {
		if cl, ok := parseStdClient(fs, filepath.Join(dir, name), "project", "Project ("+name+")"); ok {
			clients = append(clients, cl)
			break
		}
	}

	return clients
}

func defaultAppData() string {
	if runtime.GOOS == "windows" {
		if ad := os.Getenv("APPDATA"); ad != "" {
			return ad
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config")
	}
	return ""
}

// parseStdClient parses the common {"mcpServers": {...}} format used by
// Claude Desktop, Cursor, and generic .mcp.json files.
func parseStdClient(fs FileReader, path, id, name string) (ClientDef, bool) {
	if !fs.Exists(path) {
		return ClientDef{}, false
	}
	data, err := fs.ReadFile(path)
	if err != nil {
		return ClientDef{}, false
	}
	var cfg struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(stripJSONC(data), &cfg); err != nil {
		return ClientDef{}, false
	}
	if len(cfg.MCPServers) == 0 {
		return ClientDef{}, false
	}
	client := ClientDef{ID: id, Name: name, Source: path}
	for srvName, raw := range cfg.MCPServers {
		if srv, ok := parseStdServer(raw); ok {
			srv.Name = srvName
			client.Servers = append(client.Servers, srv)
		}
	}
	if len(client.Servers) == 0 {
		return ClientDef{}, false
	}
	return client, true
}

// parseStdServer handles both object-form and Cursor's "type" form.
func parseStdServer(raw json.RawMessage) (ServerDef, bool) {
	var s struct {
		Command   string            `json:"command"`
		Args      []string          `json:"args"`
		Env       map[string]string `json:"env"`
		URL       string            `json:"url"`
		Transport string            `json:"type"` // Cursor: "stdio"|"http"|"sse"
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return ServerDef{}, false
	}
	def := ServerDef{}
	switch {
	case s.Command != "":
		def.Transport = "stdio"
		def.Command = s.Command
	case s.URL != "":
		def.Transport = "http"
		def.URL = RedactURL(s.URL)
		if s.Transport == "sse" {
			def.Transport = "sse"
		}
	default:
		return ServerDef{}, false
	}
	for k := range s.Env {
		def.EnvNames = append(def.EnvNames, k)
	}
	sortStrings(def.EnvNames)
	return def, true
}

// parseVSCodeClient parses VS Code's {"servers": {...}} format.
func parseVSCodeClient(fs FileReader, path string) (ClientDef, bool) {
	if !fs.Exists(path) {
		return ClientDef{}, false
	}
	data, err := fs.ReadFile(path)
	if err != nil {
		return ClientDef{}, false
	}
	var cfg struct {
		Servers map[string]struct {
			Type    string            `json:"type"`
			Command string            `json:"command"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Env     map[string]string `json:"env"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(stripJSONC(data), &cfg); err != nil {
		return ClientDef{}, false
	}
	if len(cfg.Servers) == 0 {
		return ClientDef{}, false
	}
	client := ClientDef{ID: "vscode", Name: "VS Code", Source: path}
	for name, s := range cfg.Servers {
		def := ServerDef{Name: name}
		switch {
		case s.Command != "":
			def.Transport = "stdio"
			def.Command = s.Command
		case s.URL != "":
			def.Transport = "http"
			def.URL = RedactURL(s.URL)
		default:
			continue
		}
		for k := range s.Headers {
			def.HeaderNames = append(def.HeaderNames, k)
		}
		for k := range s.Env {
			def.EnvNames = append(def.EnvNames, k)
		}
		sortStrings(def.HeaderNames)
		sortStrings(def.EnvNames)
		client.Servers = append(client.Servers, def)
	}
	if len(client.Servers) == 0 {
		return ClientDef{}, false
	}
	return client, true
}

// parseOpenCodeClient parses opencode's {"mcp": {name: {type: local|remote}}} format.
func parseOpenCodeClient(fs FileReader, path string) (ClientDef, bool) {
	if !fs.Exists(path) {
		return ClientDef{}, false
	}
	data, err := fs.ReadFile(path)
	if err != nil {
		return ClientDef{}, false
	}
	var cfg struct {
		MCP map[string]struct {
			Type    string            `json:"type"`
			Command []string          `json:"command"`
			URL     *string           `json:"url"`
			Headers map[string]string `json:"headers"`
			Enabled *bool             `json:"enabled"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(stripJSONC(data), &cfg); err != nil {
		return ClientDef{}, false
	}
	if len(cfg.MCP) == 0 {
		return ClientDef{}, false
	}
	client := ClientDef{
		ID:     "opencode-" + configScope(path),
		Name:   "opencode (" + configScope(path) + ")",
		Source: path,
	}
	for name, s := range cfg.MCP {
		if s.Enabled != nil && !*s.Enabled {
			continue
		}
		def := ServerDef{Name: name}
		switch s.Type {
		case "local", "stdio":
			def.Transport = "stdio"
			if len(s.Command) > 0 {
				def.Command = s.Command[0]
			}
		case "remote", "http", "sse":
			def.Transport = "http"
			if s.URL != nil {
				def.URL = RedactURL(*s.URL)
			}
		default:
			continue
		}
		for k := range s.Headers {
			def.HeaderNames = append(def.HeaderNames, k)
		}
		sortStrings(def.HeaderNames)
		client.Servers = append(client.Servers, def)
	}
	if len(client.Servers) == 0 {
		return ClientDef{}, false
	}
	return client, true
}

// configScope distinguishes global vs project opencode configs.
func configScope(path string) string {
	p := filepath.ToSlash(strings.ToLower(path))
	if strings.Contains(p, "/.config/opencode/") {
		return "global"
	}
	return "project"
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func provenance(sourceObject string) graph.Provenance {
	return graph.Provenance{
		Connector:    "mcp",
		SourceObject: sourceObject,
	}
}

// stripJSONC removes // and /* */ comments so JSONC configs parse as JSON.
func stripJSONC(data []byte) []byte {
	var out []byte
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if escaped {
			out = append(out, ch)
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			out = append(out, ch)
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			out = append(out, ch)
			continue
		}
		if !inString {
			if ch == '/' && i+1 < len(data) && data[i+1] == '/' {
				for i < len(data) && data[i] != '\n' {
					i++
				}
				if i < len(data) {
					out = append(out, '\n')
				}
				continue
			}
			if ch == '/' && i+1 < len(data) && data[i+1] == '*' {
				i += 2
				for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
					i++
				}
				i++
				continue
			}
		}
		out = append(out, ch)
	}
	return out
}

// RedactURL removes sensitive query parameter values from a URL.
func RedactURL(raw string) string {
	anchor := ""
	if i := strings.Index(raw, "#"); i >= 0 {
		anchor = raw[i:]
		raw = raw[:i]
	}
	qi := strings.Index(raw, "?")
	if qi < 0 {
		return raw + anchor
	}
	base, query := raw[:qi], raw[qi+1:]
	var kept []string
	for _, kv := range strings.Split(query, "&") {
		key := kv
		if i := strings.Index(kv, "="); i >= 0 {
			key = kv[:i]
		}
		if containsAny(strings.ToLower(key), "key", "token", "secret", "password", "auth", "signature") {
			kept = append(kept, key+"=REDACTED")
		} else {
			kept = append(kept, kv)
		}
	}
	return base + "?" + strings.Join(kept, "&") + anchor
}
