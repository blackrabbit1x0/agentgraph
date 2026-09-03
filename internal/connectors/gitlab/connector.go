// Package gitlab implements the GitLab connector: read-only discovery of
// projects, effective permissions, and CI/CD variable metadata (PRD
// section 22, Phase 5).
//
// Safety property: the GitLab variables API returns variable VALUES.
// This connector reads the endpoint for inventory purposes but stores
// only names and protection flags - values are dropped before anything
// reaches the graph. A unit test enforces this.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Node ID scheme (stable, referenceable from agentgraph.yaml):
//
//	gitlab:user:<login>
//	gitlab:repo:<path-with-namespace>
//	gitlab:secret:<path-with-namespace>/<variable-key>
const (
	idUser   = "gitlab:user:"
	idRepo   = "gitlab:repo:"
	idSecret = "gitlab:secret:"
)

// Project is a discovered project.
type Project struct {
	Name          string
	Path          string // path with namespace, e.g. "org/payments-api"
	Visibility    string
	DefaultBranch string
	// AccessLevel is the authenticated principal's effective access
	// (10 guest, 20 reporter, 30 developer, 40 maintainer, 50 owner).
	AccessLevel int
}

// Variable is CI/CD variable metadata. The API's value field is
// intentionally absent.
type Variable struct {
	Key       string
	Masked    bool
	Protected bool
}

// API abstracts the GitLab API calls the connector needs.
type API interface {
	GetCurrentUser(ctx context.Context) (login, name string, err error)
	ListProjects(ctx context.Context) ([]Project, error)
	ListVariables(ctx context.Context, projectPath string) ([]Variable, error)
}

// Options configures the connector.
type Options struct {
	API API
}

// Connector discovers GitLab infrastructure.
type Connector struct {
	opts Options
}

// New returns a GitLab connector.
func New(opts Options) *Connector {
	return &Connector{opts: opts}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return "gitlab" }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	if c.opts.API == nil {
		return nil, fmt.Errorf("gitlab connector: API is required")
	}
	res := &connectors.DiscoveryResult{}

	login, name, err := c.opts.API.GetCurrentUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("gitlab connector: current user: %w", err)
	}
	userNode := &graph.Node{
		ID:       idUser + strings.ToLower(login),
		Type:     graph.NodeIdentity,
		Name:     name,
		Provider: "gitlab",
		Metadata: map[string]any{"login": login},
	}
	if userNode.Name == "" {
		userNode.Name = login
	}
	res.Nodes = append(res.Nodes, userNode)

	projects, err := c.opts.API.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("gitlab connector: list projects: %w", err)
	}

	for _, p := range projects {
		repoNode := projectNode(p)
		res.Nodes = append(res.Nodes, repoNode)
		res.Edges = append(res.Edges, &graph.Edge{
			Source:     userNode.ID,
			Target:     repoNode.ID,
			Type:       accessEdge(p.AccessLevel),
			Confidence: 1.0,
			Provenance: provenance("project permissions"),
		})

		vars, err := c.opts.API.ListVariables(ctx, p.Path)
		if err != nil {
			// Missing variables scope is not fatal for the whole scan.
			continue
		}
		for _, v := range vars {
			secNode := variableNode(p, v)
			res.Nodes = append(res.Nodes, secNode)
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     repoNode.ID,
				Target:     secNode.ID,
				Type:       graph.EdgeContainsSecret,
				Confidence: 1.0,
				Provenance: provenance("ci variables"),
			})
		}
	}
	return res, nil
}

// accessEdge maps GitLab access levels to graph edge types.
func accessEdge(level int) graph.EdgeType {
	switch {
	case level >= 50:
		return graph.EdgeCanAdmin
	case level >= 30: // developer and maintainer can push
		return graph.EdgeCanWrite
	case level >= 20: // reporter
		return graph.EdgeCanRead
	default:
		return graph.EdgeConnectedTo
	}
}

func projectNode(p Project) *graph.Node {
	id := idRepo + strings.ToLower(p.Path)
	n := &graph.Node{
		ID:       id,
		Type:     graph.NodeRepository,
		Name:     p.Name,
		Provider: "gitlab",
		Metadata: map[string]any{
			"path":           p.Path,
			"visibility":     p.Visibility,
			"default_branch": p.DefaultBranch,
		},
	}
	if strings.Contains(strings.ToLower(p.Path), "prod") {
		n.Metadata["environment"] = "production"
		n.Criticality = 80
	}
	return n
}

func variableNode(p Project, v Variable) *graph.Node {
	n := &graph.Node{
		ID:       idSecret + strings.ToLower(p.Path) + "/" + v.Key,
		Type:     graph.NodeSecret,
		Name:     v.Key,
		Provider: "gitlab",
		Metadata: map[string]any{
			"type":      "gitlab_ci_variable",
			"location":  fmt.Sprintf("gitlab-ci:%s", p.Path),
			"masked":    v.Masked,
			"protected": v.Protected,
			// The API returns values; they are dropped here and never
			// stored (enforced by test).
		},
	}
	if strings.Contains(strings.ToLower(v.Key), "prod") ||
		strings.Contains(strings.ToLower(p.Path), "prod") {
		n.Metadata["environment"] = "production"
		n.Criticality = 80
	}
	return n
}

func provenance(sourceObject string) graph.Provenance {
	return graph.Provenance{Connector: "gitlab", SourceObject: sourceObject}
}

// RestAPI implements API against a GitLab instance (gitlab.com or
// self-hosted) using a personal access token. All calls are read-only.
type RestAPI struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewRestAPI builds a REST client. baseURL is e.g. https://gitlab.com
// (no trailing slash, no /api suffix).
func NewRestAPI(baseURL, token string) (*RestAPI, error) {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	if token == "" {
		return nil, fmt.Errorf("gitlab connector: token is required")
	}
	return &RestAPI{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{},
	}, nil
}

func (a *RestAPI) get(ctx context.Context, path string, out any) error {
	u := a.baseURL + "/api/v4" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", a.token)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: http %d: %s", path, resp.StatusCode, string(body))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// GetCurrentUser implements API.
func (a *RestAPI) GetCurrentUser(ctx context.Context) (string, string, error) {
	var u struct {
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if err := a.get(ctx, "/user", &u); err != nil {
		return "", "", err
	}
	return u.Username, u.Name, nil
}

// ListProjects implements API.
func (a *RestAPI) ListProjects(ctx context.Context) ([]Project, error) {
	var out []Project
	page := 1
	for {
		var raw []struct {
			Name          string `json:"name"`
			PathWithNs    string `json:"path_with_namespace"`
			Visibility    string `json:"visibility"`
			DefaultBranch string `json:"default_branch"`
			Permissions   struct {
				ProjectAccess *struct {
					AccessLevel int `json:"access_level"`
				} `json:"project_access"`
				GroupAccess *struct {
					AccessLevel int `json:"access_level"`
				} `json:"group_access"`
			} `json:"permissions"`
		}
		if err := a.get(ctx, "/projects?membership=true&simple=false&per_page=100&page="+strconv.Itoa(page), &raw); err != nil {
			return nil, err
		}
		if len(raw) == 0 {
			break
		}
		for _, p := range raw {
			level := 0
			if p.Permissions.ProjectAccess != nil {
				level = p.Permissions.ProjectAccess.AccessLevel
			}
			if p.Permissions.GroupAccess != nil && p.Permissions.GroupAccess.AccessLevel > level {
				level = p.Permissions.GroupAccess.AccessLevel
			}
			out = append(out, Project{
				Name:          p.Name,
				Path:          p.PathWithNs,
				Visibility:    p.Visibility,
				DefaultBranch: p.DefaultBranch,
				AccessLevel:   level,
			})
		}
		if len(raw) < 100 {
			break
		}
		page++
	}
	return out, nil
}

// ListVariables implements API. The API response includes `value`; it is
// decoded into a struct without a value field so values are dropped at
// the parse boundary.
func (a *RestAPI) ListVariables(ctx context.Context, projectPath string) ([]Variable, error) {
	var raw []struct {
		Key       string `json:"key"`
		Masked    bool   `json:"masked"`
		Protected bool   `json:"protected"`
		// value intentionally not decoded
	}
	if err := a.get(ctx, "/projects/"+url.PathEscape(projectPath)+"/variables", &raw); err != nil {
		return nil, err
	}
	out := make([]Variable, 0, len(raw))
	for _, v := range raw {
		out = append(out, Variable{Key: v.Key, Masked: v.Masked, Protected: v.Protected})
	}
	return out, nil
}
