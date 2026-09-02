// Package github implements the GitHub connector: read-only discovery of
// repositories, workflows, secrets metadata, and the permissions of the
// authenticated principal (PRD sections 21 and 55).
//
// It never reads or stores secret values; the GitHub API only exposes
// secret names and timestamps, which is exactly what the graph needs.
package github

import (
	"context"
	"fmt"
	"strings"

	gh "github.com/google/go-github/v74/github"

	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Node ID scheme (stable, referenceable from agentgraph.yaml):
//
//	github:user:<login>
//	github:repo:<owner>/<name>
//	github:workflow:<owner>/<repo>/<filename>
//	github:secret:<owner>/<repo>/<secret-name>
const (
	idUser     = "github:user:"
	idRepo     = "github:repo:"
	idWorkflow = "github:workflow:"
	idSecret   = "github:secret:"
)

// Options configures the connector.
type Options struct {
	// Client is an authenticated go-github client (read-only token
	// recommended).
	Client *gh.Client
	// Owner limits discovery to one user or organization. Empty means the
	// authenticated user.
	Owner string
	// MaxRepos caps the number of repositories enumerated (0 = 100).
	MaxRepos int
	// IncludeForks includes forked repositories.
	IncludeForks bool
}

// Connector discovers GitHub infrastructure.
type Connector struct {
	opts Options
}

// New returns a GitHub connector.
func New(opts Options) *Connector {
	if opts.MaxRepos <= 0 {
		opts.MaxRepos = 100
	}
	return &Connector{opts: opts}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return "github" }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	if c.opts.Client == nil {
		return nil, fmt.Errorf("github connector: client is required")
	}
	owner := c.opts.Owner
	if owner == "" {
		user, _, err := c.opts.Client.Users.Get(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("github connector: resolve authenticated user: %w", err)
		}
		owner = user.GetLogin()
	}

	res := &connectors.DiscoveryResult{}

	userNode, err := c.discoverUser(ctx, owner)
	if err != nil {
		return nil, err
	}
	res.Nodes = append(res.Nodes, userNode)

	repos, err := c.listRepos(ctx, owner)
	if err != nil {
		return nil, err
	}

	for _, repo := range repos {
		repoNode, edges := repoNodesAndEdges(userNode, repo)
		res.Nodes = append(res.Nodes, repoNode)
		res.Edges = append(res.Edges, edges...)

		// Workflows (CI pipelines triggered by this repository).
		workflows, err := c.listWorkflows(ctx, repo.GetOwner().GetLogin(), repo.GetName())
		if err != nil {
			// A missing workflows scope is not fatal for the whole scan.
			continue
		}
		for _, wf := range workflows {
			wfNode := workflowNode(repo, wf)
			res.Nodes = append(res.Nodes, wfNode)
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     repoNode.ID,
				Target:     wfNode.ID,
				Type:       graph.EdgeTriggers,
				Confidence: 1.0,
				Provenance: provenance("repository workflows"),
			})
		}

		// Repository action secrets (metadata only: name + timestamps).
		secrets, err := c.listRepoSecrets(ctx, repo.GetOwner().GetLogin(), repo.GetName())
		if err != nil {
			continue
		}
		for _, s := range secrets {
			secNode := secretNode(repo, s)
			res.Nodes = append(res.Nodes, secNode)
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     repoNode.ID,
				Target:     secNode.ID,
				Type:       graph.EdgeContainsSecret,
				Confidence: 1.0,
				Provenance: provenance("repository secrets"),
			})
		}
	}

	return res, nil
}

func (c *Connector) discoverUser(ctx context.Context, login string) (*graph.Node, error) {
	user, _, err := c.opts.Client.Users.Get(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("github connector: get user %s: %w", login, err)
	}
	n := &graph.Node{
		ID:       idUser + strings.ToLower(login),
		Type:     graph.NodeIdentity,
		Name:     user.GetName(),
		Provider: "github",
		Metadata: map[string]any{
			"login":         user.GetLogin(),
			"identity_type": identityType(user),
		},
	}
	if n.Name == "" {
		n.Name = user.GetLogin()
	}
	return n, nil
}

func identityType(user *gh.User) string {
	if user.GetType() == "Organization" {
		return "organization"
	}
	return "user"
}

func (c *Connector) listRepos(ctx context.Context, owner string) ([]*gh.Repository, error) {
	var out []*gh.Repository
	opts := &gh.RepositoryListByUserOptions{
		ListOptions: gh.ListOptions{PerPage: 100},
	}
	for {
		repos, resp, err := c.opts.Client.Repositories.ListByUser(ctx, owner, opts)
		if err != nil {
			// Fall back to the authenticated user's own repositories
			// (covers org tokens whose /users/{org}/repos view differs).
			page := &gh.RepositoryListOptions{ListOptions: gh.ListOptions{PerPage: 100}}
			for {
				mine, resp2, err2 := c.opts.Client.Repositories.List(ctx, "", page)
				if err2 != nil {
					return nil, fmt.Errorf("github connector: list repositories: %w (org fallback: %v)", err, err2)
				}
				out = append(out, mine...)
				if resp2.NextPage == 0 || len(out) >= c.opts.MaxRepos {
					return out, nil
				}
				page.Page = resp2.NextPage
			}
		}
		for _, r := range repos {
			if !c.opts.IncludeForks && r.GetFork() {
				continue
			}
			out = append(out, r)
			if len(out) >= c.opts.MaxRepos {
				return out, nil
			}
		}
		if resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

func (c *Connector) listWorkflows(ctx context.Context, owner, repo string) ([]*gh.Workflow, error) {
	var out []*gh.Workflow
	opts := &gh.ListOptions{PerPage: 100}
	for {
		res, resp, err := c.opts.Client.Actions.ListWorkflows(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, res.Workflows...)
		if resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

func (c *Connector) listRepoSecrets(ctx context.Context, owner, repo string) ([]*gh.Secret, error) {
	var out []*gh.Secret
	opts := &gh.ListOptions{PerPage: 100}
	for {
		res, resp, err := c.opts.Client.Actions.ListRepoSecrets(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, res.Secrets...)
		if resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

// repoNodesAndEdges builds the repository node plus permission edges from
// the authenticated principal's effective permissions on it.
func repoNodesAndEdges(userNode *graph.Node, repo *gh.Repository) (*graph.Node, []*graph.Edge) {
	id := idRepo + strings.ToLower(repo.GetOwner().GetLogin()+"/"+repo.GetName())
	n := &graph.Node{
		ID:       id,
		Type:     graph.NodeRepository,
		Name:     repo.GetName(),
		Provider: "github",
		Metadata: map[string]any{
			"full_name":      repo.GetFullName(),
			"visibility":     visibility(repo),
			"default_branch": repo.GetDefaultBranch(),
			"environment":    environment(repo),
		},
	}
	if strings.Contains(strings.ToLower(repo.GetName()), "prod") {
		n.Metadata["environment"] = "production"
		n.Criticality = 80
	}

	var edges []*graph.Edge
	p := repo.GetPermissions()
	if p != nil {
		edgeType := graph.EdgeCanRead
		conf := 1.0
		switch {
		case p["admin"]:
			edgeType = graph.EdgeCanAdmin
		case p["push"]:
			edgeType = graph.EdgeCanWrite
		case p["pull"]:
			edgeType = graph.EdgeCanRead
		default:
			conf = 0.5
		}
		edges = append(edges, &graph.Edge{
			Source:     userNode.ID,
			Target:     id,
			Type:       edgeType,
			Confidence: conf,
			Provenance: provenance("repository permissions"),
		})
	} else {
		edges = append(edges, &graph.Edge{
			Source:     userNode.ID,
			Target:     id,
			Type:       graph.EdgeOwns,
			Confidence: 0.8,
			Provenance: provenance("repository listing"),
		})
	}
	return n, edges
}

func workflowNode(repo *gh.Repository, wf *gh.Workflow) *graph.Node {
	return &graph.Node{
		// Owner/repo are lowercased (GitHub normalizes them); the workflow
		// path keeps its case because filenames are case-sensitive.
		ID:       idWorkflow + fmt.Sprintf("%s/%s/%s", strings.ToLower(repo.GetOwner().GetLogin()), strings.ToLower(repo.GetName()), wf.GetPath()),
		Type:     graph.NodeCIPipeline,
		Name:     wf.GetName(),
		Provider: "github",
		Metadata: map[string]any{
			"state": wf.GetState(),
			"path":  wf.GetPath(),
		},
	}
}

func secretNode(repo *gh.Repository, s *gh.Secret) *graph.Node {
	return &graph.Node{
		// Secret names are case-sensitive (AWS_DEPLOY_TOKEN); keep the case.
		ID:       idSecret + fmt.Sprintf("%s/%s/%s", strings.ToLower(repo.GetOwner().GetLogin()), strings.ToLower(repo.GetName()), s.Name),
		Type:     graph.NodeSecret,
		Name:     s.Name,
		Provider: "github",
		Metadata: map[string]any{
			"type":     "github_action_secret",
			"location": fmt.Sprintf("github-actions:%s", repo.GetFullName()),
			// Never a value: the API returns only the name and timestamps.
		},
	}
}

func visibility(repo *gh.Repository) string {
	if repo.GetPrivate() {
		return "private"
	}
	return "public"
}

func environment(repo *gh.Repository) string {
	if strings.Contains(strings.ToLower(repo.GetName()), "prod") {
		return "production"
	}
	return "development"
}

func provenance(sourceObject string) graph.Provenance {
	return graph.Provenance{
		Connector:    "github",
		SourceObject: sourceObject,
	}
}
