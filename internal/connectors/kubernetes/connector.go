// Package kubernetes implements the Kubernetes connector: read-only
// discovery of pods, service accounts, RBAC roles and bindings, and
// secret metadata (PRD section 22, Phase 5).
//
// All access uses read-only GET requests against the Kubernetes API
// server. Secret values are never read (the list endpoint returns
// metadata only).
package kubernetes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Node ID scheme (stable, referenceable from agentgraph.yaml):
//
//	k8s:pod:ns/name            Pod (CLOUD_RESOURCE)
//	k8s:sa:ns/name             ServiceAccount (IDENTITY)
//	k8s:role:ns/name           Role (CLOUD_ROLE)
//	k8s:clusterrole:name       ClusterRole (CLOUD_ROLE)
//	k8s:identity:kind/name     User/Group subject (IDENTITY)
//	k8s:secret:ns/name         Secret (SECRET, metadata only)
const (
	idPod         = "k8s:pod:"
	idSA          = "k8s:sa:"
	idRole        = "k8s:role:"
	idClusterRole = "k8s:clusterrole:"
	idIdentity    = "k8s:identity:"
	idSecret      = "k8s:secret:"
)

// Pod is a discovered pod.
type Pod struct {
	Name           string
	Namespace      string
	ServiceAccount string
}

// ServiceAccount is a discovered service account.
type ServiceAccount struct {
	Name      string
	Namespace string
}

// PolicyRule is one RBAC rule.
type PolicyRule struct {
	Verbs     []string
	Resources []string
}

// Role is a Role or ClusterRole.
type Role struct {
	Name      string
	Namespace string // empty for ClusterRole
	Cluster   bool
	Rules     []PolicyRule
}

// Subject is one binding subject.
type Subject struct {
	Kind      string // ServiceAccount | User | Group
	Name      string
	Namespace string
}

// RoleBinding is a RoleBinding or ClusterRoleBinding.
type RoleBinding struct {
	Name      string
	Namespace string
	Subjects  []Subject
	RoleRef   struct {
		Kind string // Role | ClusterRole
		Name string
	}
}

// Secret is secret metadata (never a value).
type Secret struct {
	Name      string
	Namespace string
	Type      string
}

// API abstracts the Kubernetes API calls the connector needs.
type API interface {
	ListPods(ctx context.Context) ([]Pod, error)
	ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error)
	ListRoles(ctx context.Context) ([]Role, error)
	ListClusterRoles(ctx context.Context) ([]Role, error)
	ListRoleBindings(ctx context.Context) ([]RoleBinding, error)
	ListClusterRoleBindings(ctx context.Context) ([]RoleBinding, error)
	ListSecrets(ctx context.Context) ([]Secret, error)
}

// Options configures the connector.
type Options struct {
	API API
}

// Connector discovers Kubernetes infrastructure.
type Connector struct {
	opts Options
}

// New returns a Kubernetes connector.
func New(opts Options) *Connector {
	return &Connector{opts: opts}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return "kubernetes" }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	if c.opts.API == nil {
		return nil, fmt.Errorf("kubernetes connector: API is required")
	}
	res := &connectors.DiscoveryResult{}

	sas, err := c.opts.API.ListServiceAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list service accounts: %w", err)
	}
	saIDs := map[string]*graph.Node{}
	for _, sa := range sas {
		n := &graph.Node{
			ID:       idSA + sa.Namespace + "/" + sa.Name,
			Type:     graph.NodeIdentity,
			Name:     sa.Name,
			Provider: "kubernetes",
			Metadata: map[string]any{
				"namespace":     sa.Namespace,
				"identity_type": "service_account",
				"environment":   environment(sa.Namespace),
			},
		}
		saIDs[n.ID] = n
		res.Nodes = append(res.Nodes, n)
	}

	// Pods authenticate as their service accounts.
	pods, err := c.opts.API.ListPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list pods: %w", err)
	}
	for _, pod := range pods {
		saName := pod.ServiceAccount
		if saName == "" {
			saName = "default"
		}
		podNode := &graph.Node{
			ID:       idPod + pod.Namespace + "/" + pod.Name,
			Type:     graph.NodeCloudResource,
			Name:     pod.Name,
			Provider: "kubernetes",
			Metadata: map[string]any{
				"namespace":   pod.Namespace,
				"type":        "pod",
				"environment": environment(pod.Namespace),
			},
		}
		if strings.Contains(pod.Namespace, "prod") {
			podNode.Criticality = 60
		}
		res.Nodes = append(res.Nodes, podNode)

		saID := idSA + pod.Namespace + "/" + saName
		if _, ok := saIDs[saID]; !ok {
			// Pod references an SA not returned by the API (e.g. restricted
			// list scope); model it anyway so the chain stays connected.
			n := &graph.Node{
				ID:       saID,
				Type:     graph.NodeIdentity,
				Name:     saName,
				Provider: "kubernetes",
				Metadata: map[string]any{
					"namespace":     pod.Namespace,
					"identity_type": "service_account",
					"environment":   environment(pod.Namespace),
				},
			}
			saIDs[saID] = n
			res.Nodes = append(res.Nodes, n)
		}
		res.Edges = append(res.Edges, &graph.Edge{
			Source:     podNode.ID,
			Target:     saID,
			Type:       graph.EdgeAuthenticatesAs,
			Confidence: 1.0,
			Provenance: provenance("pod spec.serviceAccountName"),
		})
	}

	// Roles: analyze verbs for privilege level.
	roleIDs := map[string]*graph.Node{}
	addRole := func(r Role) {
		level, _ := AnalyzeRules(r.Rules)
		id := idRole + r.Namespace + "/" + r.Name
		if r.Cluster {
			id = idClusterRole + r.Name
		}
		n := &graph.Node{
			ID:       id,
			Type:     graph.NodeCloudRole,
			Name:     r.Name,
			Provider: "kubernetes",
			Metadata: map[string]any{
				"privilege": level,
				"scope":     roleScope(r),
				"rules":     len(r.Rules),
			},
		}
		if r.Cluster {
			n.Metadata["scope"] = "cluster"
			if level == "admin" {
				n.Criticality = 90
			}
		}
		if level == "admin" {
			n.Criticality = 90
		}
		roleIDs[id] = n
		res.Nodes = append(res.Nodes, n)
	}

	roles, err := c.opts.API.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list roles: %w", err)
	}
	for _, r := range roles {
		addRole(r)
	}
	croles, err := c.opts.API.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list cluster roles: %w", err)
	}
	for _, r := range croles {
		r.Cluster = true
		addRole(r)
	}

	// Bindings: subjects receive roles.
	subjectNode := func(s Subject) *graph.Node {
		switch s.Kind {
		case "ServiceAccount":
			id := idSA + s.Namespace + "/" + s.Name
			if n, ok := saIDs[id]; ok {
				return n
			}
			return &graph.Node{
				ID: id, Type: graph.NodeIdentity, Name: s.Name, Provider: "kubernetes",
				Metadata: map[string]any{"namespace": s.Namespace, "identity_type": "service_account"},
			}
		default: // User, Group
			return &graph.Node{
				ID:       idIdentity + strings.ToLower(s.Kind) + "/" + s.Name,
				Type:     graph.NodeIdentity,
				Name:     s.Name,
				Provider: "kubernetes",
				Metadata: map[string]any{
					"identity_type": strings.ToLower(s.Kind),
					"external":      true,
				},
			}
		}
	}

	bindSubjects := func(bindings []RoleBinding, clusterScoped bool) {
		for _, rb := range bindings {
			// Resolve the role node.
			var roleID string
			if rb.RoleRef.Kind == "ClusterRole" {
				roleID = idClusterRole + rb.RoleRef.Name
			} else {
				ns := rb.Namespace
				roleID = idRole + ns + "/" + rb.RoleRef.Name
			}
			roleNode, known := roleIDs[roleID]
			if !known {
				continue
			}
			for _, sub := range rb.Subjects {
				subNode := subjectNode(sub)
				if _, ok := saIDs[subNode.ID]; !ok && sub.Kind == "ServiceAccount" {
					res.Nodes = append(res.Nodes, subNode)
					saIDs[subNode.ID] = subNode
				} else if sub.Kind != "ServiceAccount" {
					// Add user/group nodes (dedup by ID).
					dup := false
					for _, existing := range res.Nodes {
						if existing.ID == subNode.ID {
							dup = true
							break
						}
					}
					if !dup {
						res.Nodes = append(res.Nodes, subNode)
					}
				}
				risk := 40
				if lvl, _ := roleNode.Metadata["privilege"].(string); lvl == "admin" {
					risk = 95
				} else if lvl == "write" {
					risk = 70
				}
				res.Edges = append(res.Edges, &graph.Edge{
					Source:     subNode.ID,
					Target:     roleID,
					Type:       graph.EdgeHasPermission,
					Confidence: 1.0,
					Risk:       risk,
					Provenance: provenance(bindingKind(clusterScoped)),
				})
			}
		}
	}

	rbs, err := c.opts.API.ListRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list role bindings: %w", err)
	}
	bindSubjects(rbs, false)
	crbs, err := c.opts.API.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list cluster role bindings: %w", err)
	}
	bindSubjects(crbs, true)

	// Secret metadata only.
	secrets, err := c.opts.API.ListSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("kubernetes connector: list secrets: %w", err)
	}
	for _, s := range secrets {
		// Skip built-in token secrets auto-mounted to pods; they are
		// infrastructure noise unless projected.
		n := &graph.Node{
			ID:       idSecret + s.Namespace + "/" + s.Name,
			Type:     graph.NodeSecret,
			Name:     s.Name,
			Provider: "kubernetes",
			Metadata: map[string]any{
				"type":     s.Type,
				"location": "k8s:" + s.Namespace,
				// Never a value: the list API returns metadata only.
			},
		}
		if strings.Contains(s.Namespace, "prod") || strings.Contains(strings.ToLower(s.Name), "prod") {
			n.Metadata["environment"] = "production"
			n.Criticality = 80
		}
		res.Nodes = append(res.Nodes, n)
	}

	sort.Slice(res.Nodes, func(i, j int) bool { return res.Nodes[i].ID < res.Nodes[j].ID })
	sort.Slice(res.Edges, func(i, j int) bool {
		if res.Edges[i].Source != res.Edges[j].Source {
			return res.Edges[i].Source < res.Edges[j].Source
		}
		return res.Edges[i].Target < res.Edges[j].Target
	})
	return res, nil
}

// AnalyzeRules classifies a role's rule set by its most dangerous verbs.
// Returns (privilege level, edge risk).
func AnalyzeRules(rules []PolicyRule) (string, int) {
	level, risk := "none", 30
	for _, r := range rules {
		for _, v := range r.Verbs {
			switch {
			case v == "*" || v == "escalate" || v == "bind" || v == "impersonate":
				return "admin", 95
			case v == "create" || v == "delete" || v == "patch" || v == "update" || v == "deletecollection":
				if level != "admin" {
					level, risk = "write", 70
				}
			case v == "get" || v == "list" || v == "watch":
				if level == "none" {
					level, risk = "read", 40
				}
			}
		}
	}
	return level, risk
}

func roleScope(r Role) string {
	if r.Cluster {
		return "cluster"
	}
	return "namespace:" + r.Namespace
}

func environment(namespace string) string {
	if strings.Contains(namespace, "prod") {
		return "production"
	}
	return "development"
}

func bindingKind(clusterScoped bool) string {
	if clusterScoped {
		return "clusterrolebinding"
	}
	return "rolebinding"
}

func provenance(sourceObject string) graph.Provenance {
	return graph.Provenance{
		Connector:    "kubernetes",
		SourceObject: sourceObject,
	}
}
