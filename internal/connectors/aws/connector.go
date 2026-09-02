// Package aws implements the AWS connector: read-only discovery of IAM
// roles and trust chains, IAM users, Secrets Manager secret metadata, S3
// buckets, RDS instances, and Lambda functions (PRD section 21).
//
// It never reads or stores secret values. Secrets Manager is queried only
// for names and ARNs.
package aws

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
//	aws:identity:<arn>     IAM user or scanning principal
//	aws:role:<arn>         IAM role
//	aws:secret:<name>      Secrets Manager secret (metadata only)
//	aws:bucket:<name>      S3 bucket
//	aws:database:<id>      RDS instance identifier
//	aws:function:<name>    Lambda function
const (
	idIdentity = "aws:identity:"
	idRole     = "aws:role:"
	idSecret   = "aws:secret:"
	idBucket   = "aws:bucket:"
	idDatabase = "aws:database:"
	idFunction = "aws:function:"
)

// Role is a discovered IAM role.
type Role struct {
	Name        string
	ARN         string
	TrustPolicy string // raw JSON trust policy document
	Path        string
}

// User is a discovered IAM user.
type User struct {
	Name string
	ARN  string
}

// Secret is Secrets Manager secret metadata (never a value).
type Secret struct {
	Name string
	ARN  string
}

// Bucket is a discovered S3 bucket.
type Bucket struct {
	Name string
}

// Database is a discovered RDS instance.
type Database struct {
	Identifier string
	Engine     string
	ARN        string
}

// Function is a discovered Lambda function.
type Function struct {
	Name    string
	ARN     string
	RoleARN string
}

// API abstracts the AWS service calls the connector needs. The real
// implementation wraps the AWS SDK; tests provide fakes.
type API interface {
	GetCallerIdentity(ctx context.Context) (account, arn, principalName string, err error)
	ListRoles(ctx context.Context) ([]Role, error)
	ListUsers(ctx context.Context) ([]User, error)
	ListSecrets(ctx context.Context) ([]Secret, error)
	ListBuckets(ctx context.Context) ([]Bucket, error)
	ListDatabases(ctx context.Context) ([]Database, error)
	ListFunctions(ctx context.Context) ([]Function, error)
}

// Options configures the connector.
type Options struct {
	// API is the AWS API surface (required).
	API API
	// MaxRoles caps the number of roles enumerated (0 = all).
	MaxRoles int
	// AccountID overrides the discovered account ID (for tests).
	AccountID string
}

// Connector discovers AWS infrastructure.
type Connector struct {
	opts Options
}

// New returns an AWS connector.
func New(opts Options) *Connector {
	return &Connector{opts: opts}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return "aws" }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	if c.opts.API == nil {
		return nil, fmt.Errorf("aws connector: API is required")
	}

	res := &connectors.DiscoveryResult{}

	account, callerARN, callerName, err := c.opts.API.GetCallerIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: get caller identity: %w", err)
	}

	caller := &graph.Node{
		ID:       idIdentity + callerARN,
		Type:     graph.NodeIdentity,
		Name:     callerName,
		Provider: "aws",
		Metadata: map[string]any{
			"account":        account,
			"arn":            callerARN,
			"identity_type":  "iam_user_or_role",
			"privilege":      "admin",
			"read_only_scan": true,
		},
	}
	res.Nodes = append(res.Nodes, caller)

	// IAM roles with trust relationships.
	roles, err := c.opts.API.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: list roles: %w", err)
	}
	if c.opts.MaxRoles > 0 && len(roles) > c.opts.MaxRoles {
		roles = roles[:c.opts.MaxRoles]
	}
	roleARNs := map[string]*graph.Node{}
	for _, r := range roles {
		node := &graph.Node{
			ID:       idRole + r.ARN,
			Type:     graph.NodeCloudRole,
			Name:     r.Name,
			Provider: "aws",
			Metadata: map[string]any{
				"arn":  r.ARN,
				"path": r.Path,
			},
		}
		if strings.Contains(r.Path, "prod") || strings.Contains(strings.ToLower(r.Name), "prod") ||
			strings.Contains(strings.ToLower(r.Name), "deploy") {
			node.Metadata["environment"] = "production"
			node.Metadata["privilege"] = "admin"
			node.Criticality = 90
		}
		roleARNs[r.ARN] = node
		res.Nodes = append(res.Nodes, node)

		// Trust policy: who may assume this role.
		for _, principalARN := range ParseTrustPrincipals(r.TrustPolicy) {
			pNode, known := c.principalNode(principalARN, res)
			if !known {
				res.Nodes = append(res.Nodes, pNode)
			}
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     pNode.ID,
				Target:     node.ID,
				Type:       graph.EdgeCanAssume,
				Confidence: 1.0,
				Provenance: provenance("iam trust policy"),
			})
		}
	}

	// IAM users.
	users, err := c.opts.API.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: list users: %w", err)
	}
	for _, u := range users {
		n := &graph.Node{
			ID:       idIdentity + u.ARN,
			Type:     graph.NodeIdentity,
			Name:     u.Name,
			Provider: "aws",
			Metadata: map[string]any{"arn": u.ARN, "identity_type": "iam_user"},
		}
		res.Nodes = append(res.Nodes, n)
	}

	// Secrets Manager (names and ARNs only).
	secrets, err := c.opts.API.ListSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: list secrets: %w", err)
	}
	for _, s := range secrets {
		n := &graph.Node{
			ID:       idSecret + s.Name,
			Type:     graph.NodeSecret,
			Name:     s.Name,
			Provider: "aws",
			Metadata: map[string]any{
				"type":     "aws_secrets_manager",
				"location": "aws:secrets-manager",
				"arn":      s.ARN,
				// Never a value: ListSecrets returns metadata only.
			},
		}
		if strings.Contains(strings.ToLower(s.Name), "prod") {
			n.Metadata["environment"] = "production"
			n.Criticality = 85
		}
		res.Nodes = append(res.Nodes, n)
	}

	// S3 buckets.
	buckets, err := c.opts.API.ListBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: list buckets: %w", err)
	}
	for _, b := range buckets {
		n := &graph.Node{
			ID:       idBucket + b.Name,
			Type:     graph.NodeCloudResource,
			Name:     b.Name,
			Provider: "aws",
			Metadata: map[string]any{"type": "s3_bucket"},
		}
		if strings.Contains(strings.ToLower(b.Name), "prod") {
			n.Metadata["environment"] = "production"
			n.Criticality = 70
		}
		res.Nodes = append(res.Nodes, n)
	}

	// RDS instances.
	dbs, err := c.opts.API.ListDatabases(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: list databases: %w", err)
	}
	for _, d := range dbs {
		n := &graph.Node{
			ID:       idDatabase + d.Identifier,
			Type:     graph.NodeDatabase,
			Name:     d.Identifier,
			Provider: "aws",
			Metadata: map[string]any{
				"engine": d.Engine,
				"arn":    d.ARN,
			},
		}
		if strings.Contains(strings.ToLower(d.Identifier), "prod") {
			n.Metadata["environment"] = "production"
			n.Criticality = 90
		}
		res.Nodes = append(res.Nodes, n)
	}

	// Lambda functions (execution role edges).
	fns, err := c.opts.API.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws connector: list functions: %w", err)
	}
	for _, f := range fns {
		fnNode := &graph.Node{
			ID:       idFunction + f.Name,
			Type:     graph.NodeCloudResource,
			Name:     f.Name,
			Provider: "aws",
			Metadata: map[string]any{"type": "lambda_function", "arn": f.ARN},
		}
		res.Nodes = append(res.Nodes, fnNode)
		if role, ok := roleARNs[f.RoleARN]; ok {
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     fnNode.ID,
				Target:     role.ID,
				Type:       graph.EdgeCanAssume,
				Confidence: 1.0,
				Provenance: provenance("lambda execution role"),
			})
		}
	}

	// Deterministic output ordering.
	sort.Slice(res.Nodes, func(i, j int) bool { return res.Nodes[i].ID < res.Nodes[j].ID })
	sort.Slice(res.Edges, func(i, j int) bool {
		if res.Edges[i].Source != res.Edges[j].Source {
			return res.Edges[i].Source < res.Edges[j].Source
		}
		return res.Edges[i].Target < res.Edges[j].Target
	})
	return res, nil
}

// principalNode returns the graph node for a trust-policy principal ARN,
// creating an external-identity node when the principal was not discovered
// in this account (cross-account or service principals remain visible
// because they are part of the attack surface).
func (c *Connector) principalNode(arn string, res *connectors.DiscoveryResult) (*graph.Node, bool) {
	for _, n := range res.Nodes {
		if n.Metadata["arn"] == arn {
			return n, true
		}
	}
	name := arn
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		name = arn[i+1:]
	}
	return &graph.Node{
		ID:       idIdentity + arn,
		Type:     graph.NodeIdentity,
		Name:     name,
		Provider: "aws",
		Metadata: map[string]any{
			"arn":           arn,
			"identity_type": identityTypeForARN(arn),
			"external":      !strings.HasPrefix(arn, "arn:aws:iam::"+c.accountID()),
		},
	}, false
}

func (c *Connector) accountID() string {
	if c.opts.AccountID != "" {
		return c.opts.AccountID
	}
	return ""
}

func identityTypeForARN(arn string) string {
	switch {
	case strings.Contains(arn, ":sts:") || strings.Contains(arn, ":iam:"):
		if strings.Contains(arn, "assumed-role") {
			return "assumed_role_session"
		}
		return "iam_principal"
	case strings.HasPrefix(arn, "arn:aws:lambda"):
		return "lambda_service"
	default:
		return "service_or_external"
	}
}

func provenance(sourceObject string) graph.Provenance {
	return graph.Provenance{
		Connector:    "aws",
		SourceObject: sourceObject,
	}
}
