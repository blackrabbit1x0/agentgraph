package aws

import (
	"context"
	"testing"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// fakeAPI simulates a small AWS account:
//   - deploy-role trusted by the CI role and by an external account
//   - ci-role trusted via an assumed-role session ARN
//   - a Lambda function executing as deploy-role
type fakeAPI struct{}

func (fakeAPI) GetCallerIdentity(context.Context) (string, string, string, error) {
	return "111122223333", "arn:aws:iam::111122223333:user/sec-scanner", "sec-scanner", nil
}

func (fakeAPI) ListRoles(context.Context) ([]Role, error) {
	return []Role{
		{
			Name: "deploy-role", ARN: "arn:aws:iam::111122223333:role/deploy-role",
			TrustPolicy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:role/ci-role","arn:aws:iam::999988887777:root"]},"Action":"sts:AssumeRole"}]}`,
		},
		{
			Name: "ci-role", ARN: "arn:aws:iam::111122223333:role/ci-role",
			TrustPolicy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::111122223333:assumed-role/github-oidc/gha-session"},"Action":"sts:AssumeRole"}]}`,
		},
		{
			Name: "admin-role", ARN: "arn:aws:iam::111122223333:role/admin-role",
			TrustPolicy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
		},
		{
			// Deny-only trust: no principals should be extracted.
			Name: "denied-role", ARN: "arn:aws:iam::111122223333:role/denied-role",
			TrustPolicy: `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:role/ci-role"},"Action":"sts:AssumeRole"}]}`,
		},
	}, nil
}

func (fakeAPI) ListUsers(context.Context) ([]User, error) {
	return []User{
		{Name: "sec-scanner", ARN: "arn:aws:iam::111122223333:user/sec-scanner"},
		{Name: "developer", ARN: "arn:aws:iam::111122223333:user/developer"},
	}, nil
}

func (fakeAPI) ListSecrets(context.Context) ([]Secret, error) {
	return []Secret{
		{Name: "prod/db-password", ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-password-AbCdEf"},
		{Name: "staging/api-key", ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:staging/api-key-XyZ"},
	}, nil
}

func (fakeAPI) ListBuckets(context.Context) ([]Bucket, error) {
	return []Bucket{{Name: "prod-data-lake"}, {Name: "dev-uploads"}}, nil
}

func (fakeAPI) ListDatabases(context.Context) ([]Database, error) {
	return []Database{
		{Identifier: "prod-customers", Engine: "postgres", ARN: "arn:aws:rds:us-east-1:111122223333:db:prod-customers"},
	}, nil
}

func (fakeAPI) ListFunctions(context.Context) ([]Function, error) {
	return []Function{
		{Name: "deploy-runner", ARN: "arn:aws:lambda:us-east-1:111122223333:function:deploy-runner", RoleARN: "arn:aws:iam::111122223333:role/deploy-role"},
	}, nil
}

func TestDiscover(t *testing.T) {
	c := New(Options{API: fakeAPI{}, AccountID: "111122223333"})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	nodes := map[string]*graph.Node{}
	for _, n := range res.Nodes {
		nodes[n.ID] = n
	}

	// Required nodes.
	for _, id := range []string{
		"aws:identity:arn:aws:iam::111122223333:user/sec-scanner",
		"aws:role:arn:aws:iam::111122223333:role/deploy-role",
		"aws:role:arn:aws:iam::111122223333:role/ci-role",
		"aws:secret:prod/db-password",
		"aws:bucket:prod-data-lake",
		"aws:database:prod-customers",
		"aws:function:deploy-runner",
	} {
		if _, ok := nodes[id]; !ok {
			t.Errorf("missing node %s", id)
		}
	}

	// Trust chain: ci-role CAN_ASSUME deploy-role.
	hasEdge := func(src, tgt string, et graph.EdgeType) bool {
		for _, e := range res.Edges {
			if e.Source == src && e.Target == tgt && e.Type == et {
				return true
			}
		}
		return false
	}
	if !hasEdge("aws:identity:arn:aws:iam::111122223333:role/ci-role",
		"aws:role:arn:aws:iam::111122223333:role/deploy-role", graph.EdgeCanAssume) {
		t.Error("ci-role -> deploy-role CAN_ASSUME edge missing")
	}

	// External account trust is modeled (external flag set).
	ext := "aws:identity:arn:aws:iam::999988887777:root"
	if n, ok := nodes[ext]; !ok {
		t.Error("external account-root trust not modeled")
	} else if n.Metadata["external"] != true {
		t.Error("external trust should be flagged external")
	}
	if !hasEdge(ext, "aws:role:arn:aws:iam::111122223333:role/deploy-role", graph.EdgeCanAssume) {
		t.Error("external root -> deploy-role CAN_ASSUME edge missing")
	}

	// Assumed-role session collapses to the owning role.
	if !hasEdge("aws:identity:arn:aws:iam::111122223333:role/github-oidc",
		"aws:role:arn:aws:iam::111122223333:role/ci-role", graph.EdgeCanAssume) {
		t.Error("github-oidc role -> ci-role CAN_ASSUME edge missing")
	}

	// Wildcard trust is flagged as account root wildcard.
	if !hasEdge("aws:identity:arn:aws:iam::*:root",
		"aws:role:arn:aws:iam::111122223333:role/admin-role", graph.EdgeCanAssume) {
		t.Error("wildcard trust on admin-role not modeled")
	}

	// Deny-only policy yields no edges.
	for _, e := range res.Edges {
		if e.Target == "aws:role:arn:aws:iam::111122223333:role/denied-role" {
			t.Error("denied-role must not have trust edges")
		}
	}

	// Lambda execution role.
	if !hasEdge("aws:function:deploy-runner",
		"aws:role:arn:aws:iam::111122223333:role/deploy-role", graph.EdgeCanAssume) {
		t.Error("lambda -> execution role edge missing")
	}

	// Secrets carry metadata but never values.
	for _, n := range res.Nodes {
		if n.Type == graph.NodeSecret {
			for k := range n.Metadata {
				if k == "value" || k == "secret" || k == "plaintext" {
					t.Errorf("secret node %s carries forbidden field %s", n.ID, k)
				}
			}
		}
	}

	// Production inference.
	if n := nodes["aws:database:prod-customers"]; n.Metadata["environment"] != "production" {
		t.Error("prod-customers should be production")
	}
	if n := nodes["aws:secret:prod/db-password"]; n.Metadata["environment"] != "production" {
		t.Error("prod secret should be production")
	}
	if n := nodes["aws:database:prod-customers"]; n.Criticality < 80 {
		t.Error("prod database should carry high criticality")
	}

	// Provenance on every edge.
	for _, e := range res.Edges {
		if e.Provenance.Connector != "aws" {
			t.Errorf("edge %s->%s missing provenance", e.Source, e.Target)
		}
	}
}

func TestDiscoverRequiresAPI(t *testing.T) {
	c := New(Options{})
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected error with nil API")
	}
}

func TestParseTrustPrincipals(t *testing.T) {
	// Malformed JSON is ignored, not fatal.
	if got := ParseTrustPrincipals("{not json"); got != nil {
		t.Errorf("malformed policy should yield nil, got %v", got)
	}
	if got := ParseTrustPrincipals(""); got != nil {
		t.Errorf("empty policy should yield nil, got %v", got)
	}
}

func TestCollapseAssumedRole(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::111122223333:assumed-role/MyRole/session-1": "arn:aws:iam::111122223333:role/MyRole",
		"arn:aws:sts::123456789012:assumed-role/a/b/c":            "arn:aws:iam::123456789012:role/a",
		"arn:aws:iam::111122223333:role/plain-role":               "arn:aws:iam::111122223333:role/plain-role",
	}
	for in, want := range cases {
		got := collapseAssumedRole(in)
		if got != want {
			t.Errorf("collapseAssumedRole(%s) = %s, want %s", in, got, want)
		}
	}
}
