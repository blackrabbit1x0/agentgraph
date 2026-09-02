package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
)

// SDKAPI implements API against live AWS services using the default
// credential chain. All calls are read-only List/Get operations; the
// connector is designed to run with a read-only principal.
type SDKAPI struct {
	stsClient    *sts.Client
	iamClient    *iam.Client
	smClient     *secretsmanager.Client
	s3Client     *s3.Client
	rdsClient    *rds.Client
	lambdaClient *lambda.Client
}

// LoadAPI builds an SDKAPI from the environment's default AWS
// configuration (env vars, shared credentials file, SSO, or instance
// profile). region is optional; the SDK default region resolution applies
// when empty.
func LoadAPI(ctx context.Context, region string) (*SDKAPI, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws connector: load config: %w", err)
	}
	return &SDKAPI{
		stsClient:    sts.NewFromConfig(cfg),
		iamClient:    iam.NewFromConfig(cfg),
		smClient:     secretsmanager.NewFromConfig(cfg),
		s3Client:     s3.NewFromConfig(cfg),
		rdsClient:    rds.NewFromConfig(cfg),
		lambdaClient: lambda.NewFromConfig(cfg),
	}, nil
}

// GetCallerIdentity implements API.
func (a *SDKAPI) GetCallerIdentity(ctx context.Context) (string, string, string, error) {
	out, err := a.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", "", err
	}
	name := aws.ToString(out.Arn)
	if i := lastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return aws.ToString(out.Account), aws.ToString(out.Arn), name, nil
}

// ListRoles implements API.
func (a *SDKAPI) ListRoles(ctx context.Context) ([]Role, error) {
	var out []Role
	var marker *string
	for {
		res, err := a.iamClient.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, r := range res.Roles {
			trust := "{}"
			if r.AssumeRolePolicyDocument != nil {
				trust = *r.AssumeRolePolicyDocument
			}
			out = append(out, Role{
				Name:        aws.ToString(r.RoleName),
				ARN:         aws.ToString(r.Arn),
				TrustPolicy: trust,
				Path:        aws.ToString(r.Path),
			})
		}
		if res.Marker == nil {
			return out, nil
		}
		marker = res.Marker
	}
}

// ListUsers implements API.
func (a *SDKAPI) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	var marker *string
	for {
		res, err := a.iamClient.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, u := range res.Users {
			out = append(out, User{
				Name: aws.ToString(u.UserName),
				ARN:  aws.ToString(u.Arn),
			})
		}
		if res.Marker == nil {
			return out, nil
		}
		marker = res.Marker
	}
}

// ListSecrets implements API. Only names and ARNs are requested; secret
// values are never fetched.
func (a *SDKAPI) ListSecrets(ctx context.Context) ([]Secret, error) {
	var out []Secret
	var nextToken *string
	for {
		res, err := a.smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		for _, s := range res.SecretList {
			out = append(out, Secret{
				Name: aws.ToString(s.Name),
				ARN:  aws.ToString(s.ARN),
			})
		}
		if res.NextToken == nil {
			return out, nil
		}
		nextToken = res.NextToken
	}
}

// ListBuckets implements API.
func (a *SDKAPI) ListBuckets(ctx context.Context) ([]Bucket, error) {
	res, err := a.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	var out []Bucket
	for _, b := range res.Buckets {
		out = append(out, Bucket{Name: aws.ToString(b.Name)})
	}
	return out, nil
}

// ListDatabases implements API.
func (a *SDKAPI) ListDatabases(ctx context.Context) ([]Database, error) {
	var out []Database
	var marker *string
	for {
		res, err := a.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, db := range res.DBInstances {
			out = append(out, Database{
				Identifier: aws.ToString(db.DBInstanceIdentifier),
				Engine:     aws.ToString(db.Engine),
				ARN:        aws.ToString(db.DBInstanceArn),
			})
		}
		if res.Marker == nil {
			return out, nil
		}
		marker = res.Marker
	}
}

// ListFunctions implements API.
func (a *SDKAPI) ListFunctions(ctx context.Context) ([]Function, error) {
	var out []Function
	var marker *string
	for {
		res, err := a.lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, f := range res.Functions {
			out = append(out, Function{
				Name:    aws.ToString(f.FunctionName),
				ARN:     aws.ToString(f.FunctionArn),
				RoleARN: aws.ToString(f.Role),
			})
		}
		if res.NextMarker == nil {
			return out, nil
		}
		marker = res.NextMarker
	}
}

// Compile-time checks that SDKAPI satisfies the connector API.
var (
	_ API                  = (*SDKAPI)(nil)
	_ connectors.Connector = (*Connector)(nil)
)

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
