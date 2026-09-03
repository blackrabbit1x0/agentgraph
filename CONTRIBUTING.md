# Contributing to AgentGraph

Thanks for helping build attack-path analysis for AI agents.

## Getting started

```bash
git clone https://github.com/blackrabbit1x0/agentgraph
cd agentgraph
go build ./...
go test ./...
./agentgraph demo          # explore the vulnerable demo environment
```

You need Go 1.26 or newer. No other dependencies — the project is pure Go
with no code generation.

## Ways to contribute

### Connectors (highest impact)

AgentGraph's value grows with every connected system. Connectors are
self-contained packages that implement one interface:

```go
type Connector interface {
    Name() string
    Discover(ctx context.Context) (*DiscoveryResult, error)
}
```

`Discover` returns normalized nodes and edges; it never mutates the graph
(the assembler merges results). See `internal/connectors/` for five
worked examples: GitHub, GitLab, AWS, MCP, and Kubernetes.

**Connector rules:**

1. **Read-only.** Only List/Get API calls. Never create, modify, or
   delete anything on the target system.
2. **Never store secret values.** Secrets are modeled as metadata-only
   nodes (type, location, name). If an API returns values, drop them at
   the parse boundary — see the GitLab connector for the pattern and its
   enforcement test.
3. **Stable node IDs.** Use a provider-prefixed scheme
   (`github:repo:owner/name`, `aws:role:arn:...`) so YAML configurations
   can reference discovered nodes.
4. **Provenance on every edge.** Set `Provenance.Connector` and a
   meaningful `SourceObject` so users can trace why a relationship
   exists.
5. **Mocked tests.** Test against a fake HTTP server (see any
   `connector_test.go`); CI never uses real credentials.

Good next connectors: Entra ID, Slack, Okta, HashiCorp Vault, Jenkins,
Docker, PostgreSQL.

### Everything else

- Graph engine, path finding, risk scoring improvements
- Dashboard and visualization polish
- Docs, examples, and bug reports

## Development conventions

- `gofmt -w .` before committing (CI enforces it)
- `go vet ./...` must pass
- New features need tests; connectors need mocked-API tests
- Run the full suite: `go test ./...` (fast) or `make bench` for the
  performance validation suite (`RUN_PERF=1` required)

### Repository layout

```text
cmd/agentgraph/            CLI entry point
internal/graph/            node/edge model, store, assembler, snapshots
internal/paths/            path enumeration + shortest path
internal/risk/             explainable risk scoring
internal/blast/            blast-radius + agent exposure analysis
internal/remediation/      remediation optimizer, choke points, min-cut
internal/policy/           default + custom policy rules
internal/diff/             snapshot comparison + path attribution
internal/runtime/          attack-path execution detection
internal/attack/           MITRE ATT&CK + agent-attack taxonomy mapping
internal/svg/              static + animated SVG graph rendering
internal/config/           YAML static connector
internal/connectors/       GitHub, GitLab, AWS, MCP, Kubernetes
internal/api/              REST API + embedded web dashboard
internal/cli/              CLI commands + embedded demo environment
```

## Pull requests

1. Fork, branch, commit (small PRs land faster).
2. Reference the issue you're fixing, if any.
3. Make sure `go test ./...`, `go vet ./...`, and `gofmt -l .` are clean.
4. Describe what changed and why; for connectors, include sample output.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities in AgentGraph itself.
