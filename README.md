# AgentGraph

> **Attack-path analysis for autonomous AI agents.** Discover how agents, MCP tools, identities, secrets, CI/CD and cloud infrastructure connect — and determine what an attacker could reach if an agent is compromised.

## What happens if your AI agent gets compromised?

```text
Developer Agent
      │
      ▼
 GitHub MCP
      │
      ▼
 Repository
      │
      ▼
 CI/CD Pipeline
      │
      ▼
 AWS Role
      │
      ▼
 Production
```

Your agent technically has "just GitHub access." But compromising it may
still create a path to production.

**AgentGraph finds the path before an attacker does.**

Think BloodHound — but for AI agents.

## Why

AI agents are increasingly granted access to email, GitHub, Slack, cloud
infrastructure, databases, CI/CD, filesystems, MCP servers, and shell
environments. Traditional IAM and attack-path tools were designed around
humans, machines, and cloud identities — not agents whose *tools* unlock
further identities, secrets, and infrastructure.

Individually, each permission may look reasonable. The risk emerges from
**relationships between permissions and systems**. AgentGraph models those
relationships as a graph and calculates transitive attack paths.

## Quick start

```bash
# Build
go build -o agentgraph ./cmd/agentgraph

# Run against the built-in vulnerable demo environment
./agentgraph demo
```

Sample output:

```text
AGENTGRAPH

AI Agents                 4
Connected Tools           3
Identities                2
Discovered Resources      17

Critical Attack Paths     8
High-Risk Attack Paths    44
Crown Jewels Exposed      4

Most Critical Path
developer-agent --USES--> github-mcp --CAN_WRITE--> internal-tools
  --TRIGGERS--> production-ci --CONTAINS_SECRET--> aws-deploy-token
  --AUTHENTICATES_AS--> aws-deploy-role --CAN_ADMIN--> customer-database
```

Then explore:

```bash
./agentgraph demo blast-radius finance-agent
./agentgraph demo paths --from finance-agent --crown-jewels
./agentgraph demo explain PATH-0001
./agentgraph demo remediate finance-agent
./agentgraph demo chokepoints
```

## Model your own environment

```bash
./agentgraph init          # creates a starter agentgraph.yaml
./agentgraph scan          # loads it and prints the security dashboard
```

Configuration is a single YAML file describing agents, tools, identities,
secrets, and infrastructure — plus the relationships between them:

```yaml
agents:
  - id: finance-agent
    metadata:
      internet_access: true

mcp_servers:
  - id: github-mcp

repositories:
  - id: payments-repository
    metadata:
      environment: production

cloud_roles:
  - id: aws-deploy-role
    metadata:
      privilege: admin

databases:
  - id: production-database
    criticality: 95

crown_jewels:
  - production-database

relationships:
  - { source: finance-agent,      target: github-mcp,         type: USES }
  - { source: github-mcp,         target: payments-repository, type: CAN_WRITE }
  - { source: payments-repository, target: production-ci,       type: TRIGGERS }
  - { source: production-ci,       target: aws-deploy-role,     type: CAN_ASSUME }
  - { source: aws-deploy-role,     target: production-database, type: CAN_ACCESS }
```

Run `./agentgraph blast-radius finance-agent` and you get:

```text
finance-agent

Risk                       CRITICAL
Exposure Score             85

Direct access            Indirect access
  MCP_SERVER       2       SECRET          3
  IDENTITY         1       DATABASE        2
                          CLOUD_ROLE      1
                          ...

Reachable Nodes            17
Secrets                    3
Highest Privilege          admin

Critical Paths             4
Crown Jewels at Risk       customer-database, payment-signing-key, ...
```

## CLI reference

| Command | Description |
|---|---|
| `agentgraph init` | Create a starter `agentgraph.yaml` |
| `agentgraph scan` | Load config and print the security dashboard |
| `agentgraph agents` | List agents with tool/path/risk summaries |
| `agentgraph paths [--from A] [--to B] [--crown-jewels]` | Enumerate attack paths |
| `agentgraph path shortest --from A --to B` | Shortest attack path |
| `agentgraph blast-radius <agent>` | What a compromised agent could reach |
| `agentgraph explain <path-id>` | Why a path exists, with score breakdown |
| `agentgraph remediate <agent>` | The permission removal that kills the most paths |
| `agentgraph chokepoints` | Nodes appearing across the most attack paths |
| `agentgraph export [--out file.json]` | Export attack paths as JSON |
| `agentgraph demo <command>` | Run any command against the demo environment |

## How it works

```text
Connectors (YAML today; GitHub / MCP / AWS planned)
        │
        ▼
Normalization (nodes + edges, secret redaction)
        │
        ▼
Graph Store (in-memory; Neo4j planned)
        │
        ├── Paths Engine     depth-limited enumeration, cycle prevention,
        │                    confidence filtering, BFS shortest path
        ├── Risk Engine      explainable 0–100 scoring per path
        ├── Blast Radius     direct/indirect reach, crown jewels,
        │                    highest privilege, exposure score
        └── Remediation      edge-removal optimizer, choke-point analysis
```

**Key properties**

- Every edge carries a `confidence` (0–1); path confidence is the product.
- Every path is explainable: `agentgraph explain` shows the full risk
  factor breakdown.
- Secret values are **never stored** — only metadata (type, location,
  provider). The loader actively redacts and warns on forbidden fields.
- Deterministic path IDs (`PATH-0047`) are stable across commands.

**Risk scoring model** (additive, scaled by path confidence, 0–100):

```text
+30  target criticality (max)
+25  privilege level of highest-risk step (max)
+20  production access anywhere on the path
+15  execution / admin capability
+10  crown-jewel target
 +5  internet-exposed agent
 -5  human approval required
 -1  per hop beyond 3 (indirect paths are less reliable)

80–100 CRITICAL   60–79 HIGH   40–59 MEDIUM   20–39 LOW   0–19 INFO
```

## What AgentGraph is not

- Not a vulnerability scanner, EDR, CSPM, or prompt scanner
- Not a replacement for BloodHound (Active Directory)
- It does **not** exploit anything — it models *potential* paths and
  relationships, and it never needs (or stores) secret values

## Development

```bash
make build     # build ./bin/agentgraph
make test      # run the unit test suite
make vet       # go vet
make fmt       # gofmt
make demo      # build + run the demo scan
```

Or plain Go: `go build ./cmd/agentgraph`, `go test ./...`

### Repository layout

```text
cmd/agentgraph/       CLI entry point
internal/graph/       node/edge model + in-memory graph store
internal/paths/       path enumeration + shortest path
internal/risk/        explainable risk scoring
internal/blast/       blast-radius + agent exposure analysis
internal/remediation/ remediation optimizer + choke points
internal/config/      YAML static connector (secret redaction)
internal/cli/         CLI commands + embedded demo environment
```

## Roadmap

- **Phase 0 — Graph prototype** ✅ (this release: model, import, paths,
  blast radius, risk, remediation, choke points, CLI, demo)
- **Phase 1** — live GitHub + MCP connectors, basic web visualization
- **Phase 2** — AWS connector (IAM roles, Secrets Manager, EC2, RDS, S3)
- **Phase 3** — minimum-cut remediation, least-privilege suggestions
- **Phase 4** — graph snapshots, drift, historical diff
- **Phase 5** — Entra ID, Kubernetes, GitLab, Slack, Active Directory

## Contributing

Issues and PRs welcome. Connector contributions are especially valuable —
connectors implement a small interface and don't require touching the
graph engine.

## License

[MIT](LICENSE)
