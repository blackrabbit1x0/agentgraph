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

![AgentGraph attack path](docs/demo-graph.svg)

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
./agentgraph demo watch       # simulated attack in progress
```

`demo watch` streams simulated agent telemetry through the runtime
detection engine:

```text
RUNTIME DETECTION
Events processed: 5

[HIGH] !! ATTACK PATH EXECUTION
  Path:     PATH-0053 (finance-agent -> customer-database)
  Stages:   3/6 observed
  Next:     aws-deploy-token
  Risk:     97/100 (CRITICAL)

Summary: 20 alerts - 3 complete, 4 critical, 13 high - across 15 attack paths
```

## Live discovery: GitHub and AWS connectors

Connectors discover real infrastructure and merge it with your YAML
configuration. Node IDs are stable and referenceable — a YAML relationship
can point at `github:repo:org/repo` or `aws:role:arn:aws:iam::123:role/deploy`
before the connector even runs.

**GitHub** (read-only token, `GITHUB_TOKEN` or `--token`):

```bash
./agentgraph scan github --owner my-org --save graph.json
```

Discovers repositories (with your effective permissions: CAN_READ /
CAN_WRITE / CAN_ADMIN), Actions workflows, and Actions secret **metadata**
(names only — values are never fetched or stored).

**AWS** (default credential chain, read-only principal recommended):

```bash
./agentgraph scan aws --save graph.json
```

Discovers IAM roles and their **trust chains** (who can assume what,
including external accounts and wildcard trusts), IAM users, Secrets
Manager secret names, S3 buckets, RDS instances, and Lambda execution
roles.

**MCP** (local configuration discovery — no credentials needed):

```bash
./agentgraph scan mcp --save graph.json
./agentgraph scan mcp --live --save graph.json   # also list tools from HTTP servers
```

Discovers MCP servers from Claude Desktop, Cursor, VS Code, opencode, and
generic `.mcp.json` configs. stdio servers are **never spawned**; env var
names are recorded but values never stored; URLs are redacted of
sensitive query parameters. With `--live`, HTTP/SSE servers are queried
via the MCP protocol (initialize → tools/list) — **no tool is ever called**.

**GitLab** (gitlab.com or self-hosted, read-only token):

```bash
./agentgraph scan gitlab --save graph.json
```

Discovers projects with your effective permissions (owner → CAN_ADMIN,
developer/maintainer → CAN_WRITE, reporter → CAN_READ) and CI/CD
variable metadata. The GitLab variables API returns values — this
connector drops them at the parse boundary and stores only names and
protection flags (enforced by test).

**Kubernetes** (read-only API discovery):

```bash
./agentgraph scan kubernetes --save graph.json
```

Discovers pods and their service accounts, RBAC roles and bindings
(with verb-derived privilege levels — `escalate`/`bind`/`*` → admin),
and secret metadata. Access resolves from `--server`/`--token` flags, a
kubeconfig, or the in-cluster service account environment.

**Combine everything:**

```bash
./agentgraph scan github aws mcp gitlab kubernetes --save graph.json
```

Then analyze or serve the saved graph:

```bash
./agentgraph --graph graph.json paths --from my-agent
./agentgraph --graph graph.json blast-radius my-agent
./agentgraph serve --graph graph.json
```

## Graph diff: what changed?

```bash
./agentgraph scan --save snapshot-old.json
# ... infrastructure changes ...
./agentgraph scan --save snapshot-new.json
./agentgraph diff snapshot-old.json snapshot-new.json
```

Output:

```text
Relationships   +1 (1 added, 0 removed)
Attack paths    +36 (36 new, 0 gone)

NEW ATTACK PATHS

  support-agent --CAN_ADMIN--> github-mcp --CAN_WRITE--> payments-repository
    --TRIGGERS--> production-ci --CAN_ASSUME--> aws-deploy-role
    introduced by: support-agent --CAN_ADMIN--> github-mcp
```

Every new attack path is attributed to the relationship that introduced it.

## Minimum cut: sever the blast radius

```bash
./agentgraph mincut --agent finance-agent --to production-database
./agentgraph mincut --agent finance-agent --all    # every reachable crown jewel
```

Max-flow (Edmonds-Karp) analysis finds the **minimum set of
relationships** whose removal disconnects an agent from its targets —
the smallest possible change with the biggest security impact.

## Policy engine

```bash
./agentgraph policy                       # default rules
./agentgraph policy --rules my-rules.yaml # custom rules
```

Default rules: agents must not reach production admin (critical),
production environments (critical), or secrets (high). Custom rules:

```yaml
rules:
  - id: AGENT-100
    name: Agents must not reach payment infrastructure
    severity: critical
    when:
      node_type: AI_AGENT
    deny_reach:
      has_any_tag: [payments, billing]
      environment: production
```

Violations include the full path evidence for auditors.

## SVG export

```bash
./agentgraph export --svg --out graph.svg
./agentgraph export --svg --from finance-agent --out highlighted.svg
```

Standalone SVG image of the graph: agents on the left, targets on the
right, crown jewels in gold, admin/execute edges in red, and (with
`--from`) the agent's most dangerous path highlighted in blue. Drop it
straight into a README, report, or slide deck.

## Runtime detection: EDR for AI agents (research preview)

Attack paths describe what *could* happen. Runtime detection watches what
agents *actually do*, and alerts when observed behavior advances in order
along a known dangerous path (PRD section 68):

```bash
# Batch: analyze an event log
./agentgraph watch --events agent-events.jsonl

# Live: tail the log and process events as they arrive
./agentgraph watch --events agent-events.jsonl --follow
```

Or run detection inside the dashboard — alerts stream live into the web
UI via server-sent events:

```bash
./agentgraph serve --graph graph.json --watch agent-events.jsonl --follow
```

Event format (one JSON object per line — from an MCP gateway log, audit
log, or agent telemetry):

```json
{"timestamp":"2026-09-03T10:02:14Z","agent":"finance-agent",
 "action":"tool_call","tool":"github-mcp","target":"payments-repository"}
```

Alert levels: **HIGH** (≥50% of path stages observed), **CRITICAL**
(within one stage of the target), **COMPLETE** (target reached).
Out-of-order events never advance a path; every alert names the path,
the next hop, and the path's risk score. Alerts are also exposed at
`/api/v1/alerts` and `/api/v1/alerts/stream` (SSE).

## MITRE ATT&CK and agent-attack taxonomy

Every path maps to the frameworks security teams already use:

```bash
./agentgraph explain PATH-0047
```

```text
MITRE ATT&CK techniques:
  T1072      Software Deployment Tools
  T1078      Valid Accounts
  T1548      Abuse Elevation Control Mechanism
  T1552      Unsecured Credentials
  T1195.002  Compromise Software Supply Chain

Agent attack techniques:
  AGT-004    Agent Credential Exposure
  AGT-006    MCP Trust Exploitation
  AGT-008    Agent Identity Escalation
  AGT-009    Agent-to-Cloud Pivot
  AGT-010    Agent-to-CI/CD Pivot
```

ATT&CK tags and AGT classifications are included in JSON export. Not
every relationship is forced into ATT&CK — only meaningful mappings.

## Probabilistic attack paths

Reachability says a path *can* be walked; likelihood estimates how
*plausibly* it is. Every edge gets an exploitation probability derived
from its risk (ease of abuse), attenuated by confidence (existence
certainty), with optional YAML overrides:

```yaml
relationships:
  - source: finance-agent
    target: github-mcp
    type: USES
    likelihood: 0.9     # informed estimate, (0, 1]
```

Path likelihood is the product of its hops — long chains attenuate
quickly, which is the point:

```text
PATH-0005  CRITICAL  risk  97  conf 1.00  likelihood 0.0580 (POSSIBLE)  6 hops
```

A 97/100-risk 6-hop path is only ~6% likely to be walked end-to-end;
`agentgraph paths` orders results by **expected threat** (risk ×
likelihood) so plausible medium-risk paths outrank implausible critical
ones. `agentgraph explain` shows per-hop likelihood and the full
breakdown.

## Neo4j graph store

Graphs persist as files by default (`--save graph.json`). For durable,
Cypher-queryable storage, add `--store neo4j`:

```bash
# Run Neo4j (any 5.x):
docker run -e NEO4J_AUTH=neo4j/yourpass -p 7687:7687 neo4j:5

# Save and load snapshots:
NEO4J_PASSWORD=yourpass agentgraph scan github --store neo4j --store-key prod
NEO4J_PASSWORD=yourpass agentgraph blast-radius my-agent --store neo4j --store-key prod
```

Configuration via `NEO4J_URI` (default `neo4j://localhost:7687`),
`NEO4J_USER` (default `neo4j`), `NEO4J_PASSWORD`. Snapshots are stored
as `(:AgentGraphSnapshot {key})-[:CONTAINS]->(:AgentGraphNode)` with
`EDGE` relationships, so your team can query them directly:

```cypher
MATCH (n:AgentGraphNode {snapKey: "prod", type: "SECRET"})<-[e:EDGE]-(src)
RETURN n.name, src.id, e.type
```

## Install

Prebuilt binaries: [releases](https://github.com/blackrabbit1x0/agentgraph/releases)
for Linux, macOS, and Windows.

```bash
# macOS / Linux (Homebrew)
brew tap blackrabbit1x0/tap
brew install agentgraph

# macOS / Linux (script)
curl -fsSL https://raw.githubusercontent.com/blackrabbit1x0/agentgraph/main/install.sh | sh

# Docker (demo environment on http://localhost:8080)
docker compose up

# From source
go build -o agentgraph ./cmd/agentgraph
```

## Web dashboard

```bash
./agentgraph serve                    # from agentgraph.yaml
./agentgraph serve --graph graph.json # from a saved scan
```

Opens an interactive Cytoscape.js graph at http://127.0.0.1:8080 with:

- Node types color-coded, crown jewels in gold, dangerous edges
  (CAN_ADMIN / CAN_EXECUTE) highlighted in red
- Click an agent for its blast radius, crown jewels at risk, and a
  one-click remediation recommendation
- Click any path to highlight it across the graph

REST API (same data the dashboard uses):

```text
GET /api/v1/graph
GET /api/v1/agents
GET /api/v1/agents/{id}/blast-radius
GET /api/v1/agents/{id}/remediations
GET /api/v1/paths?from=agent&to=target&crown_jewels=true
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
| `agentgraph scan [github\|aws\|mcp\|kubernetes]` | Load config and/or run connectors |
| `agentgraph watch --events f.jsonl` | Detect attack-path execution in an event stream |
| `agentgraph serve` | Web dashboard + REST API |
| `agentgraph diff <a> <b>` | Compare snapshots: new/removed attack paths |
| `agentgraph mincut --agent A [--to B\|--all]` | Minimum relationship cut |
| `agentgraph policy [--rules f]` | Evaluate policy rules |
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
Connectors (YAML static, GitHub, AWS, MCP, Kubernetes)
        │
        ▼
Normalization (nodes + edges, secret redaction, assembler merge)
        │
        ▼
Graph Store (in-memory; snapshots via --save/--graph)
        │
        ├── Paths Engine     depth-limited enumeration, cycle prevention,
        │                    confidence filtering, BFS shortest path
        ├── Risk Engine      explainable 0–100 scoring per path
        ├── Blast Radius     direct/indirect reach, crown jewels,
        │                    highest privilege, exposure score
        ├── Remediation      edge-removal optimizer, choke-point analysis,
        │                    minimum cut (Edmonds-Karp)
        ├── Policy Engine    default + custom YAML rules with evidence
        ├── Diff Engine      snapshot comparison with path attribution
        ├── Runtime Engine   attack-path execution detection from events
        ├── Attack Mapping   MITRE ATT&CK + agent-attack taxonomy (AGT)
        └── API / Web        REST endpoints, Cytoscape.js dashboard, SVG export
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
cmd/agentgraph/            CLI entry point
internal/graph/            node/edge model, store, assembler, snapshots
internal/paths/            path enumeration + shortest path
internal/risk/             explainable risk scoring + path likelihood
internal/blast/            blast-radius + agent exposure analysis
internal/remediation/      remediation optimizer, choke points, min-cut
internal/policy/           default + custom policy rules
internal/diff/             snapshot comparison + path attribution
internal/runtime/          attack-path execution detection (events -> alerts)
internal/attack/           MITRE ATT&CK + agent-attack taxonomy mapping
internal/svg/              static + animated SVG graph rendering
internal/store/            graph persistence (memory, Neo4j)
internal/config/           YAML static connector
internal/connectors/       GitHub, GitLab, AWS, MCP, Kubernetes discovery
internal/api/              REST API + embedded web dashboard
internal/cli/              CLI commands + embedded demo environment
```

## Performance

The graph engine is validated against the engineering targets
(100k nodes / 500k edges, shortest path < 2s, blast radius < 5s,
search < 1s) by a synthetic benchmark suite:

```bash
make bench
```

Measured on the synthetic topology (100,000 nodes / 545,000 edges):
shortest path ~35ms, blast radius ~740ms, graph search ~4ms — with
roughly 20–60× headroom against every target.

## Security

AgentGraph handles sensitive infrastructure metadata and is designed to
be safe to run and share:

- **Secret values are never stored.** The YAML loader redacts forbidden
  metadata fields (with normalization, across all node types and edges)
  and warns; every connector drops API-provided values at the parse
  boundary (GitLab variables, GitHub/AWS/K8s secrets APIs) — enforced by
  tests. Snapshots are written `0600`.
- **The dashboard escapes all data** and loads no external scripts
  (Cytoscape is vendored into the binary); a strict CSP is served.
- **The API can require a bearer token** (`serve --token`), is
  rate-limited per client, caps SSE subscribers, and sets server
  timeouts. Binding beyond loopback without a token prints a warning.
- **`scan mcp --live` egress policy:** servers from your global configs
  may live on private hosts; servers configured by files in the working
  directory (possibly from an untrusted repo) are only queried on public
  hosts (`--allow-private` to override). Redirects are denied. Probed
  URLs are logged.
- **Release binaries are checksummed:** each release ships `SHA256SUMS`,
  verified by `install.sh` before installation.

See [SECURITY.md](SECURITY.md) for the reporting policy.

## Roadmap

- **Phase 0 — Graph prototype** ✅ (model, import, paths, blast radius,
  risk, remediation, choke points, CLI, demo)
- **Phase 1 — MVP** ✅ (GitHub + MCP connectors, web dashboard + REST API,
  graph snapshots)
- **Phase 2 — Cloud paths** ✅ (AWS connector: IAM trust chains, Secrets
  Manager, S3, RDS, Lambda)
- **Phase 3 — Remediation** ✅ (minimum-cut analysis, policy engine)
- **Phase 4 — Historical graph** ✅ (snapshot diff with path attribution)
- **Phase 5 — Enterprise identity** 🚧 (Kubernetes + GitLab ✅; Entra ID,
  Slack, Okta, Vault next)
- **Research — EDR for AI agents** 🚧 (runtime attack-path execution
  detection: `agentgraph watch`; probabilistic paths ✅; next: behavior
  graphs)
- **Graph store** ✅ (in-memory default; Neo4j persistence via
  `--store neo4j`, PRD 30)

## Contributing

Issues and PRs welcome. Connector contributions are especially valuable —
connectors implement a small interface and don't require touching the
graph engine.

## License

[MIT](LICENSE)
