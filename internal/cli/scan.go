package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/config"
	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
	"github.com/blackrabbit1x0/agentgraph/internal/connectors/aws"
	"github.com/blackrabbit1x0/agentgraph/internal/connectors/github"
	"github.com/blackrabbit1x0/agentgraph/internal/connectors/kubernetes"
	"github.com/blackrabbit1x0/agentgraph/internal/connectors/mcp"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	gh "github.com/google/go-github/v74/github"
	"github.com/spf13/cobra"
)

// graphFile and savePath are wired in root.go.

func newScanMCPCommand() *cobra.Command {
	var live bool
	var timeout int

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Discover MCP servers and tools from local AI-client configurations",
		Long: `Discover MCP servers and tools from local AI-client
configurations: Claude Desktop, Cursor, VS Code, opencode, and generic
.mcp.json files.

stdio servers are never spawned - only their configuration is read.
Environment variable names are recorded; values are never stored.
URLs are redacted of sensitive query parameters.

With --live, HTTP/SSE servers are queried via the MCP protocol
(initialize -> tools/list) to inventory their tools. No tool is ever
called.`,
		Run: func(cmd *cobra.Command, args []string) {
			c := mcp.New(mcp.Options{Live: live, TimeoutSeconds: timeout})
			g := runScanConnectors([]connectors.Connector{c})
			printDashboard(g)
		},
	}
	cmd.Flags().BoolVar(&live, "live", false, "query HTTP/SSE servers for their tool lists")
	cmd.Flags().IntVar(&timeout, "timeout", 5, "per-server timeout for live queries (seconds)")
	return cmd
}

func newScanKubernetesCommand() *cobra.Command {
	var server, token, kubeconfig string
	var insecure bool

	cmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Discover Kubernetes pods, service accounts, RBAC, and secret metadata",
		Long: `Discover Kubernetes infrastructure via read-only API calls:
pods and their service accounts, RBAC roles/bindings (with verb-derived
privilege levels), and secret metadata.

Access is resolved from --server/--token flags, a kubeconfig
(--kubeconfig, default ~/.kube/config), or in-cluster service account
environment. Secret values are never read.

Discovered node IDs (e.g. k8s:sa:prod/payments-deployer) can be
referenced from agentgraph.yaml relationships.`,
		Run: func(cmd *cobra.Command, args []string) {
			api, err := kubernetes.LoadRestAPI(cmd.Context(), kubernetes.RestOptions{
				Server:                server,
				Token:                 token,
				InsecureSkipTLSVerify: insecure,
			}, kubeconfig)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			c := kubernetes.New(kubernetes.Options{API: api})
			g := runScanConnectors([]connectors.Connector{c})
			printDashboard(g)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "Kubernetes API server URL")
	cmd.Flags().StringVar(&token, "token", "", "bearer token (read-only)")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig (default ~/.kube/config)")
	cmd.Flags().BoolVar(&insecure, "insecure-skip-tls-verify", false, "skip TLS verification")
	return cmd
}

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [connector...]",
		Short: "Load configuration and/or run connectors, then print a security dashboard",
		Long: `Load configuration and/or run connectors, then print a security dashboard.

Without arguments, scans the local configuration only.
Available connectors: github, aws, mcp.

Examples:
  agentgraph scan
  agentgraph scan github
  agentgraph scan github aws mcp --save graph.json
  agentgraph scan --graph graph.json    # analyze a previously saved graph`,
		Run: func(cmd *cobra.Command, args []string) {
			g := runScan(args)
			printDashboard(g)
		},
	}
	cmd.AddCommand(newScanGithubCommand(), newScanAWSCommand(), newScanMCPCommand(), newScanKubernetesCommand())
	return cmd
}

func newScanGithubCommand() *cobra.Command {
	var token, owner string
	var includeForks bool
	var maxRepos int

	cmd := &cobra.Command{
		Use:   "github",
		Short: "Discover GitHub repositories, workflows, and secrets metadata",
		Long: `Discover GitHub repositories, workflows, and secrets metadata
using a read-only token (GITHUB_TOKEN environment variable or --token).

Requires a token with repo scope (read-only fine-grained tokens work).
Discovering Actions secrets additionally requires the secrets read scope.`,
		Run: func(cmd *cobra.Command, args []string) {
			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}
			if token == "" {
				fmt.Println("error: GitHub token required (set GITHUB_TOKEN or pass --token)")
				os.Exit(1)
			}
			client := gh.NewClient(nil).WithAuthToken(token)
			c := github.New(github.Options{
				Client:       client,
				Owner:        owner,
				IncludeForks: includeForks,
				MaxRepos:     maxRepos,
			})
			g := runScanConnectors([]connectors.Connector{c})
			printDashboard(g)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "GitHub personal access token (read-only)")
	cmd.Flags().StringVar(&owner, "owner", "", "user or organization to scan (default: authenticated user)")
	cmd.Flags().BoolVar(&includeForks, "include-forks", false, "include forked repositories")
	cmd.Flags().IntVar(&maxRepos, "max-repos", 100, "maximum repositories to enumerate")
	return cmd
}

func newScanAWSCommand() *cobra.Command {
	var region string

	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Discover AWS IAM roles, trust chains, secrets, buckets, databases, functions",
		Long: `Discover AWS infrastructure using the default credential chain
(environment variables, shared credentials file, SSO, or instance profile).

Uses read-only List/Get API calls only. Recommended: a read-only principal.

Discovered node IDs (e.g. aws:role:arn:aws:iam::123:role/deploy) can be
referenced from agentgraph.yaml relationships to connect agents to cloud.`,
		Run: func(cmd *cobra.Command, args []string) {
			api, err := aws.LoadAPI(context.Background(), region)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			c := aws.New(aws.Options{API: api})
			g := runScanConnectors([]connectors.Connector{c})
			printDashboard(g)
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "AWS region (default: SDK resolution)")
	return cmd
}

// runScan resolves the scan source: snapshot, connectors, or local config.
func runScan(args []string) *graph.Graph {
	var conns []connectors.Connector
	for _, name := range args {
		switch name {
		case "github":
			// Handled by the dedicated subcommand; here we require a token.
			token := os.Getenv("GITHUB_TOKEN")
			if token == "" {
				fmt.Println("error: GITHUB_TOKEN not set (for full options run: agentgraph scan github)")
				os.Exit(1)
			}
			client := gh.NewClient(nil).WithAuthToken(token)
			conns = append(conns, github.New(github.Options{Client: client}))
		case "aws":
			api, err := aws.LoadAPI(context.Background(), "")
			if err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			conns = append(conns, aws.New(aws.Options{API: api}))
		case "mcp":
			conns = append(conns, mcp.New(mcp.Options{}))
		case "kubernetes":
			api, err := kubernetes.LoadRestAPI(context.Background(), kubernetes.RestOptions{}, "")
			if err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			conns = append(conns, kubernetes.New(kubernetes.Options{API: api}))
		default:
			fmt.Printf("error: unknown connector %q (available: github, aws, mcp, kubernetes)\n", name)
			os.Exit(1)
		}
	}
	if len(conns) == 0 {
		return runScanConnectors(nil)
	}
	return runScanConnectors(conns)
}

// runScanConnectors merges the YAML configuration (if present) with
// connector discoveries, applies crown jewels, optionally saves the
// merged graph, and returns it.
func runScanConnectors(conns []connectors.Connector) *graph.Graph {
	// Prefer a saved snapshot when --graph is set.
	if graphFile != "" {
		g, _ := loadGraph()
		maybeSaveGraph(g)
		return g
	}

	asm := graph.NewAssembler()
	var crownJewels []string
	var warnings []string

	if fileExists(resolveConfigPath()) {
		cfgData, err := os.ReadFile(resolveConfigPath())
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		cfg, err := config.Parse(cfgData)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		cj, warns, err := cfg.Assemble(asm)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		crownJewels = cj
		warnings = append(warnings, warns...)
	}

	ctx := context.Background()
	for _, c := range conns {
		res, err := c.Discover(ctx)
		if err != nil {
			fmt.Printf("error: connector %s: %v\n", c.Name(), err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "connector %s: %d nodes, %d relationships discovered\n",
			c.Name(), len(res.Nodes), len(res.Edges))
		for _, n := range res.Nodes {
			if err := asm.AddNode(n); err != nil {
				fmt.Printf("error: connector %s: %v\n", c.Name(), err)
				os.Exit(1)
			}
		}
		for _, e := range res.Edges {
			asm.AddEdge(e)
		}
	}

	g, err := asm.Build()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	for _, id := range crownJewels {
		n, ok := g.Node(id)
		if !ok {
			fmt.Fprintf(os.Stderr, "warning: crown jewel %q was not discovered by any source\n", id)
			continue
		}
		n.CrownJewel = true
	}

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	maybeSaveGraph(g)
	return g
}

func maybeSaveGraph(g *graph.Graph) {
	if savePath == "" {
		return
	}
	if err := graph.SaveSnapshotFile(g, savePath); err != nil {
		fmt.Printf("error: save graph: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "saved graph snapshot to %s (%d nodes, %d edges)\n",
		savePath, g.NodeCount(), g.EdgeCount())
}

func printDashboard(g *graph.Graph) {
	all, _ := paths.EnumerateAll(g, paths.Options{})
	scored := remediation.ScoreAll(all)

	tools := len(g.NodesByType(graph.NodeTool)) + len(g.NodesByType(graph.NodeMCPServer))
	identities := len(g.NodesByType(graph.NodeIdentity))
	resources := g.NodeCount() - len(g.NodesByType(graph.NodeAIAgent)) -
		len(g.NodesByType(graph.NodeTool)) - len(g.NodesByType(graph.NodeMCPServer))

	critical, high := 0, 0
	cjExposed := map[string]bool{}
	for _, sp := range scored {
		switch sp.Risk.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		}
		if sp.Path.Target.CrownJewel {
			cjExposed[sp.Path.Target.ID] = true
		}
	}

	fmt.Println("AGENTGRAPH")
	fmt.Println()
	fmt.Printf("AI Agents                 %d\n", len(g.NodesByType(graph.NodeAIAgent)))
	fmt.Printf("Connected Tools           %d\n", tools)
	fmt.Printf("Identities                %d\n", identities)
	fmt.Printf("Discovered Resources      %d\n", resources)
	fmt.Printf("Graph                     %d nodes / %d edges\n", g.NodeCount(), g.EdgeCount())
	fmt.Println()
	fmt.Printf("Critical Attack Paths     %d\n", critical)
	fmt.Printf("High-Risk Attack Paths    %d\n", high)
	fmt.Printf("Crown Jewels Exposed      %d\n", len(cjExposed))
	fmt.Println()

	// Highest-risk agent.
	type agentRisk struct {
		id    string
		score int
	}
	var agents []agentRisk
	for _, a := range g.NodesByType(graph.NodeAIAgent) {
		best := 0
		for _, sp := range scored {
			if sp.Path.Source.ID == a.ID && sp.Risk.Score > best {
				best = sp.Risk.Score
			}
		}
		agents = append(agents, agentRisk{a.ID, best})
	}
	if len(agents) > 0 {
		top := agents[0]
		for _, a := range agents[1:] {
			if a.score > top.score {
				top = a
			}
		}
		fmt.Println("Highest Risk Agent")
		fmt.Printf("%s (top path risk %d/100)\n", top.id, top.score)
	}

	// Most critical path.
	var topPath *remediation.ScoredPath
	for _, sp := range scored {
		if topPath == nil || sp.Risk.Score > topPath.Risk.Score {
			topPath = sp
		}
	}
	if topPath != nil {
		fmt.Println()
		fmt.Println("Most Critical Path")
		fmt.Printf("%s  risk %d/100  confidence %.2f\n",
			topPath.Path.ID, topPath.Risk.Score, topPath.Path.Confidence)
		fmt.Println(renderPathArrow(topPath.Path))
	}
}
