package cli

import (
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	"github.com/spf13/cobra"
)

// pathOptionsFromFlags builds path enumeration options from CLI flags.
type pathFlags struct {
	from        string
	to          string
	crownJewels bool
	maxDepth    int
	minConf     float64
}

func (f *pathFlags) options() paths.Options {
	return paths.Options{
		MaxDepth:        f.maxDepth,
		MinConfidence:   f.minConf,
		TargetID:        "",
		TargetSubstring: f.to,
		CrownJewelsOnly: f.crownJewels,
	}
}

func addPathFlags(cmd *cobra.Command, f *pathFlags) {
	cmd.Flags().StringVar(&f.from, "from", "", "source agent ID")
	cmd.Flags().StringVar(&f.to, "to", "", "target node ID or name substring")
	cmd.Flags().BoolVar(&f.crownJewels, "crown-jewels", false, "only paths ending at crown jewels")
	cmd.Flags().IntVar(&f.maxDepth, "max-depth", paths.DefaultMaxDepth, "maximum path depth (hops)")
	cmd.Flags().Float64Var(&f.minConf, "min-confidence", 0, "minimum edge confidence (0-1)")
}

func newScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Load the configuration and print a security dashboard",
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			printDashboard(g)
		},
	}
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
