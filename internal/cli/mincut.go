package cli

import (
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	"github.com/spf13/cobra"
)

func newMincutCommand() *cobra.Command {
	var agentID, targetID string
	var all bool

	cmd := &cobra.Command{
		Use:   "mincut",
		Short: "Compute the minimum set of relationships to cut an agent off from a target",
		Long: `Compute the minimum set of relationships (a minimum edge cut) whose
removal disconnects an agent from a target, using max-flow analysis.

With --all, computes cuts against every crown jewel the agent can reach.

Examples:
  agentgraph mincut --agent finance-agent --to production-database
  agentgraph mincut --agent finance-agent --all`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			if agentID == "" {
				fmt.Println("error: --agent is required")
				return
			}

			if all {
				results, err := remediation.MincutToCrownJewels(g, agentID, paths.Options{})
				if err != nil {
					fmt.Printf("error: %v\n", err)
					return
				}
				if len(results) == 0 {
					fmt.Printf("Agent %s reaches no crown jewels; nothing to cut.\n", agentID)
					return
				}
				fmt.Printf("MINIMUM CUTS: %s -> crown jewels\n\n", agentID)
				for _, r := range results {
					printCut(r)
				}
				return
			}

			if targetID == "" {
				fmt.Println("error: --to or --all is required")
				return
			}
			// Resolve fuzzy target to exact ID.
			id := resolveTargetID(g, targetID)
			if id == "" {
				fmt.Printf("error: no node matches %q\n", targetID)
				return
			}
			res, err := remediation.Mincut(g, agentID, id, paths.Options{})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			printCut(res)
		},
	}
	cmd.Flags().StringVar(&agentID, "agent", "", "source agent ID")
	cmd.Flags().StringVar(&targetID, "to", "", "target node ID or name substring")
	cmd.Flags().BoolVar(&all, "all", false, "cut all reachable crown jewels")
	return cmd
}

func printCut(r *remediation.CutResult) {
	fmt.Printf("%s -> %s\n", r.Agent, r.Target)
	fmt.Printf("  Paths considered:   %d\n", r.PathsConsidered)
	if len(r.CutEdges) == 0 {
		fmt.Printf("  No path exists; nothing to cut.\n\n")
		return
	}
	fmt.Printf("  Cut %d relationship(s):\n", len(r.CutEdges))
	for _, e := range r.CutEdges {
		fmt.Printf("    %s --%s--> %s\n", e.Source, e.Type, e.Target)
	}
	fmt.Println()
}

// resolveTargetID resolves a fuzzy target spec to an exact node ID.
func resolveTargetID(g *graph.Graph, spec string) string {
	if _, ok := g.Node(spec); ok {
		return spec
	}
	for _, n := range g.Nodes() {
		if containsFold(n.ID, spec) || containsFold(n.Name, spec) {
			return n.ID
		}
	}
	return ""
}

// containsFold is a case-insensitive substring test.
func containsFold(s, sub string) bool {
	if len(sub) == 0 || len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFoldStr(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFoldStr(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
