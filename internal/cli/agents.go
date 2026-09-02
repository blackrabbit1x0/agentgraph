package cli

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/spf13/cobra"
)

func newAgentsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "agents",
		Short: "List AI agents with tool, path, and risk summaries",
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()

			type row struct {
				id    string
				tools int
				paths int
				risk  int
			}
			var rows []row

			for _, a := range g.NodesByType(graph.NodeAIAgent) {
				tools := 0
				for _, e := range g.OutEdges(a.ID) {
					if e.Type == graph.EdgeUses {
						tools++
					}
				}
				ps, _ := paths.Enumerate(g, a.ID, paths.Options{})
				best := 0
				for _, sp := range scorePaths(ps) {
					if sp.Risk.Score > best {
						best = sp.Risk.Score
					}
				}
				rows = append(rows, row{a.ID, tools, len(ps), best})
			}

			sort.Slice(rows, func(i, j int) bool { return rows[i].risk > rows[j].risk })

			fmt.Printf("%-24s %-8s %-8s %-6s\n", "ID", "TOOLS", "PATHS", "RISK")
			for _, r := range rows {
				fmt.Printf("%-24s %-8d %-8d %d\n", r.id, r.tools, r.paths, r.risk)
			}
		},
	}
}
