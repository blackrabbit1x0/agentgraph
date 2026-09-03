package cli

import (
	"fmt"
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
	"github.com/spf13/cobra"
)

func newPathsCommand() *cobra.Command {
	var f pathFlags

	cmd := &cobra.Command{
		Use:   "paths",
		Short: "Enumerate attack paths",
		Long: `Enumerate attack paths originating from an AI agent.

If --from is omitted, paths from every agent are enumerated.
Filter targets with --to (ID or name substring) or --crown-jewels.`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			opts := f.options()

			// Always enumerate globally so path IDs match "agentgraph explain".
			ps, err := paths.EnumerateAll(g, opts)
			if err != nil {
				if _, ok := err.(*paths.TruncatedError); !ok {
					fmt.Printf("error: %v\n", err)
					return
				}
				fmt.Println("note: results truncated at path limit")
			}
			if f.from != "" {
				filtered := make([]*paths.Path, 0, len(ps))
				for _, p := range ps {
					if p.Source.ID == f.from {
						filtered = append(filtered, p)
					}
				}
				ps = filtered
			}

			scored := scorePaths(ps)
			if len(scored) == 0 {
				fmt.Println("No attack paths found.")
				return
			}
			// Order by expected threat: impact x likelihood (PRD 68).
			sort.SliceStable(scored, func(i, j int) bool {
				ei := risk.ExpectedThreat(scored[i].Risk.Score, risk.PathLikelihood(scored[i].Path.Edges()))
				ej := risk.ExpectedThreat(scored[j].Risk.Score, risk.PathLikelihood(scored[j].Path.Edges()))
				return ei > ej
			})
			for _, sp := range scored {
				printScoredPath(sp)
			}
			fmt.Printf("\nTotal: %d paths\n", len(scored))
		},
	}

	addPathFlags(cmd, &f)

	cmd.AddCommand(newShortestCommand(&f))
	return cmd
}

func newShortestCommand(f *pathFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "shortest",
		Short: "Find the shortest attack path between two nodes",
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			if f.from == "" || f.to == "" {
				fmt.Println("error: --from and --to are both required")
				return
			}
			p := paths.Shortest(g, f.from, f.to)
			if p == nil {
				fmt.Printf("No path from %s to %s.\n", f.from, f.to)
				return
			}
			sp := scorePaths([]*paths.Path{p})[0]
			fmt.Printf("Shortest path: %d hops\n\n", p.Length())
			fmt.Println(renderPathTree(p))
			fmt.Printf("\nRisk %d/100 (%s), confidence %.2f\n",
				sp.Risk.Score, sp.Risk.Severity, p.Confidence)
		},
	}
}
