package cli

import (
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	"github.com/spf13/cobra"
)

func newRemediateCommand() *cobra.Command {
	var maxDepth int
	var minConf float64

	cmd := &cobra.Command{
		Use:   "remediate <agent>",
		Short: "Recommend the permission removal that eliminates the most attack paths",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			rec, err := remediation.Optimize(g, args[0], paths.Options{
				MaxDepth:      maxDepth,
				MinConfidence: minConf,
			}, 20)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}

			fmt.Println("TOP RECOMMENDATION")
			fmt.Println()
			fmt.Println("Remove relationship:")
			fmt.Printf("  %s --%s--> %s\n", rec.Edge.Source, rec.Edge.Type, rec.Edge.Target)
			fmt.Println()
			fmt.Printf("Attack paths before:      %d\n", rec.PathsBefore)
			fmt.Printf("Attack paths after:       %d\n", rec.PathsAfter)
			fmt.Printf("Critical paths remaining: %d / %d\n", rec.CriticalAfter, rec.CriticalBefore)
			fmt.Printf("High paths remaining:     %d / %d\n", rec.HighAfter, rec.HighBefore)
			fmt.Printf("Risk reduction:           %d%%\n", rec.RiskReductionPct)
		},
	}
	cmd.Flags().IntVar(&maxDepth, "max-depth", paths.DefaultMaxDepth, "maximum path depth (hops)")
	cmd.Flags().Float64Var(&minConf, "min-confidence", 0, "minimum edge confidence (0-1)")
	return cmd
}

func newChokePointsCommand() *cobra.Command {
	var f pathFlags

	cmd := &cobra.Command{
		Use:   "chokepoints",
		Short: "Identify nodes that appear across the most attack paths",
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			opts := f.options()

			var ps []*paths.Path
			if f.from == "" {
				ps, _ = paths.EnumerateAll(g, opts)
			} else {
				ps, _ = paths.Enumerate(g, f.from, opts)
			}
			scored := remediation.ScoreAll(ps)
			if len(scored) == 0 {
				fmt.Println("No attack paths found.")
				return
			}

			cps := remediation.ChokePoints(g, scored)
			if len(cps) == 0 {
				fmt.Println("No choke points (all paths are direct).")
				return
			}

			fmt.Println("TOP ATTACK-PATH CHOKE POINTS")
			fmt.Println()
			limit := len(cps)
			if limit > 10 {
				limit = 10
			}
			for i, cp := range cps[:limit] {
				fmt.Printf("%d. %s (%s)\n", i+1, cp.Node.ID, cp.Node.Type)
				fmt.Printf("   Appears in %d attack paths (%d critical)\n",
					cp.PathCount, cp.CriticalCount)
			}
		},
	}
	addPathFlags(cmd, &f)
	return cmd
}
