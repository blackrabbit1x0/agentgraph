package cli

import (
	"fmt"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
	"github.com/spf13/cobra"
)

func newExplainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <path-id>",
		Short: "Explain why an attack path exists",
		Long: `Explain why an attack path exists.

Path IDs (PATH-0001 ...) are stable for a given configuration and default
enumeration settings; run "agentgraph paths" to list them.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			all, _ := paths.EnumerateAll(g, paths.Options{})

			var target *paths.Path
			for _, p := range all {
				if strings.EqualFold(p.ID, args[0]) {
					target = p
					break
				}
			}
			if target == nil {
				fmt.Printf("error: path %s not found (run \"agentgraph paths\" to list IDs)\n", args[0])
				return
			}

			res := risk.ScorePath(target.Nodes(), target.Edges(), target.Confidence)

			fmt.Printf("%s exists because:\n\n", strings.ToUpper(target.ID))
			nodes := target.Nodes()
			edges := target.Edges()
			for i, e := range edges {
				fmt.Printf("%d. %s can reach %s via %s.\n", i+1, e.Source, e.Target, e.Type)
			}
			_ = nodes
			fmt.Printf("\nTherefore:\n\n")
			fmt.Printf("Compromise of %s may create a path to %s.\n",
				target.Source.ID, target.Target.ID)

			fmt.Printf("\nRisk: %d/100 (%s)\n", res.Score, res.Severity)
			fmt.Printf("Confidence: %.2f\n\n", res.Confidence)
			fmt.Println("Score breakdown:")
			risk.SortFactors(res.Factors)
			for _, f := range res.Factors {
				fmt.Printf("  %+4d  %-22s %s\n", f.Delta, f.Name, f.Reason)
			}
		},
	}
}
