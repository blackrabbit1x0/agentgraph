package cli

import (
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/blast"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/spf13/cobra"
)

func newBlastRadiusCommand() *cobra.Command {
	var maxDepth int
	var minConf float64

	cmd := &cobra.Command{
		Use:   "blast-radius <agent>",
		Short: "Analyze what a compromised agent could reach",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			r, err := blast.Analyze(g, args[0], paths.Options{
				MaxDepth:      maxDepth,
				MinConfidence: minConf,
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			printRadius(r)
		},
	}
	cmd.Flags().IntVar(&maxDepth, "max-depth", paths.DefaultMaxDepth, "maximum path depth (hops)")
	cmd.Flags().Float64Var(&minConf, "min-confidence", 0, "minimum edge confidence (0-1)")
	return cmd
}

func printRadius(r *blast.Radius) {
	fmt.Printf("%s\n\n", r.Agent.ID)

	fmt.Printf("Risk                       %s\n", r.ExposureRisk)
	fmt.Printf("Exposure Score             %d\n\n", r.ExposureScore)

	fmt.Println("Direct access")
	fmt.Println("-------------------------------")
	printTypeCounts(r.Direct)
	fmt.Println()

	fmt.Println("Indirect access")
	fmt.Println("-------------------------------")
	printTypeCounts(r.Indirect)
	fmt.Println()

	fmt.Printf("Reachable Nodes            %d\n", r.ReachableNodes)
	fmt.Printf("Cloud Roles                %d\n", r.CloudRoles)
	fmt.Printf("Secrets                    %d\n", r.ReachableSecrets)
	fmt.Printf("Identities                 %d\n", r.ReachableIdentities)
	if r.HighestPrivilege != "" {
		fmt.Printf("Highest Privilege          %s\n", r.HighestPrivilege)
	}
	fmt.Println()

	fmt.Printf("Total Paths                %d\n", r.TotalPaths)
	fmt.Printf("Critical Paths             %d\n", r.CriticalPaths)
	fmt.Printf("High Paths                 %d\n", r.HighPaths)
	fmt.Println()

	if len(r.ReachableCrownJewels) > 0 {
		fmt.Printf("Crown Jewels at Risk       %s\n", joinIDs(r.ReachableCrownJewels))
		fmt.Println()
	}

	if r.MostDangerous != nil {
		fmt.Println("Most Dangerous Path")
		fmt.Printf("%s  risk %d/100  confidence %.2f\n",
			r.MostDangerous.Path.ID, r.MostDangerous.Risk.Score, r.MostDangerous.Path.Confidence)
		fmt.Println(renderPathArrow(r.MostDangerous.Path))
	}
}

func printTypeCounts(counts map[graph.NodeType]int) {
	if len(counts) == 0 {
		fmt.Println("(none)")
		return
	}
	// Deterministic order by count desc, then type name.
	type kv struct {
		t graph.NodeType
		n int
	}
	var list []kv
	for t, n := range counts {
		list = append(list, kv{t, n})
	}
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].n > list[i].n || (list[j].n == list[i].n && list[j].t < list[i].t) {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	for _, e := range list {
		fmt.Printf("%-26s %d\n", e.t, e.n)
	}
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ", "
		}
		out += id
	}
	return out
}
