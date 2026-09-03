package cli

import (
	"fmt"

	"github.com/blackrabbit1x0/agentgraph/internal/diff"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/spf13/cobra"
)

func newDiffCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <snapshot-a> <snapshot-b>",
		Short: "Compare two graph snapshots: new and removed attack paths",
		Long: `Compare two graph snapshots (files saved with --save).

Reports added/removed nodes, edges, and - most importantly - attack paths
that appeared or disappeared, with attribution of which new relationship
introduced each path.

Example:
  agentgraph scan --save snapshot-old.json
  # ... infrastructure changes ...
  agentgraph scan --save snapshot-new.json
  agentgraph diff snapshot-old.json snapshot-new.json`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			oldG, err := graph.LoadSnapshotFile(args[0])
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			newG, err := graph.LoadSnapshotFile(args[1])
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}

			report, err := diff.Compute(oldG, newG)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			printDiff(report)
		},
	}
	return cmd
}

func printDiff(r *diff.Report) {
	if r.IsEmpty() {
		fmt.Println("Snapshots are graph-identical: no changes.")
		return
	}

	fmt.Println("SNAPSHOT DIFF")
	fmt.Println()

	// Structural summary.
	fmt.Printf("Nodes           %+d (%d added, %d removed)\n",
		len(r.AddedNodes)-len(r.RemovedNodes), len(r.AddedNodes), len(r.RemovedNodes))
	fmt.Printf("Relationships   %+d (%d added, %d removed)\n",
		len(r.AddedEdges)-len(r.RemovedEdges), len(r.AddedEdges), len(r.RemovedEdges))
	fmt.Printf("Attack paths    %+d (%d new, %d gone)\n",
		len(r.NewPaths)-len(r.GonePaths), len(r.NewPaths), len(r.GonePaths))
	fmt.Println()

	limit := 10

	// New attack paths with attribution.
	if len(r.NewPaths) > 0 {
		fmt.Println("NEW ATTACK PATHS")
		fmt.Println()
		n := len(r.NewPaths)
		if n > limit {
			n = limit
		}
		for _, p := range r.NewPaths[:n] {
			fmt.Printf("  %s\n", p.String())
			if attr := r.Attribution(p); len(attr) > 0 {
				e := attr[0]
				fmt.Printf("    introduced by: %s --%s--> %s", e.Source, e.Type, e.Target)
				if len(attr) > 1 {
					fmt.Printf(" (+%d more)", len(attr)-1)
				}
				fmt.Println()
			}
			fmt.Println()
		}
		if len(r.NewPaths) > limit {
			fmt.Printf("  ... and %d more\n\n", len(r.NewPaths)-limit)
		}
	}

	// Gone attack paths.
	if len(r.GonePaths) > 0 {
		fmt.Println("REMOVED ATTACK PATHS")
		fmt.Println()
		n := len(r.GonePaths)
		if n > limit {
			n = limit
		}
		for _, p := range r.GonePaths[:n] {
			fmt.Printf("  %s\n\n", p.String())
		}
		if len(r.GonePaths) > limit {
			fmt.Printf("  ... and %d more\n\n", len(r.GonePaths)-limit)
		}
	}

	// Added relationships.
	if len(r.AddedEdges) > 0 {
		fmt.Println("NEW RELATIONSHIPS")
		fmt.Println()
		n := len(r.AddedEdges)
		if n > limit {
			n = limit
		}
		for _, e := range r.AddedEdges[:n] {
			fmt.Printf("  %s --%s--> %s\n", e.Source, e.Type, e.Target)
		}
		if len(r.AddedEdges) > limit {
			fmt.Printf("  ... and %d more\n", len(r.AddedEdges)-limit)
		}
		fmt.Println()
	}

	// Removed relationships.
	if len(r.RemovedEdges) > 0 {
		fmt.Println("REMOVED RELATIONSHIPS")
		fmt.Println()
		n := len(r.RemovedEdges)
		if n > limit {
			n = limit
		}
		for _, e := range r.RemovedEdges[:n] {
			fmt.Printf("  %s --%s--> %s\n", e.Source, e.Type, e.Target)
		}
		if len(r.RemovedEdges) > limit {
			fmt.Printf("  ... and %d more\n", len(r.RemovedEdges)-limit)
		}
		fmt.Println()
	}

	// Added / removed nodes.
	if len(r.AddedNodes) > 0 {
		fmt.Println("NEW NODES")
		n := len(r.AddedNodes)
		if n > limit {
			n = limit
		}
		for _, node := range r.AddedNodes[:n] {
			fmt.Printf("  %s (%s)\n", node.ID, node.Type)
		}
		if len(r.AddedNodes) > limit {
			fmt.Printf("  ... and %d more\n", len(r.AddedNodes)-limit)
		}
		fmt.Println()
	}
	if len(r.RemovedNodes) > 0 {
		fmt.Println("REMOVED NODES")
		n := len(r.RemovedNodes)
		if n > limit {
			n = limit
		}
		for _, node := range r.RemovedNodes[:n] {
			fmt.Printf("  %s (%s)\n", node.ID, node.Type)
		}
		if len(r.RemovedNodes) > limit {
			fmt.Printf("  ... and %d more\n", len(r.RemovedNodes)-limit)
		}
		fmt.Println()
	}
}
