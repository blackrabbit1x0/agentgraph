package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
	"github.com/blackrabbit1x0/agentgraph/internal/svg"
	"github.com/spf13/cobra"
)

// exportPath is the JSON export format (PRD section 61).
type exportPath struct {
	ID         string          `json:"id"`
	Source     string          `json:"source"`
	Target     string          `json:"target"`
	RiskScore  int             `json:"risk_score"`
	Severity   string          `json:"severity"`
	Confidence float64         `json:"confidence"`
	Path       []exportPathHop `json:"path"`
	Factors    []risk.Factor   `json:"factors,omitempty"`
}

type exportPathHop struct {
	Node         string `json:"node"`
	Relationship string `json:"relationship,omitempty"`
}

func newExportCommand() *cobra.Command {
	var outFile string
	var asSVG bool
	var f pathFlags

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export attack paths as JSON, or the graph as SVG",
		Long: `Export attack paths as JSON, or the graph as a shareable SVG image.

With --svg, renders the whole graph as a standalone SVG (agents on the
left, critical targets on the right). When --from is given together with
--svg, that agent's most dangerous path is highlighted.`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			opts := f.options()

			if asSVG {
				exportSVG(g, outFile, f, opts)
				return
			}

			// Always enumerate globally so path IDs match "agentgraph explain".
			ps, _ := paths.EnumerateAll(g, opts)
			if f.from != "" {
				filtered := make([]*paths.Path, 0, len(ps))
				for _, p := range ps {
					if p.Source.ID == f.from {
						filtered = append(filtered, p)
					}
				}
				ps = filtered
			}

			out := make([]exportPath, 0, len(ps))
			for _, p := range ps {
				res := risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence)
				ep := exportPath{
					ID:         p.ID,
					Source:     p.Source.ID,
					Target:     p.Target.ID,
					RiskScore:  res.Score,
					Severity:   res.Severity,
					Confidence: p.Confidence,
					Path: []exportPathHop{
						{Node: p.Source.ID},
					},
				}
				for _, s := range p.Steps {
					ep.Path = append(ep.Path, exportPathHop{
						Node:         s.Node.ID,
						Relationship: string(s.Edge.Type),
					})
				}
				out = append(out, ep)
			}

			data, err := json.MarshalIndent(map[string]any{
				"attack_paths": out,
				"count":        len(out),
			}, "", "  ")
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}

			if outFile == "" {
				fmt.Println(string(data))
				return
			}
			if err := os.WriteFile(outFile, data, 0644); err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			fmt.Printf("Exported %d attack paths to %s\n", len(out), outFile)
		},
	}
	cmd.Flags().StringVar(&outFile, "out", "", "output file (default stdout)")
	cmd.Flags().BoolVar(&asSVG, "svg", false, "export the graph as an SVG image")
	addPathFlags(cmd, &f)
	return cmd
}

// exportSVG renders the graph as SVG, optionally highlighting an agent's
// most dangerous path.
func exportSVG(g *graph.Graph, outFile string, f pathFlags, opts paths.Options) {
	hl := svg.NewHighlight(nil)
	title := "AgentGraph"
	if f.from != "" {
		// Highlight the agent's most dangerous path.
		all, _ := paths.Enumerate(g, f.from, opts)
		var best *paths.Path
		bestScore := -1
		for _, p := range all {
			s := risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence).Score
			if s > bestScore {
				bestScore = s
				best = p
			}
		}
		if best != nil {
			hl = svg.NewHighlight(best)
			title = fmt.Sprintf("AgentGraph: %s (top path risk %d/100)", f.from, bestScore)
		} else {
			title = fmt.Sprintf("AgentGraph: %s (no attack paths)", f.from)
		}
	}

	out := svg.Render(g, title, hl)
	if outFile == "" {
		fmt.Println(out)
		return
	}
	if err := os.WriteFile(outFile, []byte(out), 0644); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("Exported SVG graph to %s\n", outFile)
}
