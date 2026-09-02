package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
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
	var f pathFlags

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export attack paths as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			opts := f.options()

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
	addPathFlags(cmd, &f)
	return cmd
}
