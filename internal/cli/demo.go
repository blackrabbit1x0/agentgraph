package cli

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/config"
	"github.com/spf13/cobra"
)

//go:embed demo/agentgraph-demo.yaml
var demoConfig []byte

func newDemoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run AgentGraph against the built-in vulnerable demo environment",
		Long: `Run AgentGraph against the built-in vulnerable demo environment
(PRD sections 49-50): three AI agents share a GitHub MCP that can write to
repositories which trigger production CI.`,
		Run: func(cmd *cobra.Command, args []string) {
			g, warnings, err := config.LoadFromBytes(demoConfig)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "warning: %s\n", w)
			}
			maybeSaveGraph(g)
			printDashboard(g)
			fmt.Println()
			fmt.Println("Try:")
			fmt.Println("  agentgraph demo paths --from finance-agent")
			fmt.Println("  agentgraph demo blast-radius finance-agent")
			fmt.Println("  agentgraph demo explain <path-id>")
		},
	}

	cmd.AddCommand(
		demoSub("paths", newPathsCommand()),
		demoSub("scan", newScanCommand()),
		demoSub("agents", newAgentsCommand()),
		demoSub("blast-radius", newBlastRadiusCommand()),
		demoSub("explain", newExplainCommand()),
		demoSub("remediate", newRemediateCommand()),
		demoSub("chokepoints", newChokePointsCommand()),
		demoSub("export", newExportCommand()),
	)
	return cmd
}

// demoSub clones a command so it can run against the embedded demo
// configuration regardless of the --config flag.
func demoSub(use string, cmd *cobra.Command) *cobra.Command {
	cmd.Use = use
	cmd.RunE = func(c *cobra.Command, args []string) error {
		// Point the config loader at the embedded demo graph.
		dir, err := os.MkdirTemp("", "agentgraph-demo-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		path := dir + "/agentgraph-demo.yaml"
		if err := os.WriteFile(path, demoConfig, 0644); err != nil {
			return err
		}
		cfgFile = path
		c.Run(c, args)
		return nil
	}
	return cmd
}
