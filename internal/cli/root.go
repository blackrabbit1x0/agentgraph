// Package cli implements the agentgraph command-line interface.
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blackrabbit1x0/agentgraph/internal/config"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/spf13/cobra"
)

// DefaultConfigFile is the conventional project configuration filename.
const DefaultConfigFile = "agentgraph.yaml"

var (
	cfgFile   string
	graphFile string
	savePath  string
)

// NewRootCommand builds the agentgraph CLI.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "agentgraph",
		Short: "Attack-path analysis for autonomous AI agents",
		Long: `AgentGraph discovers how AI agents, MCP tools, identities, secrets,
CI/CD and cloud infrastructure connect - and determines what an attacker
could reach if an agent is compromised.`,
		SilenceUsage: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&cfgFile, "config", DefaultConfigFile,
		"path to the agentgraph configuration file")
	pf.StringVar(&graphFile, "graph", "",
		"path to a saved graph snapshot (graph.json) instead of YAML")
	pf.StringVar(&savePath, "save", "",
		"save the analyzed graph to a snapshot file (graph.json)")

	root.AddCommand(
		newInitCommand(),
		newScanCommand(),
		newAgentsCommand(),
		newPathsCommand(),
		newBlastRadiusCommand(),
		newExplainCommand(),
		newRemediateCommand(),
		newChokePointsCommand(),
		newExportCommand(),
		newDiffCommand(),
		newMincutCommand(),
		newPolicyCommand(),
		newServeCommand(),
		newDemoCommand(),
	)
	return root
}

// loadGraph loads the graph the CLI should operate on: a saved snapshot
// when --graph is set, otherwise the YAML configuration. Warnings are
// printed to stderr.
func loadGraph() (*graph.Graph, []string) {
	if graphFile != "" {
		g, err := graph.LoadSnapshotFile(graphFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return g, nil
	}
	g, warnings, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	return g, warnings
}

// resolveConfigPath returns the effective config path, checking the file
// exists where relevant.
func resolveConfigPath() string {
	if cfgFile == "" {
		return DefaultConfigFile
	}
	return cfgFile
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func absPath(path string) string {
	a, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return a
}
