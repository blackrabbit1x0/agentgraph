// Command agentgraph is the AgentGraph CLI: attack-path analysis for
// autonomous AI agents.
package main

import (
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
