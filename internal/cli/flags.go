package cli

import (
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/spf13/cobra"
)

// pathFlags carries the shared path-filtering CLI flags.
type pathFlags struct {
	from        string
	to          string
	crownJewels bool
	maxDepth    int
	minConf     float64
}

// options builds path enumeration options from the flags.
func (f *pathFlags) options() paths.Options {
	return paths.Options{
		MaxDepth:        f.maxDepth,
		MinConfidence:   f.minConf,
		TargetSubstring: f.to,
		CrownJewelsOnly: f.crownJewels,
	}
}

// addPathFlags registers the shared flags on a command.
func addPathFlags(cmd *cobra.Command, f *pathFlags) {
	cmd.Flags().StringVar(&f.from, "from", "", "source agent ID")
	cmd.Flags().StringVar(&f.to, "to", "", "target node ID or name substring")
	cmd.Flags().BoolVar(&f.crownJewels, "crown-jewels", false, "only paths ending at crown jewels")
	cmd.Flags().IntVar(&f.maxDepth, "max-depth", paths.DefaultMaxDepth, "maximum path depth (hops)")
	cmd.Flags().Float64Var(&f.minConf, "min-confidence", 0, "minimum edge confidence (0-1)")
}
