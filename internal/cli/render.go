package cli

import (
	"fmt"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/blast"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

// renderPathArrow renders a path in PRD arrow notation:
// a --USES--> b --CAN_WRITE--> c
func renderPathArrow(p *paths.Path) string {
	var b strings.Builder
	b.WriteString(p.Source.ID)
	for _, s := range p.Steps {
		fmt.Fprintf(&b, " --%s--> %s", s.Edge.Type, s.Node.ID)
	}
	return b.String()
}

// renderPathTree renders a path in the PRD tree notation:
//
//	source
//	  --USES--> target
//	    --CAN_WRITE--> ...
func renderPathTree(p *paths.Path) string {
	var b strings.Builder
	b.WriteString(p.Source.ID)
	indent := "  "
	for _, s := range p.Steps {
		fmt.Fprintf(&b, "\n%s--%s--> %s", indent, s.Edge.Type, s.Node.ID)
		indent += "  "
	}
	return b.String()
}

// severityTag returns a fixed-width severity label.
func severityTag(sev string) string { return sev }

// printScoredPath prints one scored path in summary form.
func printScoredPath(sp *blast.ScoredPath) {
	p := risk.PathLikelihood(sp.Path.Edges())
	fmt.Printf("%s  %s  risk %3d  conf %.2f  likelihood %.4f (%s)  %d hops\n",
		sp.Path.ID, sp.Risk.Severity, sp.Risk.Score, sp.Path.Confidence, p,
		risk.LikelihoodFor(p), sp.Path.Length())
	fmt.Printf("  %s\n", renderPathArrow(sp.Path))
}

// scorePaths is a small helper for CLI commands.
func scorePaths(ps []*paths.Path) []*blast.ScoredPath {
	out := make([]*blast.ScoredPath, 0, len(ps))
	for _, p := range ps {
		out = append(out, &blast.ScoredPath{
			Path: p,
			Risk: risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence),
		})
	}
	return out
}
