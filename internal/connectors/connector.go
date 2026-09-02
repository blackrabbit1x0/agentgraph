// Package connectors defines the discovery interface implemented by every
// AgentGraph integration (PRD section 34).
package connectors

import (
	"context"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// DiscoveryResult is the normalized output of a connector run.
type DiscoveryResult struct {
	Nodes []*graph.Node
	Edges []*graph.Edge
}

// Connector discovers infrastructure relationships from a provider.
// Implementations must be read-only and must never capture secret values.
type Connector interface {
	Name() string
	Discover(ctx context.Context) (*DiscoveryResult, error)
}
