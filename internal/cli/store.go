package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/store"
	"github.com/spf13/cobra"
)

// storeFlags holds the shared persistence flags.
var (
	storeBackend string // "", "memory", "neo4j"
	storeKey     string
)

// addStoreFlags registers persistence flags on a command.
func addStoreFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&storeBackend, "store", "",
		"persist snapshots to a graph store: neo4j (default: local files via --save)")
	cmd.Flags().StringVar(&storeKey, "store-key", "default",
		"snapshot key in the graph store")
}

// openStore builds the configured store. Nil means "no persistence" (the
// default file-based --save flow applies instead).
func openStore() store.Store {
	if storeBackend == "" {
		return nil
	}
	switch storeBackend {
	case "memory":
		return store.NewMemoryStore()
	case "neo4j":
		uri := os.Getenv("NEO4J_URI")
		if uri == "" {
			uri = "neo4j://localhost:7687"
		}
		user := os.Getenv("NEO4J_USER")
		if user == "" {
			user = "neo4j"
		}
		pass := os.Getenv("NEO4J_PASSWORD")
		s, err := store.NewNeo4jStore(context.Background(), store.Neo4jConfig{
			URI: uri, Username: user, Password: pass,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return s
	default:
		fmt.Fprintf(os.Stderr, "error: unknown store %q (available: neo4j)\n", storeBackend)
		os.Exit(1)
		return nil
	}
}

// persistGraph saves the graph to the configured store, if any.
func persistGraph(g *graph.Graph) {
	s := openStore()
	if s == nil {
		return
	}
	defer s.Close()
	if err := s.Save(context.Background(), storeKey, g); err != nil {
		fmt.Fprintf(os.Stderr, "error: store save: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "saved snapshot %q to %s store\n", storeKey, s.Name())
}

// loadFromStore reads a graph snapshot from the configured store.
// Returns nil when no store is configured. Falls back to the standard
// graph loading when the key is not found.
func loadFromStore() *graph.Graph {
	s := openStore()
	if s == nil {
		return nil
	}
	defer s.Close()
	g, err := s.Load(context.Background(), storeKey)
	if err != nil {
		if store.IsNotFound(err) {
			fmt.Fprintf(os.Stderr, "snapshot %q not found in %s store; falling back\n", storeKey, s.Name())
			return nil
		}
		fmt.Fprintf(os.Stderr, "error: store load: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded snapshot %q from %s store\n", storeKey, s.Name())
	return g
}
