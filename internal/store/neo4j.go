//go:build !nolive

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Neo4jStore persists graph snapshots in a Neo4j database (PRD section
// 30). Each snapshot is stored as a labeled subgraph:
//
//	(:AgentGraphSnapshot {key: <key>})-[:CONTAINS]->(:Node {id, ...})
//	(:Node)-[:Edge {type, confidence, risk, ...}]->(:Node)
//
// Save replaces any existing snapshot with the same key in one
// transaction. The JSON snapshot blob is also kept on the snapshot node
// so Load can reconstruct exact metadata cheaply.
type Neo4jStore struct {
	driver neo4j.DriverWithContext
}

// Neo4jConfig configures the connection.
type Neo4jConfig struct {
	// URI, e.g. neo4j://localhost:7687 or neo4j+s://host.
	URI string
	// Username (default "neo4j").
	Username string
	// Password (required).
	Password string
	// Database name (default "neo4j").
	Database string
}

// NewNeo4jStore connects to a Neo4j server and verifies connectivity.
func NewNeo4jStore(ctx context.Context, cfg Neo4jConfig) (*Neo4jStore, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("neo4j store: URI is required (e.g. neo4j://localhost:7687)")
	}
	if cfg.Username == "" {
		cfg.Username = "neo4j"
	}
	if cfg.Database == "" {
		cfg.Database = "neo4j"
	}
	driver, err := neo4j.NewDriverWithContext(
		cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("neo4j store: connect: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("neo4j store: verify connectivity: %w", err)
	}
	return &Neo4jStore{driver: driver}, nil
}

// Name implements Store.
func (s *Neo4jStore) Name() string { return "neo4j" }

// Save implements Store.
func (s *Neo4jStore) Save(ctx context.Context, key string, g *graph.Graph) error {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	blob, err := json.Marshal(g.Snapshot())
	if err != nil {
		return fmt.Errorf("neo4j store: marshal snapshot: %w", err)
	}

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Detach-delete any previous version of this snapshot.
		if _, err := tx.Run(ctx,
			`MATCH (snap:AgentGraphSnapshot {key: $key})
			 OPTIONAL MATCH (snap)-[:CONTAINS]->(n:AgentGraphNode)
			 DETACH DELETE n
			 DELETE snap`, map[string]any{"key": key}); err != nil {
			return nil, err
		}
		// Create the snapshot node with the full JSON blob.
		if _, err := tx.Run(ctx,
			`CREATE (snap:AgentGraphSnapshot {key: $key, savedAt: datetime(), blob: $blob})`,
			map[string]any{"key": key, "blob": string(blob)}); err != nil {
			return nil, err
		}
		// Materialize nodes and edges for Cypher queries.
		if _, err := tx.Run(ctx, `
			UNWIND $nodes AS n
			CREATE (node:AgentGraphNode {id: n.id, name: n.name, type: n.type,
				provider: n.provider, criticality: coalesce(n.criticality, 0),
				crownJewel: coalesce(n.crown_jewel, false), snapKey: $key})
			WITH node, n
			MATCH (snap:AgentGraphSnapshot {key: $key})
			CREATE (snap)-[:CONTAINS]->(node)`,
			map[string]any{"nodes": nodesForCypher(g), "key": key}); err != nil {
			return nil, err
		}
		if _, err := tx.Run(ctx, `
			UNWIND $edges AS e
			MATCH (a:AgentGraphNode {id: e.source, snapKey: $key})
			MATCH (b:AgentGraphNode {id: e.target, snapKey: $key})
			CREATE (a)-[:EDGE {type: e.type, confidence: e.confidence,
				risk: coalesce(e.risk, 0), snapKey: $key}]->(b)`,
			map[string]any{"edges": edgesForCypher(g), "key": key}); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("neo4j store: save %q: %w", key, err)
	}
	return nil
}

// Load implements Store.
func (s *Neo4jStore) Load(ctx context.Context, key string) (*graph.Graph, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	rec, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx,
			`MATCH (snap:AgentGraphSnapshot {key: $key}) RETURN snap.blob AS blob`,
			map[string]any{"key": key})
		if err != nil {
			return nil, err
		}
		if record, err := result.Single(ctx); err == nil {
			return record.Values[0], nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("neo4j store: load %q: %w", key, err)
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	blob, ok := rec.(string)
	if !ok {
		return nil, fmt.Errorf("neo4j store: snapshot %q has no blob", key)
	}
	var snap graph.Snapshot
	if err := json.Unmarshal([]byte(blob), &snap); err != nil {
		return nil, fmt.Errorf("neo4j store: parse snapshot: %w", err)
	}
	return graph.FromSnapshot(&snap)
}

// Close implements Store.
func (s *Neo4jStore) Close() error {
	return s.driver.Close(context.Background())
}

// nodesForCypher converts graph nodes into parameter maps.
func nodesForCypher(g *graph.Graph) []map[string]any {
	nodes := g.Nodes()
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, map[string]any{
			"id":          n.ID,
			"name":        n.Name,
			"type":        string(n.Type),
			"provider":    n.Provider,
			"criticality": n.Criticality,
			"crown_jewel": n.CrownJewel,
		})
	}
	return out
}

// edgesForCypher converts graph edges into parameter maps.
func edgesForCypher(g *graph.Graph) []map[string]any {
	edges := g.Edges()
	out := make([]map[string]any, 0, len(edges))
	for _, e := range edges {
		out = append(out, map[string]any{
			"source":     e.Source,
			"target":     e.Target,
			"type":       string(e.Type),
			"confidence": e.Confidence,
			"risk":       e.Risk,
		})
	}
	return out
}
