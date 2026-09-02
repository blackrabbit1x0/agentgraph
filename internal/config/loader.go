// Package config implements the static configuration connector: importing
// a manually defined architecture from YAML into the graph (PRD section 21).
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"gopkg.in/yaml.v3"
)

// NodeDef is a node definition inside a typed section or the generic
// nodes section.
type NodeDef struct {
	ID          string         `yaml:"id"`
	Name        string         `yaml:"name"`
	Provider    string         `yaml:"provider"`
	Criticality int            `yaml:"criticality"`
	CrownJewel  bool           `yaml:"crown_jewel"`
	Metadata    map[string]any `yaml:"metadata"`

	// Type is only used in the generic nodes section.
	Type string `yaml:"type"`
}

// EdgeDef is a relationship definition.
type EdgeDef struct {
	Source       string         `yaml:"source"`
	Target       string         `yaml:"target"`
	Type         string         `yaml:"type"`
	Confidence   float64        `yaml:"confidence"`
	Risk         int            `yaml:"risk"`
	Metadata     map[string]any `yaml:"metadata"`
	Connector    string         `yaml:"connector"`
	SourceObject string         `yaml:"source_object"`
}

// Config is the full agentgraph.yaml document.
type Config struct {
	Agents         []NodeDef `yaml:"agents"`
	MCPServers     []NodeDef `yaml:"mcp_servers"`
	Tools          []NodeDef `yaml:"tools"`
	Identities     []NodeDef `yaml:"identities"`
	Secrets        []NodeDef `yaml:"secrets"`
	Repositories   []NodeDef `yaml:"repositories"`
	CIPipelines    []NodeDef `yaml:"ci_pipelines"`
	CloudRoles     []NodeDef `yaml:"cloud_roles"`
	CloudResources []NodeDef `yaml:"cloud_resources"`
	Databases      []NodeDef `yaml:"databases"`
	Hosts          []NodeDef `yaml:"hosts"`
	APIs           []NodeDef `yaml:"apis"`
	Datasets       []NodeDef `yaml:"datasets"`

	// Nodes is a generic section where each entry carries an explicit type.
	Nodes []NodeDef `yaml:"nodes"`

	CrownJewels   []string  `yaml:"crown_jewels"`
	Relationships []EdgeDef `yaml:"relationships"`
	Edges         []EdgeDef `yaml:"edges"`
}

// forbiddenSecretFields must never be stored on SECRET nodes.
var forbiddenSecretFields = []string{
	"value", "secret", "secret_value", "plaintext", "token", "password",
	"api_key", "access_key", "private_key", "credential",
}

// Load reads and validates a configuration file, returning the built graph.
// Any secret material found in the configuration is redacted and reported
// in the returned warnings.
func Load(path string) (*graph.Graph, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses and validates configuration data into a graph.
func LoadFromBytes(data []byte) (*graph.Graph, []string, error) {
	cfg, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return Build(cfg)
}

// Parse parses configuration data without building a graph. Use with
// Assemble to merge configuration into a larger graph with connectors.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Build constructs a graph from a parsed configuration. Crown jewels must
// reference nodes declared within this configuration.
func Build(cfg *Config) (*graph.Graph, []string, error) {
	asm := graph.NewAssembler()
	var warnings []string
	if err := cfg.feedAssembler(asm, &warnings); err != nil {
		return nil, nil, err
	}
	g, err := asm.Build()
	if err != nil {
		return nil, nil, err
	}
	for _, id := range cfg.CrownJewels {
		n, ok := g.Node(id)
		if !ok {
			return nil, nil, fmt.Errorf("crown jewel %q is not a known node", id)
		}
		n.CrownJewel = true
	}
	return g, warnings, nil
}

// feedAssembler adds all config nodes and relationships to the assembler
// without applying crown-jewel flags, so connector discoveries can be
// merged before flags are resolved.
func (c *Config) feedAssembler(asm *graph.Assembler, warnings *[]string) error {
	sections := []struct {
		defs     []NodeDef
		nodeType graph.NodeType
	}{
		{c.Agents, graph.NodeAIAgent},
		{c.MCPServers, graph.NodeMCPServer},
		{c.Tools, graph.NodeTool},
		{c.Identities, graph.NodeIdentity},
		{c.Secrets, graph.NodeSecret},
		{c.Repositories, graph.NodeRepository},
		{c.CIPipelines, graph.NodeCIPipeline},
		{c.CloudRoles, graph.NodeCloudRole},
		{c.CloudResources, graph.NodeCloudResource},
		{c.Databases, graph.NodeDatabase},
		{c.Hosts, graph.NodeHost},
		{c.APIs, graph.NodeAPI},
		{c.Datasets, graph.NodeDataset},
	}

	for _, sec := range sections {
		for _, def := range sec.defs {
			if err := addNode(asm, def, sec.nodeType, warnings); err != nil {
				return err
			}
		}
	}

	for _, def := range c.Nodes {
		if def.Type == "" {
			return fmt.Errorf("node %q in nodes section is missing a type", def.ID)
		}
		t := graph.NodeType(strings.ToUpper(def.Type))
		if err := addNode(asm, def, t, warnings); err != nil {
			return err
		}
	}

	edges := c.Relationships
	if len(edges) == 0 {
		edges = c.Edges
	}
	for _, ed := range edges {
		e := &graph.Edge{
			Source:     ed.Source,
			Target:     ed.Target,
			Confidence: ed.Confidence,
			Risk:       ed.Risk,
			Metadata:   ed.Metadata,
			Provenance: graph.Provenance{
				Connector:    ed.Connector,
				SourceObject: ed.SourceObject,
				ObservedAt:   time.Now().UTC(),
			},
		}
		if ed.Type == "" {
			return fmt.Errorf("relationship %s -> %s is missing a type", ed.Source, ed.Target)
		}
		e.Type = graph.EdgeType(strings.ToUpper(ed.Type))
		if e.Confidence == 0 {
			e.Confidence = 1.0
		}
		asm.AddEdge(e)
	}
	return nil
}

// Assemble feeds the parsed configuration into an external assembler so
// connector discoveries can be merged into the same graph. Crown-jewel IDs
// are returned for the caller to apply once the merged graph is built,
// because they may reference connector-discovered nodes.
func (c *Config) Assemble(asm *graph.Assembler) ([]string, []string, error) {
	var warnings []string
	if err := c.feedAssembler(asm, &warnings); err != nil {
		return nil, nil, err
	}
	return c.CrownJewels, warnings, nil
}

func addNode(asm *graph.Assembler, def NodeDef, t graph.NodeType, warnings *[]string) error {
	if def.ID == "" {
		return fmt.Errorf("%s section contains a node without an id", t)
	}
	meta := def.Metadata
	if t == graph.NodeSecret {
		var cleaned map[string]any
		for k, v := range meta {
			if isForbiddenSecretField(k) {
				*warnings = append(*warnings,
					fmt.Sprintf("redacted forbidden field %q on secret node %q (secret values must never be stored)", k, def.ID))
				continue
			}
			if cleaned == nil {
				cleaned = map[string]any{}
			}
			cleaned[k] = v
		}
		meta = cleaned
	}
	n := &graph.Node{
		ID:          def.ID,
		Type:        t,
		Name:        def.Name,
		Provider:    def.Provider,
		Criticality: def.Criticality,
		CrownJewel:  def.CrownJewel,
		Metadata:    meta,
	}
	if n.Name == "" {
		n.Name = def.ID
	}
	if err := asm.AddNode(n); err != nil {
		return fmt.Errorf("%s node: %w", t, err)
	}
	return nil
}

func isForbiddenSecretField(key string) bool {
	k := strings.ToLower(key)
	for _, f := range forbiddenSecretFields {
		if k == f {
			return true
		}
	}
	return false
}
