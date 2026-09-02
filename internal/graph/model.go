// Package graph implements the AgentGraph normalized node and edge models
// and the in-memory graph store.
package graph

import (
	"fmt"
	"time"
)

// NodeType enumerates all node categories modeled by AgentGraph.
type NodeType string

const (
	NodeAIAgent       NodeType = "AI_AGENT"
	NodeMCPServer     NodeType = "MCP_SERVER"
	NodeTool          NodeType = "TOOL"
	NodeIdentity      NodeType = "IDENTITY"
	NodeSecret        NodeType = "SECRET"
	NodeRepository    NodeType = "REPOSITORY"
	NodeCIPipeline    NodeType = "CI_PIPELINE"
	NodeCloudRole     NodeType = "CLOUD_ROLE"
	NodeCloudResource NodeType = "CLOUD_RESOURCE"
	NodeDatabase      NodeType = "DATABASE"
	NodeHost          NodeType = "HOST"
	NodeAPI           NodeType = "API"
	NodeDataset       NodeType = "DATASET"
)

// AllNodeTypes is the canonical ordered list of node types.
var AllNodeTypes = []NodeType{
	NodeAIAgent, NodeMCPServer, NodeTool, NodeIdentity, NodeSecret,
	NodeRepository, NodeCIPipeline, NodeCloudRole, NodeCloudResource,
	NodeDatabase, NodeHost, NodeAPI, NodeDataset,
}

// IsValidNodeType reports whether t is a known node type.
func IsValidNodeType(t NodeType) bool {
	for _, n := range AllNodeTypes {
		if n == t {
			return true
		}
	}
	return false
}

// EdgeType enumerates relationship categories between nodes.
type EdgeType string

const (
	EdgeUses            EdgeType = "USES"
	EdgeCanCall         EdgeType = "CAN_CALL"
	EdgeHasPermission   EdgeType = "HAS_PERMISSION"
	EdgeCanRead         EdgeType = "CAN_READ"
	EdgeCanWrite        EdgeType = "CAN_WRITE"
	EdgeCanExecute      EdgeType = "CAN_EXECUTE"
	EdgeCanModify       EdgeType = "CAN_MODIFY"
	EdgeCanAssume       EdgeType = "CAN_ASSUME"
	EdgeCanImpersonate  EdgeType = "CAN_IMPERSONATE"
	EdgeAuthenticatesAs EdgeType = "AUTHENTICATES_AS"
	EdgeHasSecret       EdgeType = "HAS_SECRET"
	EdgeContainsSecret  EdgeType = "CONTAINS_SECRET"
	EdgeCanAccess       EdgeType = "CAN_ACCESS"
	EdgeCanAdmin        EdgeType = "CAN_ADMIN"
	EdgeDeploysTo       EdgeType = "DEPLOYS_TO"
	EdgeTriggers        EdgeType = "TRIGGERS"
	EdgeOwns            EdgeType = "OWNS"
	EdgeMemberOf        EdgeType = "MEMBER_OF"
	EdgeConnectedTo     EdgeType = "CONNECTED_TO"
	EdgeTrusts          EdgeType = "TRUSTS"
	EdgeExposedTo       EdgeType = "EXPOSED_TO"
)

// AllEdgeTypes is the canonical list of edge types.
var AllEdgeTypes = []EdgeType{
	EdgeUses, EdgeCanCall, EdgeHasPermission, EdgeCanRead, EdgeCanWrite,
	EdgeCanExecute, EdgeCanModify, EdgeCanAssume, EdgeCanImpersonate,
	EdgeAuthenticatesAs, EdgeHasSecret, EdgeContainsSecret, EdgeCanAccess,
	EdgeCanAdmin, EdgeDeploysTo, EdgeTriggers, EdgeOwns, EdgeMemberOf,
	EdgeConnectedTo, EdgeTrusts, EdgeExposedTo,
}

// IsValidEdgeType reports whether t is a known edge type.
func IsValidEdgeType(t EdgeType) bool {
	for _, e := range AllEdgeTypes {
		if e == t {
			return true
		}
	}
	return false
}

// DefaultEdgeRisk maps edge types to intrinsic risk (0-100) when an edge
// does not carry an explicit risk. Dangerous capabilities are rated
// according to the PRD's dangerous-capability table.
var DefaultEdgeRisk = map[EdgeType]int{
	EdgeCanAdmin:        95,
	EdgeCanExecute:      90,
	EdgeCanImpersonate:  90,
	EdgeCanAssume:       85,
	EdgeContainsSecret:  80,
	EdgeHasSecret:       80,
	EdgeAuthenticatesAs: 75,
	EdgeCanModify:       75,
	EdgeCanWrite:        70,
	EdgeTriggers:        60,
	EdgeCanAccess:       55,
	EdgeDeploysTo:       50,
	EdgeCanRead:         40,
	EdgeHasPermission:   35,
	EdgeUses:            30,
	EdgeCanCall:         30,
	EdgeOwns:            30,
	EdgeMemberOf:        30,
	EdgeConnectedTo:     25,
	EdgeTrusts:          45,
	EdgeExposedTo:       50,
}

// Provenance records where a relationship was observed.
type Provenance struct {
	Connector    string    `json:"connector,omitempty" yaml:"connector,omitempty"`
	ObservedAt   time.Time `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	SourceObject string    `json:"source_object,omitempty" yaml:"source_object,omitempty"`
}

// Node is the normalized graph node (PRD section 35).
type Node struct {
	ID          string         `json:"id" yaml:"id"`
	Type        NodeType       `json:"type" yaml:"type"`
	Name        string         `json:"name" yaml:"name"`
	Provider    string         `json:"provider,omitempty" yaml:"provider,omitempty"`
	Criticality int            `json:"criticality,omitempty" yaml:"criticality,omitempty"`
	CrownJewel  bool           `json:"crown_jewel,omitempty" yaml:"crown_jewel,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Edge is the normalized graph edge (PRD section 36) with provenance
// (section 41) and freshness fields (section 42).
type Edge struct {
	Source       string         `json:"source" yaml:"source"`
	Target       string         `json:"target" yaml:"target"`
	Type         EdgeType       `json:"type" yaml:"type"`
	Confidence   float64        `json:"confidence" yaml:"confidence"`
	Risk         int            `json:"risk,omitempty" yaml:"risk,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Provenance   Provenance     `json:"provenance,omitempty" yaml:"provenance,omitempty"`
	FirstSeen    time.Time      `json:"first_seen,omitempty" yaml:"first_seen,omitempty"`
	LastSeen     time.Time      `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
	LastVerified time.Time      `json:"last_verified,omitempty" yaml:"last_verified,omitempty"`
}

// Validate checks node invariants.
func (n *Node) Validate() error {
	if n.ID == "" {
		return fmt.Errorf("node id must not be empty")
	}
	if !IsValidNodeType(n.Type) {
		return fmt.Errorf("node %q: unknown type %q", n.ID, n.Type)
	}
	if n.Criticality < 0 || n.Criticality > 100 {
		return fmt.Errorf("node %q: criticality must be 0-100", n.ID)
	}
	return nil
}

// EffectiveRisk returns the edge risk, falling back to the intrinsic
// default risk of its type.
func (e *Edge) EffectiveRisk() int {
	if e.Risk > 0 {
		return e.Risk
	}
	if r, ok := DefaultEdgeRisk[e.Type]; ok {
		return r
	}
	return 30
}

// Validate checks edge invariants.
func (e *Edge) Validate() error {
	if e.Source == "" || e.Target == "" {
		return fmt.Errorf("edge %q -> %q: source and target must not be empty", e.Source, e.Target)
	}
	if e.Source == e.Target {
		return fmt.Errorf("edge %q: self-loops are not allowed", e.Source)
	}
	if !IsValidEdgeType(e.Type) {
		return fmt.Errorf("edge %s -> %s: unknown type %q", e.Source, e.Target, e.Type)
	}
	if e.Confidence <= 0 || e.Confidence > 1 {
		return fmt.Errorf("edge %s -> %s: confidence must be in (0,1]", e.Source, e.Target)
	}
	if e.Risk < 0 || e.Risk > 100 {
		return fmt.Errorf("edge %s -> %s: risk must be 0-100", e.Source, e.Target)
	}
	return nil
}

// Privilege ranks for identity and role nodes.
var privilegeRank = map[string]int{
	"none":  0,
	"read":  1,
	"write": 2,
	"admin": 3,
}

// PrivilegeRank returns an ordered rank for a privilege level string.
func PrivilegeRank(level string) int {
	return privilegeRank[normalizePrivilege(level)]
}

func normalizePrivilege(level string) string {
	switch string(level) {
	case "":
		return "none"
	default:
		s := []rune(level)
		for i := range s {
			if s[i] >= 'A' && s[i] <= 'Z' {
				s[i] += 'a' - 'A'
			}
		}
		return string(s)
	}
}
