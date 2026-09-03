// Package policy implements the rules engine: YAML-defined conditions
// evaluated against the graph, with embedded default rules (PRD section 45).
package policy

import (
	"fmt"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"gopkg.in/yaml.v3"
)

// Rule is a policy definition.
type Rule struct {
	ID       string `yaml:"id" json:"id"`
	Name     string `yaml:"name" json:"name"`
	Severity string `yaml:"severity" json:"severity"`
	// When selects source agents: a node-type filter plus optional
	// provider and metadata match.
	When RuleWhen `yaml:"when" json:"when"`
	// DenyReach forbids the selected agents from reaching nodes matching
	// the target selector.
	DenyReach *Selector `yaml:"deny_reach" json:"deny_reach,omitempty"`
}

// RuleWhen selects the agents a rule applies to.
type RuleWhen struct {
	NodeType    string            `yaml:"node_type" json:"node_type"`
	Provider    string            `yaml:"provider,omitempty" json:"provider,omitempty"`
	HasMetadata map[string]string `yaml:"has_metadata,omitempty" json:"has_metadata,omitempty"`
}

// Selector matches target nodes.
type Selector struct {
	NodeType    string            `yaml:"node_type" json:"node_type"`
	Provider    string            `yaml:"provider,omitempty" json:"provider,omitempty"`
	HasMetadata map[string]string `yaml:"has_metadata,omitempty" json:"has_metadata,omitempty"`
	HasAnyTag   []string          `yaml:"has_any_tag,omitempty" json:"has_any_tag,omitempty"`
	Environment string            `yaml:"environment,omitempty" json:"environment,omitempty"`
	Privilege   string            `yaml:"privilege,omitempty" json:"privilege,omitempty"`
	CrownJewel  *bool             `yaml:"crown_jewel,omitempty" json:"crown_jewel,omitempty"`
}

// Violation is one rule breach.
type Violation struct {
	RuleID        string   `json:"rule_id"`
	RuleName      string   `json:"rule_name"`
	Severity      string   `json:"severity"`
	Agent         string   `json:"agent"`
	Target        string   `json:"target"`
	TargetType    string   `json:"target_type"`
	Path          []string `json:"path"`
	PathEdgeTypes []string `json:"path_edge_types"`
}

// Set is a collection of rules.
type Set struct {
	Rules []Rule `yaml:"rules"`
}

// Parse decodes a YAML rule set.
func Parse(data []byte) (*Set, error) {
	var s Set
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	for _, r := range s.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("policy rule without id")
		}
		switch strings.ToLower(r.Severity) {
		case "critical", "high", "medium", "low", "informational":
		default:
			return nil, fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
		}
	}
	return &s, nil
}

// DefaultRules implements the built-in policy set.
func DefaultRules() *Set {
	return &Set{Rules: []Rule{
		{
			ID:       "AGENT-001",
			Name:     "AI agents must not reach production administrative access",
			Severity: "critical",
			When:     RuleWhen{NodeType: "AI_AGENT"},
			DenyReach: &Selector{
				HasMetadata: map[string]string{"privilege": "admin"},
			},
		},
		{
			ID:       "AGENT-002",
			Name:     "AI agents must not reach production environments",
			Severity: "critical",
			When:     RuleWhen{NodeType: "AI_AGENT"},
			DenyReach: &Selector{
				Environment: "production",
			},
		},
		{
			ID:       "AGENT-003",
			Name:     "AI agents must not reach secrets",
			Severity: "high",
			When:     RuleWhen{NodeType: "AI_AGENT"},
			DenyReach: &Selector{
				NodeType: "SECRET",
			},
		},
	}}
}

// Evaluate checks every rule against the graph and returns violations.
// Internet-exposed agents are checked first so the most serious exposure
// surfaces at the top.
func Evaluate(g *graph.Graph, s *Set, opts paths.Options) ([]*Violation, error) {
	var out []*Violation

	for _, rule := range s.Rules {
		if rule.DenyReach == nil {
			continue
		}

		// Select source agents.
		var agents []*graph.Node
		for _, n := range g.NodesByType(graph.NodeType(strings.ToUpper(strings.TrimSpace(rule.When.NodeType)))) {
			if !matchesWhen(n, rule.When) {
				continue
			}
			agents = append(agents, n)
		}

		for _, a := range agents {
			ps, err := paths.Enumerate(g, a.ID, opts)
			if err != nil {
				return nil, err
			}
			for _, p := range ps {
				if !MatchesSelector(p.Target, rule.DenyReach) {
					continue
				}
				v := &Violation{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   strings.ToUpper(rule.Severity),
					Agent:      a.ID,
					Target:     p.Target.ID,
					TargetType: string(p.Target.Type),
				}
				for _, n := range p.Nodes() {
					v.Path = append(v.Path, n.ID)
				}
				for _, e := range p.Edges() {
					v.PathEdgeTypes = append(v.PathEdgeTypes, string(e.Type))
				}
				out = append(out, v)
			}
		}
	}
	return out, nil
}

// matchesWhen reports whether a node satisfies the rule's source filter.
func matchesWhen(n *graph.Node, w RuleWhen) bool {
	if w.Provider != "" && n.Provider != w.Provider {
		return false
	}
	for k, want := range w.HasMetadata {
		if got, _ := n.Metadata[k].(string); got != want {
			return false
		}
	}
	return true
}

// MatchesSelector reports whether a target node matches the selector.
func MatchesSelector(n *graph.Node, sel *Selector) bool {
	if sel.NodeType != "" && n.Type != graph.NodeType(strings.ToUpper(strings.TrimSpace(sel.NodeType))) {
		return false
	}
	if sel.Provider != "" && n.Provider != sel.Provider {
		return false
	}
	if sel.Environment != "" {
		if got, _ := n.Metadata["environment"].(string); got != sel.Environment {
			return false
		}
	}
	if sel.Privilege != "" {
		if got, _ := n.Metadata["privilege"].(string); !equalFold(got, sel.Privilege) {
			return false
		}
	}
	for k, want := range sel.HasMetadata {
		got, _ := n.Metadata[k].(string)
		if sel.isTagKey(k) {
			// Tag-style keys match any of comma-separated values.
			if !hasTagValue(got, want) {
				return false
			}
			continue
		}
		if got != want && !equalFold(got, want) {
			return false
		}
	}
	if sel.CrownJewel != nil && n.CrownJewel != *sel.CrownJewel {
		return false
	}
	if len(sel.HasAnyTag) > 0 {
		matched := false
		for _, tag := range sel.HasAnyTag {
			if hasTagValue(n.ID, tag) || hasTagValue(n.Name, tag) {
				matched = true
				break
			}
			for _, v := range n.Metadata {
				if s, ok := v.(string); ok && hasTagValue(s, tag) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// isTagKey marks metadata keys where comma-separated matching applies.
func (s *Selector) isTagKey(key string) bool {
	switch strings.ToLower(key) {
	case "tags", "labels":
		return true
	}
	return false
}

// hasTagValue reports whether the comma-separated got contains want.
func hasTagValue(got, want string) bool {
	for _, part := range strings.Split(got, ",") {
		if equalFold(strings.TrimSpace(part), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
