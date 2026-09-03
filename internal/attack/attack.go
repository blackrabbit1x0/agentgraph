// Package attack maps graph relationships to the MITRE ATT&CK framework
// and the experimental AgentGraph agent-attack taxonomy (PRD sections
// 46-47). Per the PRD, not every relationship is forced into ATT&CK; only
// meaningful mappings are made.
package attack

import (
	"sort"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// Technique is one MITRE ATT&CK technique.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AGT is one AgentGraph taxonomy entry (PRD section 47).
type AGT struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// The agent-attack technique taxonomy (experimental, PRD section 47).
var (
	AGT001 = AGT{"AGT-001", "Indirect Prompt Injection"}
	AGT002 = AGT{"AGT-002", "Tool Poisoning"}
	AGT003 = AGT{"AGT-003", "Excessive Tool Permission"}
	AGT004 = AGT{"AGT-004", "Agent Credential Exposure"}
	AGT005 = AGT{"AGT-005", "Cross-Agent Trust Abuse"}
	AGT006 = AGT{"AGT-006", "MCP Trust Exploitation"}
	AGT008 = AGT{"AGT-008", "Agent Identity Escalation"}
	AGT009 = AGT{"AGT-009", "Agent-to-Cloud Pivot"}
	AGT010 = AGT{"AGT-010", "Agent-to-CI/CD Pivot"}
)

// edgeTechniques maps edge types to ATT&CK techniques. Unlisted edge
// types have no meaningful ATT&CK mapping (per PRD guidance).
var edgeTechniques = map[graph.EdgeType][]Technique{
	graph.EdgeCanAssume:       {{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts"}},
	graph.EdgeAuthenticatesAs: {{ID: "T1078", Name: "Valid Accounts"}},
	graph.EdgeContainsSecret:  {{ID: "T1552", Name: "Unsecured Credentials"}},
	graph.EdgeHasSecret:       {{ID: "T1552", Name: "Unsecured Credentials"}},
	graph.EdgeCanExecute:      {{ID: "T1059", Name: "Command and Scripting Interpreter"}},
	graph.EdgeCanAdmin:        {{ID: "T1548", Name: "Abuse Elevation Control Mechanism"}},
	graph.EdgeCanImpersonate:  {{ID: "T1550", Name: "Use Alternate Authentication Material"}},
	graph.EdgeTriggers:        {{ID: "T1072", Name: "Software Deployment Tools"}},
}

// PathAnalysis is the ATT&CK + AGT view of one attack path.
type PathAnalysis struct {
	Techniques []Technique `json:"techniques,omitempty"`
	AGTs       []AGT       `json:"agent_techniques,omitempty"`
}

// AnalyzePath computes the ATT&CK techniques and AGT classifications for
// an attack path.
func AnalyzePath(p *paths.Path) *PathAnalysis {
	nodes := p.Nodes()
	edges := p.Edges()
	a := &PathAnalysis{}

	// ATT&CK: per-edge mapping, plus context-sensitive supply-chain
	// mapping for repository/pipeline writes.
	seen := map[string]bool{}
	addTech := func(t ...Technique) {
		for _, x := range t {
			if !seen[x.ID] {
				seen[x.ID] = true
				a.Techniques = append(a.Techniques, x)
			}
		}
	}
	for i, e := range edges {
		addTech(edgeTechniques[e.Type]...)
		if e.Type == graph.EdgeCanWrite {
			switch nodes[i+1].Type {
			case graph.NodeRepository:
				addTech(Technique{ID: "T1195.002", Name: "Compromise Software Supply Chain"})
			case graph.NodeCIPipeline:
				addTech(Technique{ID: "T1195.002", Name: "Compromise Software Supply Chain"})
			}
		}
	}
	sort.Slice(a.Techniques, func(i, j int) bool { return a.Techniques[i].ID < a.Techniques[j].ID })

	// AGT: structural patterns along the path.
	agtSeen := map[string]bool{}
	addAGT := func(t ...AGT) {
		for _, x := range t {
			if !agtSeen[x.ID] {
				agtSeen[x.ID] = true
				a.AGTs = append(a.AGTs, x)
			}
		}
	}
	for _, n := range nodes {
		switch n.Type {
		case graph.NodeTool:
			addAGT(AGT002, AGT003)
		case graph.NodeMCPServer:
			addAGT(AGT006)
		case graph.NodeSecret:
			addAGT(AGT004)
		case graph.NodeCIPipeline:
			addAGT(AGT010)
		case graph.NodeCloudRole, graph.NodeCloudResource:
			addAGT(AGT009)
		case graph.NodeAIAgent:
			// Another agent in the middle of the chain = cross-agent trust.
			if n.ID != p.Source.ID {
				addAGT(AGT005)
			}
		}
	}
	for _, e := range edges {
		if e.Type == graph.EdgeCanAssume || e.Type == graph.EdgeAuthenticatesAs ||
			e.Type == graph.EdgeCanImpersonate {
			addAGT(AGT008)
			break
		}
	}
	sort.Slice(a.AGTs, func(i, j int) bool { return a.AGTs[i].ID < a.AGTs[j].ID })

	return a
}
