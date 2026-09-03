package api

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

func jsonNewEncoder(w io.Writer) *json.Encoder {
	return json.NewEncoder(w)
}

// blastRadiusJSON is the JSON form of blast.Radius.
type blastRadiusJSON struct {
	Agent             string         `json:"agent"`
	ExposureScore     int            `json:"exposure_score"`
	ExposureRisk      string         `json:"exposure_risk"`
	Direct            map[string]int `json:"direct"`
	Indirect          map[string]int `json:"indirect"`
	ReachableNodes    int            `json:"reachable_nodes"`
	CloudRoles        int            `json:"cloud_roles"`
	Secrets           int            `json:"secrets"`
	Identities        int            `json:"identities"`
	CrownJewels       []string       `json:"crown_jewels"`
	HighestPrivilege  string         `json:"highest_privilege,omitempty"`
	TotalPaths        int            `json:"total_paths"`
	CriticalPaths     int            `json:"critical_paths"`
	HighPaths         int            `json:"high_paths"`
	MostDangerousPath *pathJSON      `json:"most_dangerous_path,omitempty"`
}

// pathJSON is the wire form of a scored path.
type pathJSON struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	RiskScore  int       `json:"risk_score"`
	Severity   string    `json:"severity"`
	Confidence float64   `json:"confidence"`
	Hops       []hopJSON `json:"hops"`
}

type hopJSON struct {
	Node         string `json:"node"`
	NodeType     string `json:"node_type"`
	Relationship string `json:"relationship,omitempty"`
}

func pathToJSON(p *paths.Path) *pathJSON {
	out := &pathJSON{
		ID:         p.ID,
		Source:     p.Source.ID,
		Target:     p.Target.ID,
		Confidence: p.Confidence,
		Hops: []hopJSON{
			{Node: p.Source.ID, NodeType: string(p.Source.Type)},
		},
	}
	for _, s := range p.Steps {
		out.Hops = append(out.Hops, hopJSON{
			Node:         s.Node.ID,
			NodeType:     string(s.Node.Type),
			Relationship: string(s.Edge.Type),
		})
	}
	return out
}

func scoredToJSON(p *paths.Path, res risk.Result) *pathJSON {
	pj := pathToJSON(p)
	pj.RiskScore = res.Score
	pj.Severity = res.Severity
	return pj
}

func containsFoldSimple(s, sub string) bool {
	return sub != "" && strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

var _ = fmt.Sprintf
