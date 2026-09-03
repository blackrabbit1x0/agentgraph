// Package api implements the AgentGraph REST API and web dashboard
// (PRD sections 60 and 29).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blackrabbit1x0/agentgraph/internal/blast"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

// Server serves the REST API and the embedded dashboard.
type Server struct {
	graph *graph.Graph
	mux   *http.ServeMux
	// hub is optional; set when runtime detection is enabled.
	hub *AlertHub
}

// NewServer builds the server for a graph.
func NewServer(g *graph.Graph) *Server {
	return NewServerWithAlerts(g, nil)
}

// NewServerWithAlerts builds the server with a runtime-detection alert
// hub (enables the /api/v1/alerts endpoints).
func NewServerWithAlerts(g *graph.Graph, hub *AlertHub) *Server {
	s := &Server{graph: g, mux: http.NewServeMux(), hub: hub}
	s.routes()
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/graph", s.handleGraph)
	s.mux.HandleFunc("GET /api/v1/agents", s.handleAgents)
	s.mux.HandleFunc("GET /api/v1/agents/{id}", s.handleAgent)
	s.mux.HandleFunc("GET /api/v1/agents/{id}/blast-radius", s.handleBlastRadius)
	s.mux.HandleFunc("GET /api/v1/agents/{id}/remediations", s.handleRemediations)
	s.mux.HandleFunc("GET /api/v1/paths", s.handlePaths)
	s.mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	s.mux.HandleFunc("GET /api/v1/alerts/stream", s.handleAlertStream)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// GET /api/v1/graph
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.graph.Snapshot())
}

// agentSummary is the /api/v1/agents listing entry.
type agentSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ToolCount     int    `json:"tool_count"`
	PathCount     int    `json:"path_count"`
	CriticalPaths int    `json:"critical_paths"`
	TopPathRisk   int    `json:"top_path_risk"`
	ExposureScore int    `json:"exposure_score"`
	ExposureRisk  string `json:"exposure_risk"`
}

// GET /api/v1/agents
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents := s.graph.NodesByType(graph.NodeAIAgent)
	summaries := make([]agentSummary, 0, len(agents))

	byAgent := map[string][]*remediation.ScoredPath{}
	for _, p := range s.allPaths(r) {
		sp := &remediation.ScoredPath{Path: p, Risk: risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence)}
		byAgent[p.Source.ID] = append(byAgent[p.Source.ID], sp)
	}

	for _, a := range agents {
		sum := agentSummary{ID: a.ID, Name: a.Name}
		for _, e := range s.graph.OutEdges(a.ID) {
			if e.Type == graph.EdgeUses {
				sum.ToolCount++
			}
		}
		for _, sp := range byAgent[a.ID] {
			sum.PathCount++
			if sp.Risk.Severity == risk.SeverityCritical {
				sum.CriticalPaths++
			}
			if sp.Risk.Score > sum.TopPathRisk {
				sum.TopPathRisk = sp.Risk.Score
			}
		}
		if rad, err := blast.Analyze(s.graph, a.ID, s.pathOptions(r)); err == nil {
			sum.ExposureScore = rad.ExposureScore
			sum.ExposureRisk = rad.ExposureRisk
		}
		summaries = append(summaries, sum)
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": summaries})
}

// GET /api/v1/agents/{id}
func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, ok := s.graph.Node(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown node %q", id))
		return
	}
	writeJSON(w, http.StatusOK, n)
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

// GET /api/v1/agents/{id}/blast-radius
func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rad, err := blast.Analyze(s.graph, id, s.pathOptions(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	out := blastRadiusJSON{
		Agent:            rad.Agent.ID,
		ExposureScore:    rad.ExposureScore,
		ExposureRisk:     rad.ExposureRisk,
		ReachableNodes:   rad.ReachableNodes,
		CloudRoles:       rad.CloudRoles,
		Secrets:          rad.ReachableSecrets,
		Identities:       rad.ReachableIdentities,
		CrownJewels:      rad.ReachableCrownJewels,
		HighestPrivilege: rad.HighestPrivilege,
		TotalPaths:       rad.TotalPaths,
		CriticalPaths:    rad.CriticalPaths,
		HighPaths:        rad.HighPaths,
		Direct:           map[string]int{},
		Indirect:         map[string]int{},
	}
	for t, n := range rad.Direct {
		out.Direct[string(t)] = n
	}
	for t, n := range rad.Indirect {
		out.Indirect[string(t)] = n
	}
	if rad.MostDangerous != nil {
		out.MostDangerousPath = scoredToJSON(rad.MostDangerous.Path, rad.MostDangerous.Risk)
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/agents/{id}/remediations
func (s *Server) handleRemediations(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := remediation.Optimize(s.graph, id, s.pathOptions(r), 20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := map[string]any{
		"agent":              id,
		"remove_edge":        map[string]string{"source": rec.Edge.Source, "target": rec.Edge.Target, "type": string(rec.Edge.Type)},
		"paths_before":       rec.PathsBefore,
		"paths_after":        rec.PathsAfter,
		"critical_before":    rec.CriticalBefore,
		"critical_after":     rec.CriticalAfter,
		"high_before":        rec.HighBefore,
		"high_after":         rec.HighAfter,
		"risk_reduction_pct": rec.RiskReductionPct,
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/paths?from=&to=
func (s *Server) handlePaths(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	cj := r.URL.Query().Get("crown_jewels") == "true"

	opts := s.pathOptions(r)
	opts.TargetSubstring = to
	opts.CrownJewelsOnly = cj

	var ps []*paths.Path
	if from == "" {
		ps = s.allPathsFiltered(r, opts)
	} else {
		var err error
		ps, err = paths.Enumerate(s.graph, from, opts)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	out := make([]*pathJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, pathToJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": out, "count": len(out)})
}

func (s *Server) pathOptions(r *http.Request) paths.Options {
	return paths.Options{
		TargetSubstring: r.URL.Query().Get("to"),
		CrownJewelsOnly: r.URL.Query().Get("crown_jewels") == "true",
	}
}

// allPaths enumerates paths from every agent with global ID assignment.
func (s *Server) allPaths(r *http.Request) []*paths.Path {
	return s.allPathsFiltered(r, paths.Options{})
}

func (s *Server) allPathsFiltered(r *http.Request, opts paths.Options) []*paths.Path {
	ps, _ := paths.EnumerateAll(s.graph, opts)
	return ps
}
