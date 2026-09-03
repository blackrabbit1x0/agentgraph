// Package api implements the AgentGraph REST API and web dashboard
// (PRD sections 60 and 29).
package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/blast"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/remediation"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

// ServerOptions configures the API server.
type ServerOptions struct {
	Graph *graph.Graph
	// Hub is an optional alert hub enabling the /api/v1/alerts endpoints.
	Hub *AlertHub
	// Token enables bearer-token authentication when non-empty. Requests
	// must present it via "Authorization: Bearer <token>" or "?token=".
	Token string
}

// Server serves the REST API. Heavy analysis (path enumeration, blast
// radii) is computed once and cached; request handlers only read the
// cache. The remediation endpoint never mutates the served graph.
type Server struct {
	graph *graph.Graph
	hub   *AlertHub
	token string
	lim   *rateLimiter

	mux *http.ServeMux

	cacheMu   sync.Mutex
	agentsSum []agentSummary
	basePaths []*paths.Path
	radii     map[string]*blast.Radius
}

// NewServer builds the server for a graph.
func NewServer(g *graph.Graph) *Server {
	return NewServerWithOptions(ServerOptions{Graph: g})
}

// NewServerWithAlerts builds the server with a runtime-detection alert
// hub (enables the /api/v1/alerts endpoints).
func NewServerWithAlerts(g *graph.Graph, hub *AlertHub) *Server {
	return NewServerWithOptions(ServerOptions{Graph: g, Hub: hub})
}

// NewServerWithOptions builds a configured server.
func NewServerWithOptions(opts ServerOptions) *Server {
	s := &Server{
		graph: opts.Graph,
		hub:   opts.Hub,
		token: opts.Token,
		lim:   newRateLimiter(10, 120), // 10 req/s sustained, 120 burst
		radii: map[string]*blast.Radius{},
		mux:   http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler (auth + rate limit enforced on
// /api/*).
func (s *Server) Handler() http.Handler {
	return s.auth(s.mux)
}

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

// auth wraps the mux with bearer-token authentication (when configured)
// and per-client rate limiting.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the API surface is authenticated and rate limited; the
		// dashboard HTML itself contains no data.
		if !isAPIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r)
		if !s.lim.allow(ip) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		if s.token != "" {
			presented := r.Header.Get("Authorization")
			if presented == "Bearer "+s.token || r.URL.Query().Get("token") == s.token {
				// authenticated
			} else {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isAPIPath(path string) bool {
	return len(path) >= 5 && path[:5] == "/api/"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimiter is a per-client token bucket.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   int
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{
		buckets: map[string]*bucket{},
		rate:    rate,
		burst:   burst,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), last: now}
		rl.buckets[key] = b
		// Bound the map: drop stale buckets beyond a generous cap.
		if len(rl.buckets) > 4096 {
			for k, v := range rl.buckets {
				if now.Sub(v.last) > 10*time.Minute {
					delete(rl.buckets, k)
				}
			}
		}
	}
	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ensureAnalysis computes the cached agent summaries and the base path
// enumeration exactly once.
func (s *Server) ensureAnalysis() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.agentsSum != nil {
		return
	}

	s.basePaths, _ = paths.EnumerateAll(s.graph, paths.Options{})
	byAgent := map[string]int{}
	for _, p := range s.basePaths {
		byAgent[p.Source.ID]++
	}
	byAgentCritical := map[string]int{}
	byAgentTopRisk := map[string]int{}
	for _, p := range s.basePaths {
		res := risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence)
		if res.Severity == risk.SeverityCritical {
			byAgentCritical[p.Source.ID]++
		}
		if res.Score > byAgentTopRisk[p.Source.ID] {
			byAgentTopRisk[p.Source.ID] = res.Score
		}
	}

	agents := s.graph.NodesByType(graph.NodeAIAgent)
	summaries := make([]agentSummary, 0, len(agents))
	for _, a := range agents {
		sum := agentSummary{
			ID:            a.ID,
			Name:          a.Name,
			PathCount:     byAgent[a.ID],
			CriticalPaths: byAgentCritical[a.ID],
			TopPathRisk:   byAgentTopRisk[a.ID],
		}
		for _, e := range s.graph.OutEdges(a.ID) {
			if e.Type == graph.EdgeUses {
				sum.ToolCount++
			}
		}
		if rad := s.radiusLocked(a.ID); rad != nil {
			sum.ExposureScore = rad.ExposureScore
			sum.ExposureRisk = rad.ExposureRisk
		}
		summaries = append(summaries, sum)
	}
	s.agentsSum = summaries
}

// radiusLocked returns the cached blast radius for an agent. Callers must
// hold cacheMu.
func (s *Server) radiusLocked(agentID string) *blast.Radius {
	if r, ok := s.radii[agentID]; ok {
		return r
	}
	r, err := blast.Analyze(s.graph, agentID, paths.Options{})
	if err != nil {
		return nil
	}
	s.radii[agentID] = r
	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = jsonNewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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

// GET /api/v1/graph
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.graph.Snapshot())
}

// GET /api/v1/agents
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	s.ensureAnalysis()
	s.cacheMu.Lock()
	sums := append([]agentSummary(nil), s.agentsSum...)
	s.cacheMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"agents": sums})
}

// GET /api/v1/agents/{id}
func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, ok := s.graph.Node(id)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown node "+strconv.Quote(id))
		return
	}
	writeJSON(w, http.StatusOK, n)
}

// GET /api/v1/agents/{id}/blast-radius
func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.ensureAnalysis()
	s.cacheMu.Lock()
	rad := s.radiusLocked(id)
	s.cacheMu.Unlock()
	if rad == nil {
		writeError(w, http.StatusNotFound, "unknown agent "+strconv.Quote(id))
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
	// Optimize operates on a clone internally: the served graph is never
	// mutated (see remediation.Optimize).
	rec, err := remediation.Optimize(s.graph, id, paths.Options{}, 20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := map[string]any{
		"agent": id,
		"remove_edge": map[string]string{
			"source": rec.Edge.Source, "target": rec.Edge.Target, "type": string(rec.Edge.Type),
		},
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

// GET /api/v1/paths?from=&to=&crown_jewels=
func (s *Server) handlePaths(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	cj := r.URL.Query().Get("crown_jewels") == "true"

	s.ensureAnalysis()
	s.cacheMu.Lock()
	base := s.basePaths
	s.cacheMu.Unlock()

	// Filter the globally-enumerated set so path IDs match the CLI,
	// explain, export, and alert feeds.
	ps := make([]*paths.Path, 0, len(base))
	for _, p := range base {
		if from != "" && p.Source.ID != from {
			continue
		}
		if cj && !p.Target.CrownJewel {
			continue
		}
		if to != "" && !pathMatchesTarget(p, to) {
			continue
		}
		ps = append(ps, p)
	}

	out := make([]*pathJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, pathToJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": out, "count": len(out)})
}

func pathMatchesTarget(p *paths.Path, spec string) bool {
	for _, n := range p.Nodes() {
		if containsFoldSimple(n.ID, spec) || containsFoldSimple(n.Name, spec) {
			return true
		}
	}
	return false
}
