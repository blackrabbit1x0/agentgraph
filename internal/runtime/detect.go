// Package runtime implements attack-path execution detection: observed
// agent actions are matched against the graph's known attack paths, and
// alerts fire when an agent's behavior advances along a dangerous path
// (PRD section 68 - "EDR for AI agents").
package runtime

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
)

// Event is one observed agent action (e.g. from an MCP gateway log,
// audit log, or agent telemetry).
type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Agent     string         `json:"agent"`
	Action    string         `json:"action,omitempty"` // tool_call, mcp_call, ...
	Tool      string         `json:"tool,omitempty"`   // tool or MCP server name
	Target    string         `json:"target,omitempty"` // target node id or name
	Detail    map[string]any `json:"detail,omitempty"`
}

// Alert levels.
const (
	LevelHigh     = "HIGH"
	LevelCritical = "CRITICAL"
	LevelComplete = "COMPLETE"
)

// Alert is raised when observed events advance an attack path.
type Alert struct {
	Level     string    `json:"level"`
	PathID    string    `json:"path_id"`
	Agent     string    `json:"agent"`
	Target    string    `json:"target"`
	Stages    int       `json:"stages_observed"`
	Total     int       `json:"total_stages"`
	NextNode  string    `json:"next_node,omitempty"`
	Risk      int       `json:"risk"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// Detector matches event streams against known attack paths. It supports
// both batch processing (Process) and incremental streaming (ProcessEvent),
// which powers live tailing.
type Detector struct {
	g           *graph.Graph
	opts        paths.Options
	states      map[string][]*pathState // path states by agent
	nodeIndex   []indexedNode           // for fast fuzzy resolution
	initialized bool
}

type indexedNode struct {
	id, lowerID, name, lowerName string
}

// New returns a detector for a graph.
func New(g *graph.Graph, opts paths.Options) *Detector {
	return &Detector{g: g, opts: opts}
}

// pathState tracks in-order progress along one attack path.
type pathState struct {
	path    *paths.Path
	score   risk.Result
	cursor  int // index into path.Nodes(); 0 = only the source observed
	alerted map[string]bool
}

// Init enumerates attack paths and prepares per-path state. Called
// lazily by ProcessEvent on first use.
func (d *Detector) Init() error {
	if d.initialized {
		return nil
	}
	all, err := paths.EnumerateAll(d.g, d.opts)
	if err != nil {
		return err
	}
	d.states = map[string][]*pathState{}
	for _, p := range all {
		d.states[p.Source.ID] = append(d.states[p.Source.ID], &pathState{
			path:    p,
			score:   risk.ScorePath(p.Nodes(), p.Edges(), p.Confidence),
			alerted: map[string]bool{},
		})
	}
	for _, n := range d.g.Nodes() {
		d.nodeIndex = append(d.nodeIndex, indexedNode{
			id: n.ID, lowerID: strings.ToLower(n.ID),
			name: n.Name, lowerName: strings.ToLower(n.Name),
		})
	}
	d.initialized = true
	return nil
}

// Process consumes a batch of events in order and returns alerts.
func (d *Detector) Process(events []Event) ([]Alert, error) {
	if err := d.Init(); err != nil {
		return nil, err
	}
	var alerts []Alert
	for _, ev := range events {
		al, err := d.ProcessEvent(ev)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, al...)
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.Before(alerts[j].Timestamp)
	})
	return alerts, nil
}

// ProcessEvent consumes one event and returns any alerts it triggered.
// Safe to call concurrently with nothing else; designed for sequential
// streaming.
func (d *Detector) ProcessEvent(ev Event) ([]Alert, error) {
	if !d.initialized {
		if err := d.Init(); err != nil {
			return nil, err
		}
	}

	agentStates := d.states[ev.Agent]
	if agentStates == nil {
		return nil, nil
	}

	matched := d.resolveNode(ev)
	if matched == "" {
		return nil, nil
	}

	var alerts []Alert
	for _, st := range agentStates {
		nodes := st.path.Nodes()
		// Advance: the event's node must be the next node in the chain.
		if st.cursor+1 < len(nodes) && nodes[st.cursor+1].ID == matched {
			st.cursor++
			if alert, ok := st.evaluate(ev.Timestamp); ok {
				alerts = append(alerts, alert)
			}
		}
	}
	return alerts, nil
}

// evaluate decides whether the current progress warrants an alert.
func (st *pathState) evaluate(ts time.Time) (Alert, bool) {
	total := len(st.path.Nodes()) - 1 // hops
	if total <= 0 {
		return Alert{}, false
	}
	stages := st.cursor

	nodes := st.path.Nodes()
	next := ""
	if st.cursor < len(nodes)-1 {
		next = nodes[st.cursor+1].ID
	}

	level := ""
	switch {
	case stages == total:
		level = LevelComplete
	case total >= 3 && stages >= total-1:
		level = LevelCritical
	case stages >= 2 && stages*2 >= total:
		level = LevelHigh
	}
	if level == "" {
		return Alert{}, false
	}
	// Fire each level at most once per path.
	if st.alerted[level] {
		return Alert{}, false
	}
	st.alerted[level] = true

	return Alert{
		Level:     level,
		PathID:    st.path.ID,
		Agent:     st.path.Source.ID,
		Target:    st.path.Target.ID,
		Stages:    stages,
		Total:     total,
		NextNode:  next,
		Risk:      st.score.Score,
		Severity:  st.score.Severity,
		Timestamp: ts,
	}, true
}

// resolveNode maps an event to a graph node ID: exact ID, exact name,
// then fuzzy substring on either.
func (d *Detector) resolveNode(ev Event) string {
	for _, candidate := range []string{ev.Target, ev.Tool} {
		if candidate == "" {
			continue
		}
		if _, ok := d.g.Node(candidate); ok {
			return candidate
		}
		lower := strings.ToLower(candidate)
		for _, n := range d.nodeIndex {
			if n.name != "" && n.name == candidate {
				return n.id
			}
		}
		for _, n := range d.nodeIndex {
			if strings.Contains(n.lowerID, lower) || (n.lowerName != "" && strings.Contains(n.lowerName, lower)) {
				return n.id
			}
		}
	}
	return ""
}

// Summary aggregates alerts for reporting.
type Summary struct {
	TotalAlerts int
	Complete    int
	Critical    int
	High        int
	PathsAtRisk map[string]int
}

// Summarize aggregates a set of alerts.
func Summarize(alerts []Alert) *Summary {
	s := &Summary{PathsAtRisk: map[string]int{}}
	for _, a := range alerts {
		s.TotalAlerts++
		switch a.Level {
		case LevelComplete:
			s.Complete++
		case LevelCritical:
			s.Critical++
		case LevelHigh:
			s.High++
		}
		s.PathsAtRisk[a.PathID] = a.Stages
	}
	return s
}

// FormatAlert renders one alert in the PRD section 68 style.
func FormatAlert(a Alert) string {
	var b strings.Builder
	icon := "!!"
	if a.Level == LevelComplete {
		icon = "XX"
	}
	fmt.Fprintf(&b, "[%s] %s ATTACK PATH EXECUTION\n", a.Level, icon)
	fmt.Fprintf(&b, "  Path:     %s (%s -> %s)\n", a.PathID, a.Agent, a.Target)
	fmt.Fprintf(&b, "  Stages:   %d/%d observed\n", a.Stages, a.Total)
	if a.Level != LevelComplete && a.NextNode != "" {
		fmt.Fprintf(&b, "  Next:     %s\n", a.NextNode)
	}
	fmt.Fprintf(&b, "  Risk:     %d/100 (%s)\n", a.Risk, a.Severity)
	fmt.Fprintf(&b, "  At:       %s\n", a.Timestamp.Format(time.RFC3339))
	return b.String()
}
