// Package svg renders an attack-path graph as a standalone SVG file,
// suitable for sharing and embedding in reports and READMEs.
package svg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
)

// Node colors by type.
var typeColors = map[graph.NodeType]string{
	graph.NodeAIAgent:       "#f778ba",
	graph.NodeMCPServer:     "#bc8cff",
	graph.NodeTool:          "#d2a8ff",
	graph.NodeIdentity:      "#58a6ff",
	graph.NodeSecret:        "#ff7b72",
	graph.NodeRepository:    "#3fb950",
	graph.NodeCIPipeline:    "#d29922",
	graph.NodeCloudRole:     "#ffa657",
	graph.NodeCloudResource: "#f0883e",
	graph.NodeDatabase:      "#f85149",
	graph.NodeHost:          "#8b949e",
	graph.NodeAPI:           "#79c0ff",
	graph.NodeDataset:       "#e3b341",
}

// Highlight specifies which path to emphasize.
type Highlight struct {
	NodeIDs  map[string]bool
	EdgeKeys map[string]bool
}

// NewHighlight builds a highlight from a path.
func NewHighlight(p *paths.Path) *Highlight {
	h := &Highlight{NodeIDs: map[string]bool{}, EdgeKeys: map[string]bool{}}
	if p == nil {
		return h
	}
	for _, n := range p.Nodes() {
		h.NodeIDs[n.ID] = true
	}
	for _, e := range p.Edges() {
		h.EdgeKeys[edgeKey(e)] = true
	}
	return h
}

func edgeKey(e *graph.Edge) string {
	return fmt.Sprintf("%s|%s|%s", e.Source, e.Type, e.Target)
}

// Render produces a complete SVG document. When animate is true, the
// highlighted path animates: edges dash-flow and nodes pulse in
// sequence, producing a shareable "attack path in motion" image
// (animated SVGs render in GitHub READMEs).
//
// Layout: nodes are placed in columns by BFS hop distance from the
// leftmost AI agents, and stacked vertically within each column. Agents
// are on the left, critical targets on the right.
func Render(g *graph.Graph, title string, hl *Highlight, animate bool) string {
	if hl == nil {
		hl = &Highlight{NodeIDs: map[string]bool{}, EdgeKeys: map[string]bool{}}
	}
	hlIndex := map[string]int{}
	if animate {
		// Order highlighted nodes for sequential animation delays.
		i := 0
		for _, e := range g.Edges() {
			if hl.EdgeKeys[edgeKey(e)] {
				hlIndex[e.Source] = i
				hlIndex[e.Target] = i + 1
				i++
			}
		}
	}

	// Column assignment: BFS depth from any agent; agents are depth 0.
	depth := map[string]int{}
	queue := []string{}
	for _, a := range g.NodesByType(graph.NodeAIAgent) {
		depth[a.ID] = 0
		queue = append(queue, a.ID)
	}
	// Nodes unreachable from any agent get their own final column.
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.OutEdges(cur) {
			if _, ok := depth[e.Target]; !ok {
				depth[e.Target] = depth[cur] + 1
				queue = append(queue, e.Target)
			}
		}
	}
	maxDepth := 0
	unreached := []string{}
	for _, n := range g.Nodes() {
		if d, ok := depth[n.ID]; ok {
			if d > maxDepth {
				maxDepth = d
			}
		} else {
			unreached = append(unreached, n.ID)
		}
	}
	for _, id := range unreached {
		depth[id] = maxDepth + 1
	}
	if len(unreached) > 0 {
		maxDepth++
	}

	// Group nodes by column, sorted by ID for determinism.
	columns := map[int][]*graph.Node{}
	for _, n := range g.Nodes() {
		columns[depth[n.ID]] = append(columns[depth[n.ID]], n)
	}
	for c := range columns {
		col := columns[c]
		sort.Slice(col, func(i, j int) bool { return col[i].ID < col[j].ID })
	}

	// Layout metrics.
	const (
		nodeW   = 150.0
		nodeH   = 38.0
		colGap  = 90.0
		rowGap  = 18.0
		margin  = 24.0
		headerH = 56.0
	)

	colCount := maxDepth + 1
	rows := 0
	for _, col := range columns {
		if len(col) > rows {
			rows = len(col)
		}
	}

	width := margin*2 + float64(colCount)*nodeW + float64(colCount-1)*colGap
	height := headerH + margin*2 + float64(rows)*nodeH + float64(rows-1)*rowGap
	if rows == 0 {
		height = headerH + margin*2
	}

	// Node positions.
	type pos struct{ x, y float64 }
	positions := map[string]pos{}
	for c, col := range columns {
		for i, n := range col {
			x := margin + float64(c)*(nodeW+colGap)
			y := headerH + margin + float64(i)*(nodeH+rowGap)
			positions[n.ID] = pos{x, y}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" font-family="Segoe UI, Helvetica, Arial, sans-serif">
<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="#6e7681"/>
</marker>
<marker id="arrow-hl" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="#58a6ff"/>
</marker>
<marker id="arrow-danger" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="#f85149"/>
</marker>
</defs>
`, width, height, width, height)
	if animate {
		b.WriteString(`<style>
.hl-node { animation: ag-pulse 2.4s ease-in-out infinite; }
.hl-edge { stroke-dasharray: 8 6; animation: ag-dash 1.2s linear infinite; }
.hl-label { animation: ag-pulse 2.4s ease-in-out infinite; }
@keyframes ag-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
@keyframes ag-dash { to { stroke-dashoffset: -28; } }
</style>
`)
	}
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#0d1117"/>
<text x="%.0f" y="34" fill="#e6edf3" font-size="18" font-weight="600">%s</text>
`, margin, escapeXML(title))

	// Edges first (below nodes).
	for _, e := range g.Edges() {
		src, ok1 := positions[e.Source]
		tgt, ok2 := positions[e.Target]
		if !ok1 || !ok2 {
			continue
		}
		x1 := src.x + nodeW
		y1 := src.y + nodeH/2
		x2 := tgt.x
		y2 := tgt.y + nodeH/2

		color := "#6e7681"
		marker := "arrow"
		widthAttr := "1.4"
		switch {
		case e.Type == graph.EdgeCanAdmin || e.Type == graph.EdgeCanExecute || e.Type == graph.EdgeCanImpersonate:
			color = "#f85149"
			marker = "arrow-danger"
			widthAttr = "2.2"
		case e.Type == graph.EdgeCanAssume || e.Type == graph.EdgeContainsSecret || e.Type == graph.EdgeHasSecret:
			color = "#ffa657"
		}
		if hl.EdgeKeys[edgeKey(e)] {
			color = "#58a6ff"
			marker = "arrow-hl"
			widthAttr = "3"
		}

		// Curved path for visual clarity.
		mx := (x1 + x2) / 2
		animClass := ""
		if animate && hl.EdgeKeys[edgeKey(e)] {
			animClass = ` class="hl-edge"`
		}
		fmt.Fprintf(&b, `<path%s d="M %.1f %.1f C %.1f %.1f, %.1f %.1f, %.1f %.1f" fill="none" stroke="%s" stroke-width="%s" marker-end="url(#%s)"/>`+"\n",
			animClass, x1, y1, mx, y1, mx, y2, x2-2, y2, color, widthAttr, marker)

		// Edge label at midpoint.
		label := string(e.Type)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="#8b949e" font-size="8" text-anchor="middle" transform="rotate(-90 %.1f %.1f)">%s</text>`+"\n",
			mx, (y1+y2)/2-3, mx, (y1+y2)/2-3, label)
	}

	// Nodes.
	for c := 0; c <= maxDepth; c++ {
		for _, n := range columns[c] {
			p := positions[n.ID]
			color := typeColors[n.Type]
			if color == "" {
				color = "#8b949e"
			}
			stroke := "#30363d"
			strokeW := "1"
			if hl.NodeIDs[n.ID] {
				stroke = "#58a6ff"
				strokeW = "2.5"
			}
			if n.CrownJewel {
				stroke = "#e3b341"
				strokeW = "2.5"
			}
			animStyle := ""
			if animate && hl.NodeIDs[n.ID] {
				animStyle = fmt.Sprintf(` class="hl-node" style="animation-delay:%dms"`, hlIndex[n.ID]*300)
			}
			fmt.Fprintf(&b, `<g%s><rect x="%.1f" y="%.1f" width="%.0f" height="%.0f" rx="6" fill="%s" fill-opacity="0.18" stroke="%s" stroke-width="%s"/>`,
				animStyle, p.x, p.y, nodeW, nodeH, color, stroke, strokeW)

			label := shortLabel(n)
			fontSize := 11
			if len(label) > 20 {
				fontSize = 9
			}
			textColor := "#c9d1d9"
			if n.CrownJewel {
				textColor = "#e3b341"
			}
			fmt.Fprintf(&b, `<title>%s (%s)</title>`, escapeXML(n.ID), n.Type)
			fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="%s" font-size="%d" font-weight="600" text-anchor="middle">%s</text></g>`+"\n",
				p.x+nodeW/2, p.y+nodeH/2+4, textColor, fontSize, escapeXML(label))
		}
	}

	// Legend.
	legendTypes := []graph.NodeType{graph.NodeAIAgent, graph.NodeMCPServer, graph.NodeSecret, graph.NodeCloudRole, graph.NodeDatabase}
	lx := margin
	ly := height - 14
	b.WriteString(`<g font-size="10" fill="#8b949e">`)
	for _, t := range legendTypes {
		b.WriteString(fmt.Sprintf(`<rect x="%.0f" y="%.0f" width="10" height="10" rx="2" fill="%s" fill-opacity="0.4" stroke="%s"/>`,
			lx, ly-9, typeColors[t], typeColors[t]))
		b.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.0f">%s</text>`, lx+16, ly, string(t)))
		lx += 16 + float64(len(string(t)))*6 + 24
	}
	b.WriteString(fmt.Sprintf(`<rect x="%.0f" y="%.0f" width="10" height="10" rx="2" fill="none" stroke="#e3b341" stroke-width="2"/>`, lx, ly-9))
	b.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.0f">CROWN JEWEL</text></g>`, lx+16, ly))
	b.WriteString("\n</svg>\n")

	return b.String()
}

func shortLabel(n *graph.Node) string {
	if n.Name != "" && n.Name != n.ID {
		if len(n.Name) <= 26 {
			return n.Name
		}
		return n.Name[:25] + "…"
	}
	parts := strings.Split(n.ID, "/")
	last := parts[len(parts)-1]
	if len(last) > 26 {
		return last[:25] + "…"
	}
	return last
}

func escapeXML(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
