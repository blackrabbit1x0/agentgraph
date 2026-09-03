package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	rt "github.com/blackrabbit1x0/agentgraph/internal/runtime"
	"github.com/spf13/cobra"
)

func newWatchCommand() *cobra.Command {
	var eventsFile string

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Detect attack-path execution in an agent event stream",
		Long: `Detect attack-path execution in an agent event stream
(PRD section 68).

Reads a JSONL file of observed agent events - from an MCP gateway log,
audit log, or agent telemetry - and matches them against the graph's
known attack paths. Alerts fire when an agent's behavior advances
in order along a dangerous path:

  [HIGH]     >= 50% of the path stages observed
  [CRITICAL] within one stage of the target
  [COMPLETE] target reached

Event format (one JSON object per line):

  {"timestamp":"2026-09-03T10:00:00Z","agent":"finance-agent",
   "action":"tool_call","tool":"github-mcp","target":"payments-repo"}`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()

			if eventsFile == "" {
				fmt.Println("error: --events is required (a JSONL event file)")
				return
			}
			data, err := os.ReadFile(eventsFile)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			events, err := parseEventsJSONL(data)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}

			det := rt.New(g, paths.Options{})
			alerts, err := det.Process(events)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			printAlerts(events, alerts)
		},
	}
	cmd.Flags().StringVar(&eventsFile, "events", "", "path to a JSONL event stream file")
	return cmd
}

func parseEventsJSONL(data []byte) ([]rt.Event, error) {
	var events []rt.Event
	line := 0
	for _, raw := range splitLines(data) {
		line++
		if len(raw) == 0 {
			continue
		}
		var ev rt.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("event line %d: %w", line, err)
		}
		if ev.Agent == "" {
			return nil, fmt.Errorf("event line %d: missing agent", line)
		}
		events = append(events, ev)
	}
	return events, nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, trimCR(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, trimCR(data[start:]))
	}
	return out
}

func trimCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}

func printAlerts(events []rt.Event, alerts []rt.Alert) {
	fmt.Println("RUNTIME DETECTION")
	fmt.Printf("Events processed: %d\n", len(events))
	fmt.Println()

	if len(alerts) == 0 {
		fmt.Println("No attack-path execution detected. All agents behaving.")
		return
	}

	for _, a := range alerts {
		fmt.Println(rt.FormatAlert(a))
		fmt.Println()
	}

	s := rt.Summarize(alerts)
	fmt.Printf("Summary: %d alerts - %d complete, %d critical, %d high - across %d attack paths\n",
		s.TotalAlerts, s.Complete, s.Critical, s.High, len(s.PathsAtRisk))
}
