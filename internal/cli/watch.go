package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	rt "github.com/blackrabbit1x0/agentgraph/internal/runtime"
	"github.com/spf13/cobra"
)

func newWatchCommand() *cobra.Command {
	var eventsFile string
	var follow bool
	var interval int

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

With --follow, the file is tailed live: existing events are processed,
then newly appended lines are detected and processed as they arrive
(tail -f semantics). Press Ctrl+C to stop.

Event format (one JSON object per line):

  {"timestamp":"2026-09-03T10:00:00Z","agent":"finance-agent",
   "action":"tool_call","tool":"github-mcp","target":"payments-repo"}`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()

			if eventsFile == "" {
				fmt.Println("error: --events is required (a JSONL event file)")
				return
			}
			f, err := os.Open(eventsFile)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			defer f.Close()

			det := rt.New(g, paths.Options{})
			events, alerts, err := drainEvents(f, det)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			printAlerts(events, alerts)

			if !follow {
				return
			}

			// Live tailing.
			fmt.Printf("Tailing %s for new events (every %ds). Press Ctrl+C to stop.\n\n",
				eventsFile, interval)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				<-sig
				close(done)
			}()

			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					fmt.Println("\nStopped.")
					return
				case <-ticker.C:
					n, alerts, err := drainEvents(f, det)
					if err != nil {
						fmt.Printf("error: %v\n", err)
						return
					}
					for _, a := range alerts {
						fmt.Println(rt.FormatAlert(a))
						fmt.Println()
					}
					if n > 0 {
						fmt.Printf("%d new event(s), %d alert(s)\n\n", n, len(alerts))
					}
				}
			}
		},
	}
	cmd.Flags().StringVar(&eventsFile, "events", "", "path to a JSONL event stream file")
	cmd.Flags().BoolVar(&follow, "follow", false, "tail the events file for new entries (tail -f)")
	cmd.Flags().IntVar(&interval, "interval", 1, "poll interval for --follow (seconds)")
	return cmd
}

// drainEvents reads complete lines from the current file position,
// processes each through the detector, and returns the number of events
// consumed plus any alerts. Lines without a trailing newline are left for
// the next poll.
func drainEvents(f *os.File, det *rt.Detector) (int, []rt.Alert, error) {
	var events int
	var alerts []rt.Alert
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return events, alerts, nil
			}
			return events, alerts, err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev rt.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return events, alerts, fmt.Errorf("event line: %w", err)
		}
		if ev.Agent == "" {
			return events, alerts, fmt.Errorf("event missing agent: %s", line)
		}
		events++
		newAlerts, err := det.ProcessEvent(ev)
		if err != nil {
			return events, alerts, err
		}
		alerts = append(alerts, newAlerts...)
	}
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

func printAlerts(events int, alerts []rt.Alert) {
	fmt.Println("RUNTIME DETECTION")
	fmt.Printf("Events processed: %d\n", events)
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
