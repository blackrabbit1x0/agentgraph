package cli

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blackrabbit1x0/agentgraph/internal/api"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	rt "github.com/blackrabbit1x0/agentgraph/internal/runtime"
	"github.com/spf13/cobra"
)

func newServeCommand() *cobra.Command {
	var addr string
	var watchFile string
	var follow bool
	var interval int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the web dashboard and REST API",
		Long: `Serve the interactive web dashboard and REST API for the loaded graph.

Works with the YAML configuration, a saved graph snapshot (--graph), or a
live scan (--save the graph first, then serve it).

With --watch <events.jsonl>, runtime attack-path detection runs inside
the server: alerts appear live in the dashboard (via server-sent events)
and are exposed at /api/v1/alerts. With --follow, the events file is
tailed and new events are processed as they arrive.

Example:
  agentgraph scan github aws --save graph.json
  agentgraph serve --graph graph.json \
    --watch agent-events.jsonl --follow --addr 127.0.0.1:8080`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			maybeSaveGraph(g)

			mux := http.NewServeMux()
			var hub *api.AlertHub
			var stopTail func()

			if watchFile != "" {
				hub = api.NewAlertHub()
				stopTail = startWatchTail(g, watchFile, follow, interval, hub)
			}

			mux.Handle("/", api.DashboardHandler())
			mux.Handle("/api/", api.NewServerWithAlerts(g, hub).Handler())

			fmt.Printf("AgentGraph dashboard: http://%s\n", addr)
			fmt.Printf("Graph: %d nodes / %d edges\n", g.NodeCount(), g.EdgeCount())
			if watchFile != "" {
				fmt.Printf("Runtime detection: watching %s (follow=%v)\n", watchFile, follow)
				fmt.Printf("Alert feed: http://%s/api/v1/alerts/stream\n", addr)
			}
			fmt.Println("Press Ctrl+C to stop.")

			srv := &http.Server{Addr: addr, Handler: mux}
			go func() {
				sig := make(chan os.Signal, 1)
				signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
				<-sig
				if stopTail != nil {
					stopTail()
				}
				_ = srv.Close()
			}()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address")
	cmd.Flags().StringVar(&watchFile, "watch", "", "enable runtime detection from a JSONL events file")
	cmd.Flags().BoolVar(&follow, "follow", false, "tail the events file for new entries")
	cmd.Flags().IntVar(&interval, "interval", 1, "poll interval for --follow (seconds)")
	return cmd
}

// startWatchTail tails an events file through the runtime detector in a
// background goroutine, publishing alerts to the hub. Returns a stop
// function. Initial (existing) events are always processed; with follow,
// appended events are polled every interval seconds.
func startWatchTail(g *graph.Graph, watchFile string, follow bool, interval int, hub *api.AlertHub) func() {
	done := make(chan struct{})
	go func() {
		f, err := os.Open(watchFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: watch: %v\n", err)
			return
		}
		defer f.Close()

		det := rt.New(g, paths.Options{})
		_, alerts, err := drainEvents(f, det)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: watch: %v\n", err)
			return
		}
		for _, a := range alerts {
			hub.Publish(a)
		}

		if !follow {
			return
		}

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_, alerts, err := drainEvents(f, det)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: watch: %v\n", err)
					return
				}
				for _, a := range alerts {
					hub.Publish(a)
				}
			}
		}
	}()
	return func() { close(done) }
}
