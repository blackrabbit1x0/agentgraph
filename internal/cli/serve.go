package cli

import (
	"fmt"
	"net"
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
	var apiToken string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the web dashboard and REST API",
		Long: `Serve the interactive web dashboard and REST API for the loaded graph.

Works with the YAML configuration, a saved graph snapshot (--graph), or a
live scan (--save the graph first, then serve it).

Security: the server binds to 127.0.0.1 by default. Binding to a
non-loopback address without --token exposes the full security graph
(secret names, attack paths, crown jewels) to the network - a token is
strongly recommended. With --token, API requests must authenticate via
"Authorization: Bearer <token>" (or ?token=); the dashboard prompts for
it once. API requests are rate-limited per client.

With --watch <events.jsonl>, runtime attack-path detection runs inside
the server: alerts appear live in the dashboard (via server-sent events)
and are exposed at /api/v1/alerts. With --follow, the events file is
tailed and new events are processed as they arrive.

Example:
  agentgraph scan github aws --save graph.json
  agentgraph serve --graph graph.json \
    --watch agent-events.jsonl --follow --addr 127.0.0.1:8080`,
		Run: func(cmd *cobra.Command, args []string) {
			g, warnings := loadGraph()
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "warning: %s\n", w)
			}
			maybeSaveGraph(g)

			if apiToken == "" && !isLoopbackAddr(addr) {
				fmt.Fprintf(os.Stderr,
					"WARNING: serving on %s without --token exposes the full security graph to the network.\n", addr)
			}

			var hub *api.AlertHub
			var stopTail func()
			if watchFile != "" {
				hub = api.NewAlertHub()
				stopTail = startWatchTail(g, watchFile, follow, interval, hub)
			}

			dashboard := api.DashboardHandler()
			apiServer := api.NewServerWithOptions(api.ServerOptions{
				Graph: g,
				Hub:   hub,
				Token: apiToken,
			})

			mux := http.NewServeMux()
			mux.Handle("/", securityHeaders(dashboard))
			mux.Handle("/api/", securityHeaders(apiServer.Handler()))

			fmt.Printf("AgentGraph dashboard: http://%s\n", addr)
			fmt.Printf("Graph: %d nodes / %d edges\n", g.NodeCount(), g.EdgeCount())
			if apiToken != "" {
				fmt.Println("API authentication: bearer token enabled")
			}
			if watchFile != "" {
				fmt.Printf("Runtime detection: watching %s (follow=%v)\n", watchFile, follow)
				fmt.Printf("Alert feed: http://%s/api/v1/alerts/stream\n", addr)
			}
			fmt.Println("Press Ctrl+C to stop.")

			srv := &http.Server{
				Addr:    addr,
				Handler: mux,
				// No WriteTimeout: SSE streams stay open indefinitely by
				// design. Header/body reads are still bounded.
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
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
	cmd.Flags().StringVar(&apiToken, "token", "", "require this bearer token for API access (recommended when binding beyond loopback)")
	return cmd
}

// securityHeaders sets the content-security-policy and related headers.
// All dashboard assets are self-hosted (no CDN), so script-src is
// limited to same-origin.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// isLoopbackAddr reports whether the address binds to loopback only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
		tailer := &eventTailer{}
		_, alerts, err := tailer.drain(f, det)
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
				_, alerts, err := tailer.drain(f, det)
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
