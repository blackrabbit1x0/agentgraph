package cli

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/blackrabbit1x0/agentgraph/internal/api"
	"github.com/spf13/cobra"
)

func newServeCommand() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the web dashboard and REST API",
		Long: `Serve the interactive web dashboard and REST API for the loaded graph.

Works with the YAML configuration, a saved graph snapshot (--graph), or a
live scan (--save the graph first, then serve it).

Example:
  agentgraph scan github aws --save graph.json
  agentgraph serve --graph graph.json --addr 127.0.0.1:8080`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()
			maybeSaveGraph(g)

			mux := http.NewServeMux()
			mux.Handle("/", api.DashboardHandler())
			mux.Handle("/api/", api.NewServer(g).Handler())

			fmt.Printf("AgentGraph dashboard: http://%s\n", addr)
			fmt.Printf("Graph: %d nodes / %d edges\n", g.NodeCount(), g.EdgeCount())
			fmt.Println("Press Ctrl+C to stop.")

			srv := &http.Server{Addr: addr, Handler: mux}
			go func() {
				sig := make(chan os.Signal, 1)
				signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
				<-sig
				_ = srv.Close()
			}()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address")
	return cmd
}
