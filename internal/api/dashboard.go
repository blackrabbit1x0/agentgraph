package api

import (
	_ "embed"
	"net/http"
)

//go:embed web/dashboard.html
var dashboardHTML []byte

// DashboardHandler serves the embedded web dashboard.
func DashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	})
}
