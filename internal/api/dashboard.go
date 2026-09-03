package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/dashboard.html
var dashboardHTML []byte

//go:embed web/vendor
var vendorFS embed.FS

// DashboardHandler serves the embedded web dashboard and its vendored
// static assets (cytoscape, app.js) - no external CDN, works air-gapped.
func DashboardHandler() http.Handler {
	sub, err := fs.Sub(vendorFS, "web/vendor")
	if err != nil {
		panic("api: embedded vendor assets missing: " + err.Error())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(dashboardHTML)
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	return mux
}
