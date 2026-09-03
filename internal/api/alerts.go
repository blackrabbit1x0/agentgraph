package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	rt "github.com/blackrabbit1x0/agentgraph/internal/runtime"
)

// AlertHub fans out runtime-detection alerts to SSE subscribers and
// keeps a bounded history for late joiners.
type AlertHub struct {
	mu          sync.Mutex
	subscribers map[chan rt.Alert]struct{}
	history     []rt.Alert
	maxHistory  int
}

// NewAlertHub builds an empty hub.
func NewAlertHub() *AlertHub {
	return &AlertHub{
		subscribers: map[chan rt.Alert]struct{}{},
		maxHistory:  500,
	}
}

// Publish records an alert and broadcasts it to all subscribers.
func (h *AlertHub) Publish(a rt.Alert) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.history = append(h.history, a)
	if len(h.history) > h.maxHistory {
		h.history = h.history[len(h.history)-h.maxHistory:]
	}
	for ch := range h.subscribers {
		// Non-blocking send: a slow subscriber drops alerts rather than
		// stalling the detector.
		select {
		case ch <- a:
		default:
		}
	}
}

// History returns a copy of the alert history.
func (h *AlertHub) History() []rt.Alert {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]rt.Alert, len(h.history))
	copy(out, h.history)
	return out
}

// Subscribe registers a subscriber channel; the returned func unsubscribes.
func (h *AlertHub) Subscribe() (chan rt.Alert, func()) {
	ch := make(chan rt.Alert, 64)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
	}
}

// handleAlerts serves the alert history as JSON.
// GET /api/v1/alerts
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if s.hub == nil {
		writeJSON(w, http.StatusOK, map[string]any{"alerts": []rt.Alert{}, "count": 0})
		return
	}
	h := s.hub.History()
	writeJSON(w, http.StatusOK, map[string]any{"alerts": h, "count": len(h)})
}

// handleAlertStream serves live alerts as server-sent events.
// GET /api/v1/alerts/stream
func (s *Server) handleAlertStream(w http.ResponseWriter, r *http.Request) {
	if s.hub == nil {
		writeError(w, http.StatusServiceUnavailable, "runtime detection is not enabled (start serve with --watch)")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	writeAlert := func(a rt.Alert) bool {
		data, err := json.Marshal(a)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: alert\ndata: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// History first, then live.
	for _, a := range s.hub.History() {
		if !writeAlert(a) {
			return
		}
	}

	ch, unsub := s.hub.Subscribe()
	defer unsub()

	heartbeat := r.Context()

	for {
		select {
		case <-heartbeat.Done():
			return
		case a := <-ch:
			if !writeAlert(a) {
				return
			}
		}
	}
}
