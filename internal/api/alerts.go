package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	rt "github.com/blackrabbit1x0/agentgraph/internal/runtime"
)

// maxSubscribers caps concurrent SSE clients to bound goroutine and
// channel usage.
const maxSubscribers = 32

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
// Returns false when the subscriber cap is reached.
func (h *AlertHub) Subscribe() (chan rt.Alert, func(), bool) {
	ch := make(chan rt.Alert, 64)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) >= maxSubscribers {
		return nil, nil, false
	}
	h.subscribers[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
	}, true
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
	w.Header().Set("X-Accel-Buffering", "no")

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

	// Subscribe BEFORE replaying history so no alert can fall in the
	// gap; duplicate replays are dropped by key.
	ch, unsub, ok := s.hub.Subscribe()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "too many alert stream subscribers")
		return
	}
	defer unsub()

	seen := map[string]bool{}
	for _, a := range s.hub.History() {
		key := fmt.Sprintf("%s|%s|%s|%d", a.PathID, a.Level, a.Timestamp.Format("2006-01-02T15:04:05.000000000"), a.Stages)
		if seen[key] {
			continue
		}
		seen[key] = true
		if !writeAlert(a) {
			return
		}
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-ch:
			key := fmt.Sprintf("%s|%s|%s|%d", a.PathID, a.Level, a.Timestamp.Format("2006-01-02T15:04:05.000000000"), a.Stages)
			if seen[key] {
				continue
			}
			seen[key] = true
			if !writeAlert(a) {
				return
			}
		}
	}
}
