package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// realFS is the production FileReader.
type realFS struct{}

func (realFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (realFS) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// HTTPLister lists tools from a live MCP server using the streamable HTTP
// (or HTTP+SSE) transport. It performs the standard initialize ->
// notifications/initialized -> tools/list sequence and never calls any
// tool.
type HTTPLister struct{}

// jsonRPCRequest is one JSON-RPC message.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// ListTools implements ToolLister.
func (HTTPLister) ListTools(ctx context.Context, server ServerDef, timeoutSeconds int) ([]ToolInfo, error) {
	if server.URL == "" {
		return nil, fmt.Errorf("no url")
	}
	client := &http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
		// Redirects are denied outright: the MCP endpoint is a specific
		// host, and following server-controlled redirects would turn the
		// scanner into an open proxy.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	_, session, err := mpcCall(client, ctx, server, jsonRPCRequest{
		JSONRPC: "2.0", ID: 1, Method: "initialize",
		Params: map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "agentgraph", "version": "0.3.0"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	// Notify initialized (no response expected; ignore errors).
	_, _, _ = mpcCall(client, ctx, withSession(server, session), jsonRPCRequest{
		JSONRPC: "2.0", Method: "notifications/initialized",
	})

	toolsPayload, _, err := mpcCall(client, ctx, withSession(server, session), jsonRPCRequest{
		JSONRPC: "2.0", ID: 2, Method: "tools/list",
	})
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	var out struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(toolsPayload, &out); err != nil {
		return nil, fmt.Errorf("decode tools: %w", err)
	}
	tools := make([]ToolInfo, 0, len(out.Result.Tools))
	for _, t := range out.Result.Tools {
		tools = append(tools, ToolInfo{Name: t.Name, Description: t.Description})
	}
	return tools, nil
}

// withSession rewrites the URL to include the MCP session id, mirroring
// how streamable-HTTP clients persist sessions.
func withSession(server ServerDef, session string) ServerDef {
	if session == "" {
		return server
	}
	sep := "?"
	if strings.Contains(server.URL, "?") {
		sep = "&"
	}
	s := server
	s.URL = s.URL + sep + "Mcp-Session-Id=" + session
	return s
}

// mpcCall performs one JSON-RPC POST and returns the raw response payload
// matching the request id. Handles both JSON and SSE responses.
func mpcCall(client *http.Client, ctx context.Context, server ServerDef, req jsonRPCRequest) ([]byte, string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("http %d", resp.StatusCode)
	}
	session := resp.Header.Get("Mcp-Session-Id")

	payload := extractRPCResponse(data, req.ID)
	if payload == nil {
		return nil, session, fmt.Errorf("no response for id %v", req.ID)
	}
	return payload, session, nil
}

// extractRPCResponse finds the JSON-RPC response matching id in either a
// plain JSON body or an SSE stream of "data:" events.
func extractRPCResponse(data []byte, id any) []byte {
	// Try plain JSON first.
	var envelope struct {
		ID    *any            `json:"id"`
		Error *struct{}       `json:"error"`
		Raw   json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.ID != nil {
		if fmt.Sprint(*envelope.ID) == fmt.Sprint(id) {
			return data
		}
		return nil
	}
	// SSE: scan data lines.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		var env struct {
			ID *any `json:"id"`
		}
		if err := json.Unmarshal([]byte(payload), &env); err == nil && env.ID != nil {
			if fmt.Sprint(*env.ID) == fmt.Sprint(id) {
				return []byte(payload)
			}
		}
	}
	return nil
}
