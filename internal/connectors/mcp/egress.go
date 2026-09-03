package mcp

import (
	"fmt"
	"net"
	"net/url"
)

// egressAllowed enforces the live-query network policy.
//
// Servers configured in the user's global config locations are trusted:
// they were placed there by the user, so private/loopback hosts (the
// normal case for local MCP servers) are permitted.
//
// Servers configured by files in the working directory may come from an
// untrusted repository. For those, live queries are restricted to
// public HTTPS endpoints unless AllowPrivate is explicitly set. This
// prevents a malicious .mcp.json from turning `agentgraph scan mcp --live`
// into a probe of cloud metadata endpoints (169.254.169.254) or internal
// services from the analyst's network position.
func (c *Connector) egressAllowed(srv ServerDef) error {
	if !srv.FromProjectDir || c.opts.AllowPrivate {
		return nil
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		return fmt.Errorf("invalid url")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme %q not allowed for project configs", u.Scheme)
	}
	host := u.Hostname()
	if host == "localhost" {
		return fmt.Errorf("loopback host blocked for project configs (use --allow-private to override)")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("dns resolution failed for %s", host)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("private address %s blocked for project configs (use --allow-private to override)", ip)
		}
	}
	return nil
}
