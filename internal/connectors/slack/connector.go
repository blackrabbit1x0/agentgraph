// Package slack implements the Slack connector: read-only discovery of
// the authenticated identity, channels and membership, users, and bot
// scopes (PRD section 22, Phase 5).
//
// Safety properties:
//   - The token is sent only in the Authorization header, never in URLs,
//     logs, or the graph.
//   - Message content is never fetched; only channel and user metadata
//     (ids, names, membership) is discovered.
package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blackrabbit1x0/agentgraph/internal/connectors"
	"github.com/blackrabbit1x0/agentgraph/internal/graph"
)

// Node ID scheme (stable, referenceable from agentgraph.yaml):
//
//	slack:identity:<user-id>   user or bot (IDENTITY)
//	slack:channel:<channel-id>  channel, DM, or group (DATASET)
const (
	idIdentity = "slack:identity:"
	idChannel  = "slack:channel:"
)

// Channel is a discovered conversation (public/private channel, DM).
type Channel struct {
	ID         string
	Name       string
	Kind       string // channel | group | im
	IsMember   bool   // caller is a member/users can post
	MemberIDs  []string
}

// User is a discovered workspace user or bot.
type User struct {
	ID      string
	Name    string
	RealName string
	IsBot   bool
}

// API abstracts the Slack Web API calls the connector needs.
type API interface {
	AuthTest(ctx context.Context) (userID, userName, teamID, teamName string, err error)
	ListChannels(ctx context.Context) ([]Channel, error)
	ListUsers(ctx context.Context) ([]User, error)
	BotScopes(ctx context.Context) ([]string, error)
}

// Options configures the connector.
type Options struct {
	API API
	// MaxChannels caps channel enumeration (0 = 200).
	MaxChannels int
	// SkipMembers skips per-channel membership paging (faster scans).
	SkipMembers bool
}

// Connector discovers Slack infrastructure.
type Connector struct {
	opts Options
}

// New returns a Slack connector.
func New(opts Options) *Connector {
	if opts.MaxChannels <= 0 {
		opts.MaxChannels = 200
	}
	return &Connector{opts: opts}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return "slack" }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	if c.opts.API == nil {
		return nil, fmt.Errorf("slack connector: API is required")
	}
	res := &connectors.DiscoveryResult{}

	userID, userName, teamID, teamName, err := c.opts.API.AuthTest(ctx)
	if err != nil {
		return nil, fmt.Errorf("slack connector: auth.test: %w", err)
	}
	self := &graph.Node{
		ID:   idIdentity + userID,
		Type: graph.NodeIdentity,
		Name: userName,
		Provider: "slack",
		Metadata: map[string]any{
			"user_id":       userID,
			"team_id":       teamID,
			"team":          teamName,
			"identity_type": "bot_or_user",
		},
	}
	res.Nodes = append(res.Nodes, self)

	// Bot scopes: capabilities the token itself grants.
	scopes, err := c.opts.API.BotScopes(ctx)
	if err == nil && len(scopes) > 0 {
		self.Metadata["scopes"] = scopes
		self.Metadata["privilege"] = scopesPrivilege(scopes)
	}

	// Users.
	users, err := c.opts.API.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("slack connector: users.list: %w", err)
	}
	for _, u := range users {
		if u.ID == userID {
			continue // caller already modeled above
		}
		identityType := "user"
		if u.IsBot {
			identityType = "bot"
		}
		res.Nodes = append(res.Nodes, &graph.Node{
			ID:   idIdentity + u.ID,
			Type: graph.NodeIdentity,
			Name: displayName(u),
			Provider: "slack",
			Metadata: map[string]any{
				"user_id":       u.ID,
				"identity_type": identityType,
			},
		})
	}

	// Channels: modeled as DATASET carrying workspace communications.
	channels, err := c.opts.API.ListChannels(ctx)
	if err != nil {
		return nil, fmt.Errorf("slack connector: conversations.list: %w", err)
	}
	if len(channels) > c.opts.MaxChannels {
		channels = channels[:c.opts.MaxChannels]
	}
	for _, ch := range channels {
		criticality := 30
		if strings.Contains(strings.ToLower(ch.Name), "prod") ||
			strings.Contains(strings.ToLower(ch.Name), "incident") {
			criticality = 75
		}
		res.Nodes = append(res.Nodes, &graph.Node{
			ID:          idChannel + ch.ID,
			Type:        graph.NodeDataset,
			Name:        "#" + ch.Name,
			Provider:    "slack",
			Criticality: criticality,
			Metadata: map[string]any{
				"channel_id":    ch.ID,
				"kind":          ch.Kind,
				"classification": "workspace_communications",
			},
		})

		// Membership edges from the caller: read if member, write if the
		// token holds chat:write and is a member.
		if ch.IsMember {
			res.Edges = append(res.Edges, &graph.Edge{
				Source:     self.ID,
				Target:     idChannel + ch.ID,
				Type:       graph.EdgeCanRead,
				Confidence: 1.0,
				Provenance: provenance("conversations.list is_member"),
			})
			if hasScope(scopes, "chat:write") {
				res.Edges = append(res.Edges, &graph.Edge{
					Source:     self.ID,
					Target:     idChannel + ch.ID,
					Type:       graph.EdgeCanWrite,
					Confidence: 1.0,
					Provenance: provenance("chat:write scope + membership"),
				})
			}
		}

		// Member identities gain read edges (they see the channel).
		if !c.opts.SkipMembers {
			for _, memberID := range ch.MemberIDs {
				res.Edges = append(res.Edges, &graph.Edge{
					Source:     idIdentity + memberID,
					Target:     idChannel + ch.ID,
					Type:       graph.EdgeCanRead,
					Confidence: 1.0,
					Provenance: provenance("conversations.members"),
				})
			}
		}
	}
	return res, nil
}

func displayName(u User) string {
	if u.RealName != "" {
		return u.RealName
	}
	return u.Name
}

// scopesPrivilege summarizes token scope power for policy and scoring.
func scopesPrivilege(scopes []string) string {
	if hasScope(scopes, "admin") || hasScope(scopes, "chat:write:admin") {
		return "admin"
	}
	if hasScope(scopes, "chat:write") || hasScope(scopes, "files:write") {
		return "write"
	}
	if len(scopes) > 0 {
		return "read"
	}
	return "none"
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func provenance(sourceObject string) graph.Provenance {
	return graph.Provenance{Connector: "slack", SourceObject: sourceObject}
}

// RestAPI implements API against Slack (slack.com or Enterprise Grid)
// using a bearer token. All calls are read-only metadata reads; message
// content is never requested.
type RestAPI struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewRestAPI builds a REST client. baseURL is e.g. https://slack.com.
func NewRestAPI(baseURL, token string) (*RestAPI, error) {
	if baseURL == "" {
		baseURL = "https://slack.com"
	}
	if token == "" {
		return nil, fmt.Errorf("slack connector: token is required")
	}
	return &RestAPI{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{},
	}, nil
}

type slackResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func (a *RestAPI) get(ctx context.Context, method string, query url.Values, out any) error {
	u := a.baseURL + "/api/" + method
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GET %s: http %d", method, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		OK    bool            `json:"ok"`
		Error string          `json:"error"`
		Raw   json.RawMessage `json:"-"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	if !envelope.OK {
		return fmt.Errorf("slack %s: %s", method, envelope.Error)
	}
	return json.Unmarshal(body, out)
}

// AuthTest implements API.
func (a *RestAPI) AuthTest(ctx context.Context) (string, string, string, string, error) {
	var out struct {
		UserID   string `json:"user_id"`
		User     string `json:"user"`
		TeamID   string `json:"team_id"`
		Team     string `json:"team"`
		IsBot    bool   `json:"is_bot"`
	}
	if err := a.get(ctx, "auth.test", nil, &out); err != nil {
		return "", "", "", "", err
	}
	return out.UserID, out.User, out.TeamID, out.Team, nil
}

// ListChannels implements API (paginates cursors, public + private).
func (a *RestAPI) ListChannels(ctx context.Context) ([]Channel, error) {
	var out []Channel
	cursor := ""
	for {
		q := url.Values{}
		q.Set("types", "public_channel,private_channel,im,mpim")
		q.Set("exclude_archived", "true")
		q.Set("limit", "200")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var raw struct {
			Channels []struct {
				ID       string   `json:"id"`
				Name     string   `json:"name"`
				IsIM     bool     `json:"is_im"`
				IsMPIM   bool     `json:"is_mpim"`
				IsGroup  bool     `json:"is_group"`
				IsMember bool     `json:"is_member"`
				Members  []string `json:"-"`
			} `json:"channels"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := a.get(ctx, "conversations.list", q, &raw); err != nil {
			return nil, err
		}
		for _, ch := range raw.Channels {
			kind := "channel"
			switch {
			case ch.IsMPIM:
				kind = "mpim"
			case ch.IsIM:
				kind = "im"
			case ch.IsGroup:
				kind = "group"
			}
			members, err := a.listMembers(ctx, ch.ID)
			if err != nil {
				// Missing conversations scope: keep the channel, skip membership.
				members = nil
			}
			out = append(out, Channel{
				ID:        ch.ID,
				Name:      channelName(ch.Name, ch.ID),
				Kind:      kind,
				IsMember:  ch.IsMember,
				MemberIDs: members,
			})
		}
		if raw.Meta.NextCursor == "" {
			return out, nil
		}
		cursor = raw.Meta.NextCursor
	}
}

// listMembers pages conversations.members for one channel.
func (a *RestAPI) listMembers(ctx context.Context, channelID string) ([]string, error) {
	var out []string
	cursor := ""
	for {
		q := url.Values{}
		q.Set("channel", channelID)
		q.Set("limit", "1000")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var raw struct {
			Members []string `json:"members"`
			Meta    struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := a.get(ctx, "conversations.members", q, &raw); err != nil {
			return nil, err
		}
		out = append(out, raw.Members...)
		if raw.Meta.NextCursor == "" {
			return out, nil
		}
		cursor = raw.Meta.NextCursor
	}
}

// ListUsers implements API.
func (a *RestAPI) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	cursor := ""
	for {
		q := url.Values{}
		q.Set("limit", "200")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var raw struct {
			Members []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				RealName string `json:"real_name"`
				IsBot    bool   `json:"is_bot"`
				Deleted  bool   `json:"deleted"`
			} `json:"members"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := a.get(ctx, "users.list", q, &raw); err != nil {
			return nil, err
		}
		for _, u := range raw.Members {
			if u.Deleted || u.ID == "" {
				continue
			}
			out = append(out, User{ID: u.ID, Name: u.Name, RealName: u.RealName, IsBot: u.IsBot})
		}
		if raw.Meta.NextCursor == "" {
			return out, nil
		}
		cursor = raw.Meta.NextCursor
	}
}

// BotScopes implements API. Best-effort: many tokens lack the
// permissions.info scope, in which case no scopes are reported and the
// channel CAN_WRITE inference is skipped (read edges still stand).
func (a *RestAPI) BotScopes(ctx context.Context) ([]string, error) {
	var raw struct {
		Info struct {
			AppScopes []struct {
				Scope string `json:"scope"`
			} `json:"app_scopes"`
		} `json:"info"`
	}
	if err := a.get(ctx, "apps.permissions.info", nil, &raw); err != nil {
		return nil, err
	}
	var out []string
	for _, s := range raw.Info.AppScopes {
		if s.Scope != "" {
			out = append(out, s.Scope)
		}
	}
	return out, nil
}

func channelName(name, id string) string {
	if name != "" {
		return name
	}
	return id // DMs carry no name
}
