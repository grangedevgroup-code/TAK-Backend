package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	hubNodeCA       = "ca"
	hubNodeToken    = "token"
	hubNodeOutgoing = "outgoing"
	hubNodeFederate = "federate"
)

type HubToken struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Expires int64     `json:"expires,omitempty"`
}

type HubNode struct {
	ID                string     `json:"id"`
	Type              string     `json:"type"`
	Name              string     `json:"name,omitempty"`
	CAFingerprint     string     `json:"caFingerprint,omitempty"`
	Federate          string     `json:"federate,omitempty"`
	Interconnected    bool       `json:"interconnected,omitempty"`
	AllowTokenAuth    bool       `json:"allowTokenAuth,omitempty"`
	TokenAuthDuration int64      `json:"tokenAuthDuration,omitempty"`
	Tokens            []HubToken `json:"tokens,omitempty"`
}

type HubEdge struct {
	From                string   `json:"from"`
	To                  string   `json:"to"`
	Filter              string   `json:"filter,omitempty"`
	AllowedGroups       []string `json:"allowedGroups,omitempty"`
	DisallowedGroups    []string `json:"disallowedGroups,omitempty"`
	AllowedGroupSets    []string `json:"allowedGroupSets,omitempty"`
	DisallowedGroupSets []string `json:"disallowedGroupSets,omitempty"`
	Types               []string `json:"types,omitempty"`
}

func (c FederationHubConfig) graph() bool { return c.Enabled && len(c.Nodes) > 0 }

func (c FederationHubConfig) node(id string) (HubNode, int) {
	for i, n := range c.Nodes {
		if n.ID == id {
			return n, i
		}
	}
	return HubNode{}, -1
}

func hubNodeMatches(n HubNode, p *fedPolicy, name string) bool {
	switch n.Type {
	case hubNodeCA:
		return p != nil && p.caFP != "" && normFingerprint(n.CAFingerprint) == p.caFP
	case hubNodeToken:
		return p != nil && p.tokenGroup != "" && p.tokenGroup == n.ID
	case hubNodeOutgoing, hubNodeFederate:
		if n.Federate == "" {
			return false
		}
		if p != nil && p.id != "" && normFingerprint(n.Federate) == p.id {
			return true
		}
		if p != nil && p.name != "" && linkNameMatches(n.Federate, p.name) {
			return true
		}
		return linkNameMatches(n.Federate, name)
	}
	return false
}

func (c FederationHubConfig) nodesFor(p *fedPolicy, name string) []string {
	var out []string
	for _, n := range c.Nodes {
		if hubNodeMatches(n, p, name) {
			out = append(out, n.ID)
		}
	}
	return out
}

func expandGroups(groups, sets []string, defs map[string][]string) []string {
	out := slices.Clone(groups)
	for _, s := range sets {
		out = append(out, defs[s]...)
	}
	return out
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func (e HubEdge) passes(groups []string, defs map[string][]string) bool {
	allowed := expandGroups(e.AllowedGroups, e.AllowedGroupSets, defs)
	disallowed := expandGroups(e.DisallowedGroups, e.DisallowedGroupSets, defs)
	switch strings.ToLower(strings.TrimSpace(e.Filter)) {
	case "allowed":
		return intersects(groups, allowed)
	case "disallowed":
		return !intersects(groups, disallowed)
	case "both", "allowedanddisallowed":
		return intersects(groups, allowed) && !intersects(groups, disallowed)
	}
	return true
}

func validHubFilter(f string) bool {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "", "all", "allowall", "allowed", "disallowed", "both", "allowedanddisallowed":
		return true
	}
	return false
}

func (h *Hub) messageGroupNames(m *Message) []string {
	m.hubOnce.Do(func() {
		if m.Everyone {
			m.hubGroups = []string{"__ANON__"}
			return
		}
		if h.srv != nil && h.srv.dir != nil {
			m.hubGroups = h.srv.dir.Names(m.Groups)
		}
	})
	return m.hubGroups
}

func (h *Hub) hubGraphAllows(cfg *FederationHubConfig, m *Message, target *Client) bool {
	src := cfg.nodesFor(m.Source.fedPol(), m.Source.Name)
	if len(src) == 0 {
		return false
	}
	dst := cfg.nodesFor(target.fedPol(), target.Name)
	if len(dst) == 0 {
		return false
	}
	for _, id := range src {
		if n, i := cfg.node(id); i >= 0 && n.Interconnected && slices.Contains(dst, id) {
			return true
		}
	}
	for _, e := range cfg.Edges {
		if !slices.Contains(src, e.From) || !slices.Contains(dst, e.To) {
			continue
		}
		if len(e.Types) > 0 && !typeMatches(m.Event.Type, e.Types) {
			continue
		}
		if e.passes(h.messageGroupNames(m), cfg.GroupSets) {
			return true
		}
	}
	return false
}

func (s *Server) hubDenies(p *fedPolicy, name string) bool {
	cfg := s.Config().FederationHub
	if !cfg.graph() || !cfg.DenyUnlisted {
		return false
	}
	if len(cfg.nodesFor(p, name)) > 0 {
		return false
	}
	s.log.Warn("federation hub refused a federate that is not in the policy", "federate", name)
	return true
}

func (s *Server) hubTokenAllowed(c fedTokenClaims) bool {
	cfg := s.Config().FederationHub
	if !cfg.Enabled {
		return false
	}
	if c.Group != "" {
		n, i := cfg.node(c.Group)
		if i < 0 || n.Type != hubNodeToken {
			return false
		}
		for _, t := range n.Tokens {
			if t.ID == c.Jti && (t.Expires == 0 || time.Now().Unix() < t.Expires) {
				return true
			}
		}
		return false
	}
	_, ok := s.hubCANode(c.CAFingerprint)
	return ok
}

func (s *Server) hubCANode(caFP string) (HubNode, bool) {
	cfg := s.Config().FederationHub
	fp := normFingerprint(caFP)
	if !cfg.Enabled || fp == "" {
		return HubNode{}, false
	}
	for _, n := range cfg.Nodes {
		if n.Type == hubNodeCA && n.AllowTokenAuth && normFingerprint(n.CAFingerprint) == fp {
			return n, true
		}
	}
	return HubNode{}, false
}

func validateHubPolicy(c *FederationHubConfig) error {
	ids := map[string]bool{}
	for i := range c.Nodes {
		n := &c.Nodes[i]
		n.ID = strings.TrimSpace(n.ID)
		if n.ID == "" {
			n.ID = NewSecret(8)
		}
		if ids[n.ID] {
			return fmt.Errorf("federation hub node id %q is used twice", n.ID)
		}
		ids[n.ID] = true
		switch n.Type {
		case hubNodeCA:
			if normFingerprint(n.CAFingerprint) == "" {
				return fmt.Errorf("federation hub CA node %s needs a CA fingerprint", firstNonEmpty(n.Name, n.ID))
			}
		case hubNodeOutgoing, hubNodeFederate:
			if strings.TrimSpace(n.Federate) == "" {
				return fmt.Errorf("federation hub node %s needs a federate name or certificate fingerprint", firstNonEmpty(n.Name, n.ID))
			}
		case hubNodeToken:
		default:
			return fmt.Errorf("federation hub node %s has unknown type %q; use ca, token, outgoing or federate", firstNonEmpty(n.Name, n.ID), n.Type)
		}
	}
	for _, e := range c.Edges {
		if !ids[e.From] || !ids[e.To] {
			return fmt.Errorf("federation hub rule %s -> %s refers to a node that does not exist", e.From, e.To)
		}
		if !validHubFilter(e.Filter) {
			return fmt.Errorf("federation hub rule %s -> %s has unknown filter %q; use all, allowed, disallowed or both", e.From, e.To, e.Filter)
		}
		for _, gs := range append(slices.Clone(e.AllowedGroupSets), e.DisallowedGroupSets...) {
			if _, ok := c.GroupSets[gs]; !ok {
				return fmt.Errorf("federation hub rule %s -> %s uses unknown group set %q", e.From, e.To, gs)
			}
		}
	}
	return nil
}

func cloneHubConfig(c FederationHubConfig) FederationHubConfig {
	b, _ := json.Marshal(c)
	var out FederationHubConfig
	json.Unmarshal(b, &out)
	return out
}

func (s *Server) apiFedHubPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config().FederationHub
	if cfg.Nodes == nil {
		cfg.Nodes = []HubNode{}
	}
	if cfg.Edges == nil {
		cfg.Edges = []HubEdge{}
	}
	if cfg.GroupSets == nil {
		cfg.GroupSets = map[string][]string{}
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) apiFedHubPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	var in FederationHubConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil {
		apiError(w, http.StatusBadRequest, errors.New("send the federation hub policy as JSON"))
		return
	}
	next, err := s.UpdateConfig(func(c *Config) error {
		old := c.FederationHub
		for i := range in.Nodes {
			if in.Nodes[i].Tokens == nil {
				if n, j := old.node(in.Nodes[i].ID); j >= 0 {
					in.Nodes[i].Tokens = n.Tokens
				}
			}
		}
		if err := validateHubPolicy(&in); err != nil {
			return err
		}
		c.FederationHub = in
		return nil
	})
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("federation hub policy updated", "by", identityOf(r).Name, "nodes", len(next.FederationHub.Nodes), "rules", len(next.FederationHub.Edges))
	s.enforceHubAdmission()
	writeJSON(w, http.StatusOK, next.FederationHub)
}

func (s *Server) enforceHubAdmission() {
	for _, c := range s.hub.Clients() {
		if c.Kind != KindFederation {
			continue
		}
		p := c.fedPol()
		if p == nil || p.outbound {
			continue
		}
		if s.hubDenies(p, c.Name) {
			c.Close()
		}
	}
}

type hubTokenRequest struct {
	Name    string `json:"name"`
	Expires int64  `json:"expiration"`
}

func (s *Server) apiFedHubTokenCreate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req hubTokenRequest
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		apiError(w, http.StatusBadRequest, errors.New("give the token a name"))
		return
	}
	tok := HubToken{ID: NewSecret(16), Name: req.Name, Created: time.Now().UTC().Truncate(time.Second)}
	if req.Expires > 0 {
		tok.Expires = time.Now().Add(time.Duration(req.Expires) * time.Second).Unix()
	}
	var node HubNode
	_, err := s.UpdateConfig(func(c *Config) error {
		n, i := c.FederationHub.node(id)
		if i < 0 || n.Type != hubNodeToken {
			return errors.New("no token group with that id")
		}
		hub := cloneHubConfig(c.FederationHub)
		hub.Nodes[i].Tokens = append(hub.Nodes[i].Tokens, tok)
		c.FederationHub = hub
		node = hub.Nodes[i]
		return nil
	})
	if err != nil {
		apiError(w, http.StatusNotFound, err)
		return
	}
	claims := fedTokenClaims{Name: firstNonEmpty(node.Name, node.ID) + ": " + tok.Name, Group: node.ID, Jti: tok.ID, Exp: tok.Expires}
	s.log.Info("federation hub token generated", "group", firstNonEmpty(node.Name, node.ID), "token", tok.Name, "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, map[string]any{"token": s.signFedToken(claims), "id": tok.ID, "name": tok.Name, "expires": tok.Expires})
}

func (s *Server) apiFedHubTokenDelete(w http.ResponseWriter, r *http.Request) {
	id, tid := r.PathValue("id"), r.PathValue("token")
	_, err := s.UpdateConfig(func(c *Config) error {
		n, i := c.FederationHub.node(id)
		if i < 0 || n.Type != hubNodeToken {
			return errors.New("no token group with that id")
		}
		hub := cloneHubConfig(c.FederationHub)
		before := len(hub.Nodes[i].Tokens)
		hub.Nodes[i].Tokens = slices.DeleteFunc(hub.Nodes[i].Tokens, func(t HubToken) bool { return t.ID == tid })
		if len(hub.Nodes[i].Tokens) == before {
			return errors.New("no token with that id")
		}
		c.FederationHub = hub
		return nil
	})
	if err != nil {
		apiError(w, http.StatusNotFound, err)
		return
	}
	for _, c := range s.hub.Clients() {
		if p := c.fedPol(); p != nil && p.tokenGroup == id && p.tokenID == tid {
			c.Close()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) apiFedHubConnections(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config().FederationHub
	out := []map[string]any{}
	for _, c := range s.hub.Clients() {
		if !isLinkKind(c.Kind) {
			continue
		}
		p := c.fedPol()
		nodes := cfg.nodesFor(p, c.Name)
		if nodes == nil {
			nodes = []string{}
		}
		m := map[string]any{"name": c.Name, "kind": c.Kind, "remote": c.Remote, "nodes": nodes}
		if p != nil {
			m["certificateFingerprint"], m["caFingerprint"] = p.id, p.caFP
			if p.outbound {
				m["direction"] = "outbound"
			} else {
				m["direction"] = "inbound"
			}
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiFedHubGroups(w http.ResponseWriter, r *http.Request) {
	seen := map[string]bool{}
	for _, g := range s.dir.Groups() {
		seen[g.Name] = true
	}
	for _, f := range s.Config().Federation.Federates {
		if v, ok := s.fedSeen.Get(f.ID); ok {
			for _, g := range v.RemoteGroups {
				seen[g] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) fedHubRoutes(a func(string, http.HandlerFunc)) {
	a("GET /api/fedhub/policy", s.apiFedHubPolicy)
	a("PUT /api/fedhub/policy", s.apiFedHubPolicyUpdate)
	a("GET /api/fedhub/connections", s.apiFedHubConnections)
	a("GET /api/fedhub/groups", s.apiFedHubGroups)
	a("POST /api/fedhub/nodes/{id}/tokens", s.apiFedHubTokenCreate)
	a("DELETE /api/fedhub/nodes/{id}/tokens/{token}", s.apiFedHubTokenDelete)
}
