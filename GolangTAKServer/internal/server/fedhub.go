package server

import (
	"path"
	"strings"
)

type HubRule struct {
	From  string   `json:"from"`
	To    string   `json:"to"`
	Types []string `json:"types,omitempty"`
}

type FederationHubConfig struct {
	Enabled    bool      `json:"enabled"`
	BrokerOnly bool      `json:"brokerOnly,omitempty"`
	Rules      []HubRule `json:"rules,omitempty"`
}

func isLinkKind(kind string) bool { return kind == KindFederation || kind == KindPeer }

func linkNameMatches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	name = strings.ToLower(name)
	if pattern == "" || pattern == "*" {
		return true
	}
	if ok, _ := path.Match(pattern, name); ok {
		return true
	}
	cn, _, _ := strings.Cut(name, " (")
	if ok, _ := path.Match(pattern, cn); ok {
		return true
	}
	return pattern == cn || strings.TrimPrefix(name, "link-") == pattern
}

func (h *Hub) fedHubAllows(m *Message, target *Client) bool {
	cfg := h.fedHub.Load()
	if cfg == nil || !cfg.Enabled || m.Source == nil || !isLinkKind(m.Source.Kind) {
		return true
	}
	if !isLinkKind(target.Kind) {
		return !cfg.BrokerOnly
	}
	for _, r := range cfg.Rules {
		if !linkNameMatches(r.From, m.Source.Name) || !linkNameMatches(r.To, target.Name) {
			continue
		}
		if len(r.Types) > 0 && !typeMatches(m.Event.Type, r.Types) {
			continue
		}
		return true
	}
	return false
}
