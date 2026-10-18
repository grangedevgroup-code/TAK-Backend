package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestSettingsHideOAuthSecretAndPeerTokens(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.OAuth = OAuthConfig{Enabled: false, ClientID: "tak", ClientSecret: "oidc-secret-value"}
		c.Peers = []PeerConfig{{Name: "partner", URL: "fed2://partner.example:9001", Token: "peer-token-value"}}
	})
	admin := adminHeaders(t, s)
	st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/settings"), nil, admin)
	if st != http.StatusOK {
		t.Fatalf("settings %d", st)
	}
	if strings.Contains(string(b), "oidc-secret-value") || strings.Contains(string(b), "peer-token-value") {
		t.Fatal("settings returned a secret")
	}
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/settings"), strings.NewReader(`{"oauth":{"clientSecret":"********","clientId":"tak2"},"peers":[{"name":"partner","url":"fed2://partner.example:9001","token":"********"}]}`), admin); st != http.StatusOK {
		t.Fatalf("update %d %s", st, b)
	}
	cfg := s.Config()
	if cfg.OAuth.ClientSecret != "oidc-secret-value" || cfg.OAuth.ClientID != "tak2" {
		t.Fatalf("oauth after masked update: %+v", cfg.OAuth)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Token != "peer-token-value" {
		t.Fatalf("peer token after masked update: %+v", cfg.Peers)
	}
}
