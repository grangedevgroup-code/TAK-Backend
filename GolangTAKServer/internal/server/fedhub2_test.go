package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestFederationHubPolicyGraph(t *testing.T) {
	fpA, fpB, fpX := strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("cc", 32)
	s := newTestServer(t, func(c *Config) {
		c.FederationHub = FederationHubConfig{Enabled: true, DenyUnlisted: true,
			Nodes: []HubNode{
				{ID: "caA", Type: hubNodeCA, Name: "Alpha CA", CAFingerprint: fpA, Interconnected: true},
				{ID: "caB", Type: hubNodeCA, Name: "Bravo CA", CAFingerprint: fpB},
				{ID: "tok", Type: hubNodeToken, Name: "Partners"},
				{ID: "fed", Type: hubNodeFederate, Federate: "charlie*"},
			},
			Edges: []HubEdge{
				{From: "caA", To: "caB", Filter: "allowed", AllowedGroups: []string{"Red"}},
				{From: "caB", To: "fed"},
				{From: "tok", To: "caA", Filter: "disallowed", DisallowedGroupSets: []string{"secret"}},
			},
			GroupSets: map[string][]string{"secret": {"Blue"}},
		}
	})
	s.dir.EnsureGroup("Red", "", false)
	s.dir.EnsureGroup("Blue", "", false)
	mk := func(name string, p *fedPolicy) *Client {
		p.name, p.in, p.out = name, []string{"Red", "Blue"}, []string{"Red", "Blue"}
		c := s.fedClient(KindFederation, name, "127.0.0.1:1", p)
		s.hub.Add(c)
		t.Cleanup(func() { s.hub.Remove(c) })
		return c
	}
	a1 := mk("alpha-1 (Alpha CA)", &fedPolicy{caFP: fpA})
	a2 := mk("alpha-2 (Alpha CA)", &fedPolicy{caFP: fpA})
	b1 := mk("bravo-1 (Bravo CA)", &fedPolicy{caFP: fpB})
	c1 := mk("charlie-1", &fedPolicy{})
	t1 := mk("Partners: west", &fedPolicy{tokenGroup: "tok", tokenID: "t1"})
	time.Sleep(150 * time.Millisecond)
	for _, c := range []*Client{a1, a2, b1, c1, t1} {
		drain(c, 50*time.Millisecond)
	}
	send := func(uid string, from *Client, groups ...string) {
		ev := cot.New(uid, "a-f-G-U-C", "h-e", time.Minute)
		ev.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
		s.hub.Publish(NewMessage(ev, from, s.dir.Mask(groups)))
	}
	send("a-red", a1, "Red")
	send("a-blue", a1, "Blue")
	send("b-any", b1, "Blue")
	send("t-red", t1, "Red")
	send("t-blue", t1, "Blue")
	got := map[string]map[string]bool{}
	for name, c := range map[string]*Client{"a1": a1, "a2": a2, "b1": b1, "c1": c1, "t1": t1} {
		got[name] = drain(c, 400*time.Millisecond)
	}
	want := map[string]map[string]bool{
		"a1": {"t-red": true},
		"a2": {"a-red": true, "a-blue": true, "t-red": true},
		"b1": {"a-red": true},
		"c1": {"b-any": true},
		"t1": {},
	}
	for name, w := range want {
		for _, uid := range []string{"a-red", "a-blue", "b-any", "t-red", "t-blue"} {
			if got[name][uid] != w[uid] {
				t.Errorf("%s received %s = %v, want %v (got %v)", name, uid, got[name][uid], w[uid], got[name])
			}
		}
	}
	if !s.hubDenies(&fedPolicy{caFP: fpX, name: "x"}, "xray (Unknown CA)") {
		t.Error("federate outside the policy admitted")
	}
	if s.hubDenies(&fedPolicy{caFP: fpA}, "alpha-3") || s.hubDenies(&fedPolicy{tokenGroup: "tok"}, "tok") || s.hubDenies(&fedPolicy{}, "charlie-9") {
		t.Error("listed federate refused")
	}

	admin := adminHeaders(t, s)
	st, b := doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/fedhub/nodes/tok/tokens"), strings.NewReader(`{"name":"west","expiration":3600}`), admin)
	if st != http.StatusOK {
		t.Fatalf("token %d %s", st, b)
	}
	var tok struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	json.Unmarshal(b, &tok)
	claims, err := s.parseFedToken(tok.Token)
	if err != nil || claims.Group != "tok" || claims.Jti != tok.ID {
		t.Fatalf("claims %+v %v", claims, err)
	}
	if err := s.fedTokenAllowed(claims); err != nil {
		t.Fatalf("fresh hub token refused: %v", err)
	}
	if st, b := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/api/fedhub/nodes/tok/tokens/"+tok.ID), nil, admin); st != http.StatusOK {
		t.Fatalf("delete token %d %s", st, b)
	}
	if err := s.fedTokenAllowed(claims); err == nil {
		t.Fatal("revoked hub token accepted")
	}
	forged := claims
	forged.Group = "caA"
	if err := s.fedTokenAllowed(forged); err == nil {
		t.Fatal("token for a non-token node accepted")
	}

	st, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/fedhub/connections"), nil, admin)
	if st != http.StatusOK || !strings.Contains(string(b), `"nodes":["caA"]`) || !strings.Contains(string(b), `"nodes":["fed"]`) {
		t.Fatalf("connections %d %s", st, b)
	}
	for _, bad := range []string{
		`{"enabled":true,"nodes":[{"id":"n1","type":"ca"}]}`,
		`{"enabled":true,"nodes":[{"id":"n1","type":"token"}],"edges":[{"from":"n1","to":"nope"}]}`,
		`{"enabled":true,"nodes":[{"id":"n1","type":"token"}],"edges":[{"from":"n1","to":"n1","filter":"maybe"}]}`,
		`{"enabled":true,"nodes":[{"id":"n1","type":"token"}],"edges":[{"from":"n1","to":"n1","filter":"allowed","allowedGroupSets":["missing"]}]}`,
		`{"enabled":true,"nodes":[{"id":"n1","type":"spaceship"}]}`,
	} {
		if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/fedhub/policy"), strings.NewReader(bad), admin); st != http.StatusBadRequest {
			t.Errorf("invalid policy %s accepted: %d %s", bad, st, b)
		}
	}
	keep := s.Config().FederationHub
	keep.DenyUnlisted = false
	body, _ := json.Marshal(keep)
	if st, b := doReq(t, http.DefaultClient, "PUT", plainURL(s, "/api/fedhub/policy"), strings.NewReader(string(body)), admin); st != http.StatusOK {
		t.Fatalf("policy update %d %s", st, b)
	}
	if s.Config().FederationHub.DenyUnlisted || len(s.Config().FederationHub.Nodes) != 4 {
		t.Fatalf("policy not saved: %+v", s.Config().FederationHub)
	}
}
