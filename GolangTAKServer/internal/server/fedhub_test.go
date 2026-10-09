package server

import (
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func drain(c *Client, wait time.Duration) map[string]bool {
	got := map[string]bool{}
	deadline := time.After(wait)
	for {
		select {
		case m := <-c.Out():
			got[m.Event.UID] = true
		case <-deadline:
			return got
		}
	}
}

func TestFederationHubPolicy(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.FederationHub = FederationHubConfig{Enabled: true, BrokerOnly: true, Rules: []HubRule{
			{From: "alpha", To: "bravo", Types: []string{"a-*"}},
			{From: "bravo", To: "*"},
		}}
	})
	mk := func(name string) *Client {
		c := s.relayClient(KindFederation, name, "127.0.0.1:1", nil)
		s.hub.Add(c)
		t.Cleanup(func() { s.hub.Remove(c) })
		return c
	}
	alpha, bravo, charlie := mk("alpha (Partner CA)"), mk("bravo"), mk("charlie")
	local := dialTCP(t, s)
	local.send(saXML("hub-local", "LOCAL", 1, 1))
	time.Sleep(200 * time.Millisecond)
	drain(alpha, 100*time.Millisecond)
	drain(bravo, 100*time.Millisecond)
	drain(charlie, 100*time.Millisecond)

	pos := cot.New("hub-alpha-pos", "a-f-G-U-C", "h-e", time.Minute)
	pos.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
	s.hub.Publish(NewMessage(pos, alpha, alpha.InMask()))
	spot := cot.New("hub-alpha-spot", "b-m-p-s-m", "h-e", time.Minute)
	spot.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
	s.hub.Publish(NewMessage(spot, alpha, alpha.InMask()))
	fromBravo := cot.New("hub-bravo-pos", "a-f-G-U-C", "h-e", time.Minute)
	fromBravo.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
	s.hub.Publish(NewMessage(fromBravo, bravo, bravo.InMask()))

	b := drain(bravo, 300*time.Millisecond)
	if !b["hub-alpha-pos"] || b["hub-alpha-spot"] {
		t.Fatalf("bravo got %v", b)
	}
	c := drain(charlie, 300*time.Millisecond)
	if c["hub-alpha-pos"] || !c["hub-bravo-pos"] {
		t.Fatalf("charlie got %v", c)
	}
	a := drain(alpha, 300*time.Millisecond)
	if !a["hub-bravo-pos"] {
		t.Fatalf("alpha got %v", a)
	}
	local.expectNone(func(e *cot.Event) bool { return e.UID == "hub-alpha-pos" || e.UID == "hub-bravo-pos" }, "federated traffic in broker-only mode", 300*time.Millisecond)

	local.send(saXML("hub-local-2", "LOCAL", 2, 2))
	for _, l := range []*Client{alpha, bravo, charlie} {
		if got := drain(l, 300*time.Millisecond); !got["hub-local-2"] {
			t.Fatalf("%s did not get local traffic: %v", l.Name, got)
		}
	}

	if !linkNameMatches("alpha*", "alpha-2 (CA)") || linkNameMatches("bravo", "charlie") || !linkNameMatches("ALPHA", "alpha (Partner CA)") {
		t.Fatal("name matching")
	}
}
