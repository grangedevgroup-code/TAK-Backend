package server

import (
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestParseArea(t *testing.T) {
	g, err := parseArea(" 34.0, -118.5, 34.3, -118.1 ")
	if err != nil || g == nil || !g.boxes[0].contains(34.1, -118.3) || g.boxes[0].contains(35, -118.3) {
		t.Fatalf("area %v %v", g, err)
	}
	for _, bad := range []string{"1,2,3", "34.3,-118.1,34.0,-118.5", "a,b,c,d", "-95,0,10,10"} {
		if _, err := parseArea(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if g, err := parseArea(""); g != nil || err != nil {
		t.Fatal("empty area should mean no filter")
	}
}

func TestMessageFilters(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.Filters = MessageFilters{DropTypes: []string{"b-m-p-s-p-i", "a-u-*"}, StripDetails: []string{"takv"}}
	})
	rx := dialTCP(t, s)
	rx.send(saXML("filter-rx", "RX", 1, 1))
	tx := dialTCP(t, s)
	time.Sleep(200 * time.Millisecond)

	spi := cot.New("filter-spi", "b-m-p-s-p-i", "h-e", time.Minute)
	spi.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
	tx.send(spi.String())
	unk := cot.New("filter-unknown", "a-u-G", "h-e", time.Minute)
	unk.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
	tx.send(unk.String())
	keep := cot.New("filter-keep", "a-f-G-U-C", "h-e", time.Minute)
	keep.Point = cot.Point{Lat: 1, Lon: 1, Ce: 1, Le: 1}
	keep.Detail.AddNew("takv", "device", "Pixel", "version", "5.4")
	keep.Detail.AddNew("contact", "callsign", "KEEP")
	tx.send(keep.String())

	e := rx.expect(uidIs("filter-keep"), "allowed marker")
	if e.D("takv") != nil {
		t.Fatal("takv was not removed")
	}
	if e.D("contact") == nil {
		t.Fatal("other details were removed")
	}
	rx.expectNone(func(e *cot.Event) bool { return e.UID == "filter-spi" || e.UID == "filter-unknown" }, "dropped types", 500*time.Millisecond)
}

func TestLinkAreaFiltersBothWays(t *testing.T) {
	s := newTestServer(t, nil)
	link := s.relayClient(KindPeer, "area-link", "127.0.0.1:1", nil)
	s.applyLinkArea(link, "10,10,20,20")
	s.hub.Add(link)
	defer s.hub.Remove(link)

	inside := cot.New("area-in", "a-f-G", "h-e", time.Minute)
	inside.Point = cot.Point{Lat: 15, Lon: 15, Ce: 1, Le: 1}
	outside := cot.New("area-out", "a-f-G", "h-e", time.Minute)
	outside.Point = cot.Point{Lat: 50, Lon: 50, Ce: 1, Le: 1}
	s.Publish(inside)
	s.Publish(outside)
	got := map[string]bool{}
	deadline := time.After(time.Second)
loop:
	for {
		select {
		case m := <-link.Out():
			got[m.Event.UID] = true
		case <-deadline:
			break loop
		}
	}
	if !got["area-in"] || got["area-out"] {
		t.Fatalf("outbound to link: %v", got)
	}

	fromLink := NewMessage(outside, link, link.InMask())
	if s.messageFilter(fromLink) {
		t.Fatal("item outside the area accepted from the link")
	}
	fromLink = NewMessage(inside, link, link.InMask())
	if !s.messageFilter(fromLink) {
		t.Fatal("item inside the area refused")
	}
}
