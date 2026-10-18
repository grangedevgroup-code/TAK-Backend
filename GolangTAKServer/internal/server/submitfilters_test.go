package server

import (
	"fmt"
	"testing"
	"time"
)

func cotXML(uid, how string, lat float64, stale time.Time, version string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	v := ""
	if version != "" {
		v = ` version="` + version + `"`
	}
	h := ""
	if how != "" {
		h = ` how="` + how + `"`
	}
	return fmt.Sprintf(`<event%s uid="%s" type="a-f-G-U-C"%s time="%s" start="%s" stale="%s"><point lat="%g" lon="1" hae="0" ce="9" le="9"/><detail><contact callsign="%s"/></detail></event>`,
		v, uid, h, now, now, stale.UTC().Format(time.RFC3339), lat, uid)
}

func TestIgnoreStaleAndValidateCoT(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.Filters.IgnoreStale = true
		c.Filters.ValidateCoT = true
	})
	a, b := dialTCP(t, s), dialTCP(t, s)
	time.Sleep(150 * time.Millisecond)
	future := time.Now().Add(time.Minute)
	a.send(cotXML("STALE", "m-g", 1, time.Now().Add(-time.Minute), "2.0"))
	a.send(cotXML("NOHOW", "", 1, future, "2.0"))
	a.send(cotXML("NOVERSION", "m-g", 1, future, ""))
	a.send(cotXML("BADLAT", "m-g", 95, future, "2.0"))
	a.send(cotXML("GOOD", "m-g", 1, future, "2.0"))
	b.expect(uidIs("GOOD"), "valid, current event")
	for _, uid := range []string{"STALE", "NOHOW", "NOVERSION", "BADLAT"} {
		b.expectNone(uidIs(uid), uid+" passed the submission filters", 300*time.Millisecond)
	}
	if _, err := s.UpdateConfig(func(c *Config) error { c.Filters.IgnoreStale, c.Filters.ValidateCoT = false, false; return nil }); err != nil {
		t.Fatal(err)
	}
	a.send(cotXML("NOHOW2", "", 1, future, "2.0"))
	b.expect(uidIs("NOHOW2"), "event without how once validation is off")
}
