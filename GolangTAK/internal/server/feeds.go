package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

const (
	feetToMeters = 0.3048
	knotsToMS    = 0.514444
)

type FeedStatus struct {
	Name    string    `json:"name"`
	Enabled bool      `json:"enabled"`
	LastRun time.Time `json:"lastRun"`
	LastOK  time.Time `json:"lastOk"`
	Items   int       `json:"items"`
	Error   string    `json:"error,omitempty"`
}

type feedState struct {
	mu     sync.Mutex
	status map[string]*FeedStatus
}

func (f *feedState) set(name string, enabled bool, items int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.status[name]
	if st == nil {
		st = &FeedStatus{Name: name}
		f.status[name] = st
	}
	st.Enabled = enabled
	if !enabled {
		return
	}
	st.LastRun = time.Now().UTC()
	if err != nil {
		st.Error = err.Error()
		return
	}
	st.Error = ""
	st.LastOK = st.LastRun
	st.Items = items
}

func (s *Server) feedStatus() []FeedStatus {
	cfg := s.Config().Feeds
	out := []FeedStatus{}
	for _, name := range []string{"adsb", "ais"} {
		st := FeedStatus{Name: name}
		s.feeds.mu.Lock()
		if cur := s.feeds.status[name]; cur != nil {
			st = *cur
		}
		s.feeds.mu.Unlock()
		switch name {
		case "adsb":
			st.Enabled = cfg.ADSB.Enabled
		case "ais":
			st.Enabled = cfg.AIS.Enabled
		}
		out = append(out, st)
	}
	return out
}

func (s *Server) startFeeds() {
	hc := &http.Client{Timeout: 30 * time.Second}
	run := func(name string, interval func() time.Duration, enabled func() bool, poll func(context.Context, *http.Client) (int, error)) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			var last time.Time
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			failures := 0
			for {
				select {
				case <-s.ctx.Done():
					return
				case <-tick.C:
				}
				if !enabled() {
					s.feeds.set(name, false, 0, nil)
					last = time.Time{}
					failures = 0
					continue
				}
				wait := interval()
				if failures > 0 {
					wait = min(wait*time.Duration(1<<min(failures, 4)), 10*time.Minute)
				}
				if time.Since(last) < wait {
					continue
				}
				last = time.Now()
				ctx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
				n, err := poll(ctx, hc)
				cancel()
				s.feeds.set(name, true, n, err)
				if err != nil {
					failures++
					if failures == 1 || failures%10 == 0 {
						s.log.Warn("data feed failed", "feed", name, "err", err)
					}
					continue
				}
				if failures > 0 {
					s.log.Info("data feed recovered", "feed", name)
				}
				failures = 0
			}
		}()
	}
	run("adsb", func() time.Duration { return time.Duration(s.Config().Feeds.ADSB.IntervalSec) * time.Second },
		func() bool { return s.Config().Feeds.ADSB.Enabled }, s.pollADSB)
	run("ais", func() time.Duration { return time.Duration(s.Config().Feeds.AIS.IntervalSec) * time.Second },
		func() bool { return s.Config().Feeds.AIS.Enabled }, s.pollAIS)
}

func (s *Server) publishFeed(e *cot.Event, group string) {
	m := NewMessage(e, nil, nil)
	m.NoHistory = true
	if group == "" {
		m.Everyone = true
	} else {
		if _, err := s.dir.EnsureGroup(group, "Data feed", false); err != nil {
			return
		}
		m.Groups = s.dir.Mask([]string{group})
	}
	s.hub.Publish(m)
}

func (s *Server) feedGet(ctx context.Context, hc *http.Client, u string, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "GolangTAK/"+s.Version)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("the feed service refused the request (HTTP %d); check the API key, or switch the source URL to another service such as https://api.adsb.lol/v2/point: %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return json.Unmarshal(body, out)
}

type adsbAircraft struct {
	Hex       string          `json:"hex"`
	Flight    string          `json:"flight"`
	Reg       string          `json:"r"`
	Type      string          `json:"t"`
	AltBaro   json.RawMessage `json:"alt_baro"`
	AltGeom   *float64        `json:"alt_geom"`
	Speed     *float64        `json:"gs"`
	Track     *float64        `json:"track"`
	Lat       *float64        `json:"lat"`
	Lon       *float64        `json:"lon"`
	Squawk    string          `json:"squawk"`
	Category  string          `json:"category"`
	Emergency string          `json:"emergency"`
	DBFlags   int             `json:"dbFlags"`
	SeenPos   *float64        `json:"seen_pos"`
}

func (s *Server) pollADSB(ctx context.Context, hc *http.Client) (int, error) {
	f := s.Config().Feeds.ADSB
	u := strings.TrimRight(f.URL, "/") + "/" + strconv.FormatFloat(f.Lat, 'f', 5, 64) + "/" + strconv.FormatFloat(f.Lon, 'f', 5, 64) + "/" + strconv.FormatFloat(f.RadiusNM, 'f', -1, 64)
	hdr := map[string]string{}
	if f.APIKey != "" {
		hdr["api-auth"] = f.APIKey
		hdr["api-key"] = f.APIKey
	}
	var resp struct {
		AC  []adsbAircraft `json:"ac"`
		Msg string         `json:"msg"`
	}
	if err := s.feedGet(ctx, hc, u, hdr, &resp); err != nil {
		return 0, err
	}
	stale := time.Duration(max(f.IntervalSec*3, 90)) * time.Second
	n := 0
	for _, a := range resp.AC {
		e := adsbEvent(a, stale)
		if e == nil {
			continue
		}
		s.publishFeed(e, f.Group)
		n++
	}
	return n, nil
}

func adsbEvent(a adsbAircraft, stale time.Duration) *cot.Event {
	if a.Lat == nil || a.Lon == nil || a.Hex == "" {
		return nil
	}
	if a.SeenPos != nil && *a.SeenPos > 60 {
		return nil
	}
	icao := strings.ToUpper(strings.TrimPrefix(a.Hex, "~"))
	kind := "C"
	if a.DBFlags&1 != 0 {
		kind = "M"
	}
	typ := "a-n-A-" + kind + "-F"
	switch strings.ToUpper(a.Category) {
	case "A7":
		typ = "a-n-A-" + kind + "-H"
	case "B6":
		typ = "a-n-A-M-F-Q"
	case "C1", "C2":
		typ = "a-n-G-E-V"
	}
	e := cot.New("ICAO-"+icao, typ, "m-g", stale)
	hae := cot.Unknown
	if a.AltGeom != nil {
		hae = *a.AltGeom * feetToMeters
	} else if len(a.AltBaro) > 0 {
		var v float64
		if json.Unmarshal(a.AltBaro, &v) == nil {
			hae = v * feetToMeters
		} else {
			hae = 0
		}
	}
	e.Point = cot.Point{Lat: *a.Lat, Lon: *a.Lon, Hae: hae, Ce: cot.Unknown, Le: cot.Unknown}
	flight := strings.TrimSpace(a.Flight)
	callsign := firstNonEmpty(flight, strings.TrimSpace(a.Reg), icao)
	e.Detail.AddNew("contact", "callsign", callsign)
	if a.Track != nil || a.Speed != nil {
		tr := e.Detail.AddNew("track")
		if a.Track != nil {
			tr.SetAttr("course", cot.FormatFloat(*a.Track))
		}
		if a.Speed != nil {
			tr.SetAttr("speed", cot.FormatFloat(*a.Speed*knotsToMS))
		}
	}
	e.Detail.AddNew("_aircot_", "flight", flight, "reg", strings.TrimSpace(a.Reg), "cat", a.Category, "icao", icao, "squawk", a.Squawk, "type", a.Type)
	var parts []string
	if a.Type != "" {
		parts = append(parts, "Type "+a.Type)
	}
	if a.Reg != "" {
		parts = append(parts, "Registration "+strings.TrimSpace(a.Reg))
	}
	if flight != "" {
		parts = append(parts, "Flight "+flight)
	}
	if a.Squawk != "" {
		parts = append(parts, "Squawk "+a.Squawk)
	}
	parts = append(parts, "ICAO "+icao)
	if (a.Emergency != "" && a.Emergency != "none") || a.Squawk == "7500" || a.Squawk == "7600" || a.Squawk == "7700" {
		parts = append([]string{"EMERGENCY " + firstNonEmpty(strings.ToUpper(a.Emergency), "SQUAWK "+a.Squawk)}, parts...)
	}
	if a.DBFlags&1 != 0 {
		parts = append(parts, "Military")
	}
	e.Detail.AddNew("remarks").Text = strings.Join(parts, ", ")
	return e
}

func (s *Server) pollAIS(ctx context.Context, hc *http.Client) (int, error) {
	f := s.Config().Feeds.AIS
	q := url.Values{}
	q.Set("username", f.Username)
	q.Set("format", "1")
	q.Set("output", "json")
	q.Set("compress", "0")
	q.Set("latmin", strconv.FormatFloat(f.South, 'f', -1, 64))
	q.Set("latmax", strconv.FormatFloat(f.North, 'f', -1, 64))
	q.Set("lonmin", strconv.FormatFloat(f.West, 'f', -1, 64))
	q.Set("lonmax", strconv.FormatFloat(f.East, 'f', -1, 64))
	if f.MMSI != "" {
		q.Set("mmsi", f.MMSI)
	}
	if f.IMO != "" {
		q.Set("imo", f.IMO)
	}
	var raw []json.RawMessage
	if err := s.feedGet(ctx, hc, "https://data.aishub.net/ws.php?"+q.Encode(), nil, &raw); err != nil {
		return 0, err
	}
	if len(raw) == 0 {
		return 0, errors.New("empty response")
	}
	var head []struct {
		Error   bool   `json:"ERROR"`
		Message string `json:"ERROR_MESSAGE"`
	}
	if json.Unmarshal(append(append([]byte("["), raw[0]...), ']'), &head) == nil && len(head) > 0 && head[0].Error {
		return 0, errors.New("AISHub: " + firstNonEmpty(head[0].Message, "request refused"))
	}
	if len(raw) < 2 {
		return 0, nil
	}
	var vessels []map[string]any
	if err := json.Unmarshal(raw[1], &vessels); err != nil {
		return 0, err
	}
	stale := time.Duration(max(f.IntervalSec*3, 600)) * time.Second
	n := 0
	for _, v := range vessels {
		if e := aisEvent(v, stale); e != nil {
			s.publishFeed(e, f.Group)
			n++
		}
	}
	return n, nil
}

func anyNum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	}
	return 0, false
}

func anyStr(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(strings.Trim(x, "@"))
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func aisShipType(t int) string {
	switch {
	case t == 30:
		return "a-n-S-X-F"
	case t == 35:
		return "a-n-S-C"
	case t == 36 || t == 37:
		return "a-n-S-X-R"
	case t == 31 || t == 32 || t == 52:
		return "a-n-S-X-M-T-U"
	case t == 51:
		return "a-n-S-X-L"
	case t >= 60 && t <= 69:
		return "a-n-S-X-M-P"
	case t >= 70 && t <= 79:
		return "a-n-S-X-M-C"
	case t >= 80 && t <= 89:
		return "a-n-S-X-M-O"
	}
	return "a-n-S-X"
}

func aisEvent(v map[string]any, stale time.Duration) *cot.Event {
	mmsiF, ok := anyNum(v["MMSI"])
	if !ok || mmsiF <= 0 {
		return nil
	}
	lat, ok1 := anyNum(v["LATITUDE"])
	lon, ok2 := anyNum(v["LONGITUDE"])
	if !ok1 || !ok2 || lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0) {
		return nil
	}
	mmsi := strconv.FormatInt(int64(mmsiF), 10)
	shipType, _ := anyNum(v["TYPE"])
	e := cot.New("MMSI-"+mmsi, aisShipType(int(shipType)), "m-g", stale)
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: 0, Ce: cot.Unknown, Le: cot.Unknown}
	name := anyStr(v["NAME"])
	callsign := anyStr(v["CALLSIGN"])
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(name, callsign, "MMSI "+mmsi))
	tr := e.Detail.AddNew("track")
	if cog, ok := anyNum(v["COG"]); ok && cog >= 0 && cog < 360 {
		tr.SetAttr("course", cot.FormatFloat(cog))
	} else if hd, ok := anyNum(v["HEADING"]); ok && hd >= 0 && hd < 360 {
		tr.SetAttr("course", cot.FormatFloat(hd))
	}
	if sog, ok := anyNum(v["SOG"]); ok && sog >= 0 && sog < 102.2 {
		tr.SetAttr("speed", cot.FormatFloat(sog*knotsToMS))
	}
	parts := []string{"MMSI " + mmsi}
	if imo, ok := anyNum(v["IMO"]); ok && imo > 0 {
		parts = append(parts, "IMO "+strconv.FormatInt(int64(imo), 10))
	}
	if callsign != "" {
		parts = append(parts, "Call sign "+callsign)
	}
	if dest := anyStr(v["DEST"]); dest != "" {
		parts = append(parts, "Destination "+dest)
	}
	if shipType > 0 {
		parts = append(parts, "Ship type "+strconv.Itoa(int(shipType)))
	}
	e.Detail.AddNew("remarks").Text = strings.Join(parts, ", ")
	return e
}
