package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

var inputFeedDefaults = map[string]int{"sbs": 30003, "ais": 10110, "osmand": 5055}

func (s *Server) startInputFeed(f DataFeedConfig) (bool, error) {
	proto := strings.ToLower(f.Protocol)
	switch proto {
	case "sbs", "ais", "osmand":
		if f.Port == 0 {
			f.Port = inputFeedDefaults[proto]
		}
		if f.Port < 0 || f.Port > 65535 {
			return true, fmt.Errorf("port %d is not valid", f.Port)
		}
	case "dump1090", "traccar":
		u, err := url.Parse(f.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return true, fmt.Errorf("%s feeds need an http or https URL", proto)
		}
	default:
		return false, nil
	}
	switch proto {
	case "sbs":
		if f.Address == "" {
			return true, errors.New("enter the address of the dump1090 or readsb receiver")
		}
		target := net.JoinHostPort(f.Address, strconv.Itoa(f.Port))
		c := s.feedClient(f, target)
		s.feedDialLoop(f, c, target, func(r io.Reader) error { return s.readSBS(f, c, r, target) })
	case "ais":
		dec := newAISDecoder()
		if f.Address != "" {
			target := net.JoinHostPort(f.Address, strconv.Itoa(f.Port))
			c := s.feedClient(f, target)
			s.feedDialLoop(f, c, target, func(r io.Reader) error {
				sc := bufio.NewScanner(r)
				sc.Buffer(make([]byte, 4096), 4096)
				for sc.Scan() {
					s.aisLine(f, c, dec, sc.Text(), target)
				}
				return sc.Err()
			})
			return true, nil
		}
		addr := s.addr(f.Port)
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return true, portError("udp", addr, err)
		}
		s.track(pc)
		c := s.feedClient(f, addr)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.hub.Remove(c)
			buf := make([]byte, 65536)
			last := time.Now()
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
						return
					}
					continue
				}
				for _, line := range strings.Split(string(buf[:n]), "\n") {
					s.aisLine(f, c, dec, line, from.String())
				}
				if time.Since(last) > time.Minute {
					last = time.Now()
					dec.mu.Lock()
					dec.expire(time.Hour)
					dec.mu.Unlock()
				}
			}
		}()
	case "osmand":
		ln, err := s.listenTCP(f.Port)
		if err != nil {
			return true, err
		}
		c := s.feedClient(f, s.addr(f.Port))
		hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.osmandReport(f, c, w, r) }), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.hub.Remove(c)
			go func() {
				<-s.ctx.Done()
				hs.Close()
			}()
			hs.Serve(ln)
		}()
	case "dump1090", "traccar":
		c := s.feedClient(f, f.URL)
		poll := s.pollDump1090
		every := 2
		if proto == "traccar" {
			poll, every = s.pollTraccar, 10
		}
		if f.Interval > 0 {
			every = f.Interval
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.hub.Remove(c)
			hc := &http.Client{Timeout: 20 * time.Second}
			failures := 0
			for {
				ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
				err := poll(ctx, hc, f, c)
				cancel()
				if s.ctx.Err() != nil {
					return
				}
				wait := time.Duration(every) * time.Second
				if err != nil {
					failures++
					s.dfeeds.setError(f.UUID, err.Error())
					if failures == 1 || failures%20 == 0 {
						s.log.Warn("data feed poll failed", "feed", f.Name, "err", err)
					}
					wait = min(wait*time.Duration(1<<min(failures, 5)), 5*time.Minute)
				} else {
					if failures > 0 {
						s.dfeeds.setError(f.UUID, "")
					}
					failures = 0
				}
				select {
				case <-s.ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}()
	}
	return true, nil
}

func (s *Server) feedDialLoop(f DataFeedConfig, c *Client, target string, read func(io.Reader) error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.hub.Remove(c)
		delay := time.Second
		for {
			d := net.Dialer{Timeout: 10 * time.Second}
			conn, err := d.DialContext(s.ctx, "tcp", target)
			if err == nil {
				s.dfeeds.setError(f.UUID, "")
				delay = time.Second
				stop := context.AfterFunc(s.ctx, func() { conn.Close() })
				err = read(&idleReader{conn: conn, idle: 2 * time.Minute})
				stop()
				conn.Close()
				if err == nil {
					err = errors.New("the receiver closed the connection")
				}
			}
			if s.ctx.Err() != nil {
				return
			}
			s.dfeeds.setError(f.UUID, "connecting to "+target+": "+err.Error())
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, time.Minute)
		}
	}()
}

type idleReader struct {
	conn net.Conn
	idle time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	r.conn.SetReadDeadline(time.Now().Add(r.idle))
	return r.conn.Read(p)
}

func (s *Server) aisLine(f DataFeedConfig, c *Client, dec *aisDecoder, line, from string) {
	v := dec.Line(line)
	if v == nil {
		return
	}
	if e := aisEvent(v, 10*time.Minute); e != nil {
		c.touch()
		s.ingestFeed(c, f, e, from)
	}
}

type sbsTrack struct {
	a       adsbAircraft
	posAt   time.Time
	sentAt  time.Time
	touched time.Time
}

type sbsState struct {
	mu     sync.Mutex
	tracks map[string]*sbsTrack
}

func sbsFloat(v string) *float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return &f
}

func (st *sbsState) line(line string, now time.Time) *adsbAircraft {
	fs := strings.Split(strings.TrimSpace(line), ",")
	if len(fs) < 11 || fs[0] != "MSG" {
		return nil
	}
	hex := strings.ToLower(strings.TrimSpace(fs[4]))
	if len(hex) < 6 {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	t := st.tracks[hex]
	if t == nil {
		if len(st.tracks) > 5000 {
			for k, x := range st.tracks {
				if now.Sub(x.touched) > 5*time.Minute {
					delete(st.tracks, k)
				}
			}
		}
		t = &sbsTrack{a: adsbAircraft{Hex: hex}}
		st.tracks[hex] = t
	}
	t.touched = now
	get := func(i int) string {
		if i < len(fs) {
			return strings.TrimSpace(fs[i])
		}
		return ""
	}
	if v := get(10); v != "" {
		t.a.Flight = v
	}
	if v := get(11); v != "" {
		t.a.AltBaro = json.RawMessage(v)
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			t.a.AltBaro = nil
		}
	}
	if v := sbsFloat(get(12)); v != nil {
		t.a.Speed = v
	}
	if v := sbsFloat(get(13)); v != nil {
		t.a.Track = v
	}
	lat, lon := sbsFloat(get(14)), sbsFloat(get(15))
	if lat != nil && lon != nil && (*lat != 0 || *lon != 0) {
		t.a.Lat, t.a.Lon, t.posAt = lat, lon, now
	}
	if v := get(17); v != "" {
		t.a.Squawk = v
	}
	if v := get(19); v == "-1" || v == "1" {
		t.a.Emergency = "general"
	} else if v == "0" {
		t.a.Emergency = ""
	}
	if t.posAt.IsZero() || now.Sub(t.sentAt) < 2*time.Second {
		return nil
	}
	t.sentAt = now
	a := t.a
	seen := now.Sub(t.posAt).Seconds()
	a.SeenPos = &seen
	return &a
}

func (s *Server) readSBS(f DataFeedConfig, c *Client, r io.Reader, from string) error {
	st := &sbsState{tracks: map[string]*sbsTrack{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 4096)
	for sc.Scan() {
		a := st.line(sc.Text(), time.Now())
		if a == nil {
			continue
		}
		if e := adsbEvent(*a, time.Minute); e != nil {
			c.touch()
			s.ingestFeed(c, f, e, from)
		}
	}
	return sc.Err()
}

func (s *Server) feedFetch(ctx context.Context, hc *http.Client, f DataFeedConfig, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "GolangTAK/"+s.Version)
	req.Header.Set("Accept", "application/json")
	if f.Username != "" {
		req.SetBasicAuth(f.Username, f.Password)
	} else if f.Password != "" {
		req.Header.Set("Authorization", "Bearer "+f.Password)
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
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New("the server refused the user name, password or token")
		}
		return fmt.Errorf("%s answered HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func (s *Server) pollDump1090(ctx context.Context, hc *http.Client, f DataFeedConfig, c *Client) error {
	var resp struct {
		Aircraft []struct {
			adsbAircraft
			Altitude json.RawMessage `json:"altitude"`
			OldSpeed *float64        `json:"speed"`
		} `json:"aircraft"`
	}
	u := f.URL
	if !strings.HasSuffix(strings.ToLower(strings.SplitN(u, "?", 2)[0]), ".json") {
		u = strings.TrimRight(u, "/") + "/data/aircraft.json"
	}
	if err := s.feedFetch(ctx, hc, f, u, &resp); err != nil {
		return err
	}
	for _, x := range resp.Aircraft {
		a := x.adsbAircraft
		if len(a.AltBaro) == 0 {
			a.AltBaro = x.Altitude
		}
		if a.Speed == nil {
			a.Speed = x.OldSpeed
		}
		if e := adsbEvent(a, time.Minute); e != nil {
			c.touch()
			s.ingestFeed(c, f, e, f.URL)
		}
	}
	return nil
}

type trackerFix struct {
	ID       string
	Name     string
	Category string
	Status   string
	Time     time.Time
	Lat, Lon float64
	Alt      *float64
	Speed    *float64
	Course   *float64
	Accuracy *float64
	Battery  *float64
}

func trackerType(category string) string {
	switch strings.ToLower(category) {
	case "car", "truck", "bus", "van", "pickup", "offroad", "tractor", "crane", "trolleybus", "tram", "train":
		return "a-f-G-E-V-C"
	case "motorcycle", "scooter", "bicycle":
		return "a-f-G-E-V"
	case "boat", "ship":
		return "a-f-S-X"
	case "plane":
		return "a-f-A-C-F"
	case "helicopter":
		return "a-f-A-C-H"
	case "animal":
		return "a-f-G"
	}
	return "a-f-G-U-C"
}

func trackerEvent(fx trackerFix, stale time.Duration) *cot.Event {
	if fx.ID == "" || fx.Lat < -90 || fx.Lat > 90 || fx.Lon < -180 || fx.Lon > 180 || (fx.Lat == 0 && fx.Lon == 0) {
		return nil
	}
	if fx.Time.IsZero() || fx.Time.After(time.Now().Add(time.Minute)) {
		fx.Time = time.Now()
	}
	until := fx.Time.Add(stale)
	if time.Until(until) < 30*time.Second {
		return nil
	}
	e := cot.New("traccar-"+fx.ID, trackerType(fx.Category), "m-g", time.Until(until))
	e.Point = cot.Point{Lat: fx.Lat, Lon: fx.Lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	if fx.Alt != nil {
		e.Point.Hae = *fx.Alt
	}
	if fx.Accuracy != nil && *fx.Accuracy > 0 {
		e.Point.Ce = *fx.Accuracy
	}
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(fx.Name, "Tracker "+fx.ID))
	if fx.Speed != nil || fx.Course != nil {
		tr := e.Detail.AddNew("track")
		if fx.Course != nil {
			tr.SetAttr("course", cot.FormatFloat(*fx.Course))
		}
		if fx.Speed != nil {
			tr.SetAttr("speed", cot.FormatFloat(*fx.Speed*knotsToMS))
		}
	}
	if fx.Battery != nil {
		e.Detail.AddNew("status", "battery", strconv.Itoa(int(math.Round(*fx.Battery))))
	}
	parts := []string{"Device " + fx.ID, "Fix " + fx.Time.UTC().Format("2006-01-02 15:04:05Z")}
	if fx.Status != "" {
		parts = append(parts, "Status "+fx.Status)
	}
	e.Detail.AddNew("remarks").Text = strings.Join(parts, ", ")
	return e
}

func parseFixTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(int64(n))
		}
		return time.Unix(int64(n), 0)
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

func optFloat(v string) *float64 {
	if v == "" {
		return nil
	}
	return sbsFloat(v)
}

func osmandFix(r *http.Request, body []byte) (trackerFix, bool) {
	var fx trackerFix
	if len(body) > 0 && body[0] == '{' {
		var j struct {
			DeviceID string `json:"device_id"`
			Location struct {
				Timestamp string `json:"timestamp"`
				Coords    struct {
					Latitude  float64  `json:"latitude"`
					Longitude float64  `json:"longitude"`
					Accuracy  *float64 `json:"accuracy"`
					Speed     *float64 `json:"speed"`
					Heading   *float64 `json:"heading"`
					Altitude  *float64 `json:"altitude"`
				} `json:"coords"`
				Battery struct {
					Level *float64 `json:"level"`
				} `json:"battery"`
			} `json:"location"`
		}
		if json.Unmarshal(body, &j) != nil {
			return fx, false
		}
		co := j.Location.Coords
		fx = trackerFix{ID: j.DeviceID, Lat: co.Latitude, Lon: co.Longitude, Alt: co.Altitude, Accuracy: co.Accuracy, Course: co.Heading, Time: parseFixTime(j.Location.Timestamp)}
		if co.Speed != nil && *co.Speed >= 0 {
			kn := *co.Speed / knotsToMS
			fx.Speed = &kn
		}
		if co.Heading != nil && *co.Heading < 0 {
			fx.Course = nil
		}
		if b := j.Location.Battery.Level; b != nil && *b >= 0 {
			pct := *b * 100
			fx.Battery = &pct
		}
		return fx, fx.ID != ""
	}
	q := r.URL.Query()
	if len(body) > 0 {
		if form, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range form {
				q[k] = v
			}
		}
	}
	fx.ID = firstNonEmpty(q.Get("id"), q.Get("deviceid"))
	lat, lon := sbsFloat(q.Get("lat")), sbsFloat(firstNonEmpty(q.Get("lon"), q.Get("lng")))
	if lat == nil || lon == nil {
		if loc := strings.Split(q.Get("location"), ","); len(loc) == 2 {
			lat, lon = sbsFloat(loc[0]), sbsFloat(loc[1])
		}
	}
	if fx.ID == "" || lat == nil || lon == nil {
		return fx, false
	}
	fx.Lat, fx.Lon = *lat, *lon
	fx.Name = q.Get("name")
	fx.Time = parseFixTime(q.Get("timestamp"))
	fx.Alt, fx.Speed, fx.Course = optFloat(q.Get("altitude")), optFloat(q.Get("speed")), optFloat(firstNonEmpty(q.Get("bearing"), q.Get("heading")))
	fx.Accuracy = optFloat(firstNonEmpty(q.Get("accuracy"), q.Get("hdop")))
	fx.Battery = optFloat(q.Get("batt"))
	return fx, true
}

func (s *Server) osmandReport(f DataFeedConfig, c *Client, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	fx, ok := osmandFix(r, body)
	if !ok {
		http.Error(w, "missing device id or position", http.StatusBadRequest)
		return
	}
	if f.Password != "" && r.URL.Query().Get("key") != f.Password {
		http.Error(w, "unknown key", http.StatusUnauthorized)
		return
	}
	if e := trackerEvent(fx, 15*time.Minute); e != nil {
		c.touch()
		s.ingestFeed(c, f, e, r.RemoteAddr)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) pollTraccar(ctx context.Context, hc *http.Client, f DataFeedConfig, c *Client) error {
	base := strings.TrimRight(f.URL, "/")
	var devices []struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		UniqueID string `json:"uniqueId"`
		Status   string `json:"status"`
		Category string `json:"category"`
		Disabled bool   `json:"disabled"`
	}
	if err := s.feedFetch(ctx, hc, f, base+"/api/devices", &devices); err != nil {
		return err
	}
	var positions []struct {
		DeviceID   int64          `json:"deviceId"`
		FixTime    string         `json:"fixTime"`
		Latitude   float64        `json:"latitude"`
		Longitude  float64        `json:"longitude"`
		Altitude   *float64       `json:"altitude"`
		Speed      *float64       `json:"speed"`
		Course     *float64       `json:"course"`
		Accuracy   *float64       `json:"accuracy"`
		Valid      bool           `json:"valid"`
		Attributes map[string]any `json:"attributes"`
	}
	if err := s.feedFetch(ctx, hc, f, base+"/api/positions", &positions); err != nil {
		return err
	}
	byID := map[int64]int{}
	for i, d := range devices {
		byID[d.ID] = i
	}
	stale := time.Duration(max(f.Interval*6, 900)) * time.Second
	for _, p := range positions {
		i, ok := byID[p.DeviceID]
		if !ok || devices[i].Disabled {
			continue
		}
		d := devices[i]
		fx := trackerFix{ID: firstNonEmpty(d.UniqueID, strconv.FormatInt(d.ID, 10)), Name: d.Name, Category: d.Category, Status: d.Status, Time: parseFixTime(p.FixTime), Lat: p.Latitude, Lon: p.Longitude, Alt: p.Altitude, Speed: p.Speed, Course: p.Course, Accuracy: p.Accuracy}
		if b, ok := anyNum(p.Attributes["batteryLevel"]); ok {
			fx.Battery = &b
		}
		if e := trackerEvent(fx, stale); e != nil {
			c.touch()
			s.ingestFeed(c, f, e, f.URL)
		}
	}
	return nil
}
