package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

type TrackPoint struct {
	Time   time.Time `json:"t"`
	Lat    float64   `json:"lat"`
	Lon    float64   `json:"lon"`
	Hae    float64   `json:"hae"`
	Speed  float64   `json:"speed,omitempty"`
	Course float64   `json:"course,omitempty"`
}

type track struct {
	callsign string
	typ      string
	groups   []string
	all      bool
	points   []TrackPoint
}

type historyLine struct {
	T string   `json:"t"`
	U string   `json:"u"`
	Y string   `json:"y"`
	G []string `json:"g,omitempty"`
	A bool     `json:"a,omitempty"`
	X string   `json:"x"`
}

type historyFilter func(groups []string, everyone bool) bool

func (s *Server) historyFilter(id *Identity) historyFilter {
	if id != nil && id.Admin {
		return nil
	}
	return func(groups []string, everyone bool) bool {
		return everyone || s.visibleTo(id, s.dir.Mask(groups))
	}
}

type History struct {
	dir     string
	ch      chan *Message
	mu      sync.Mutex
	day     string
	f       *os.File
	w       *bufio.Writer
	tmu     sync.RWMutex
	tracks  map[string]*track
	Dropped atomic.Uint64
	Written atomic.Uint64
	done    chan struct{}
	names   func(GroupMask) []string
}

const trackLimit = 720

func OpenHistory(dir string) (*History, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &History{dir: dir, ch: make(chan *Message, 8192), tracks: map[string]*track{}, done: make(chan struct{})}, nil
}

func (h *History) Record(m *Message) {
	e := m.Event
	if e.IsControl() && !e.IsDelete() {
		return
	}
	select {
	case h.ch <- m:
	default:
		h.Dropped.Add(1)
	}
}

func (h *History) Run(stop <-chan struct{}) {
	defer close(h.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			for {
				select {
				case m := <-h.ch:
					h.write(m)
				default:
					h.flush()
					h.closeFile()
					return
				}
			}
		case m := <-h.ch:
			h.write(m)
		case <-tick.C:
			h.flush()
		}
	}
}

func (h *History) Wait() { <-h.done }

func (h *History) write(m *Message) {
	e := m.Event
	var groups []string
	if h.names != nil && !m.Everyone {
		groups = h.names(m.Groups)
	}
	if e.Point.Lat != 0 || e.Point.Lon != 0 {
		if strings.HasPrefix(e.Type, "a-") {
			h.addPoint(e, groups, m.Everyone)
		}
	}
	day := m.Received.UTC().Format("2006-01-02")
	h.mu.Lock()
	defer h.mu.Unlock()
	if day != h.day || h.f == nil {
		h.closeLocked()
		f, err := os.OpenFile(filepath.Join(h.dir, day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return
		}
		h.f, h.w, h.day = f, bufio.NewWriterSize(f, 128<<10), day
	}
	line, err := json.Marshal(historyLine{T: cot.FormatTime(m.Received), U: e.UID, Y: e.Type, G: groups, A: m.Everyone, X: string(m.XML())})
	if err != nil {
		return
	}
	h.w.Write(line)
	h.w.WriteByte('\n')
	h.Written.Add(1)
}

func (h *History) addPoint(e *cot.Event, groups []string, all bool) {
	sp, co := 0.0, 0.0
	if tr := e.D("track"); tr != nil {
		sp = cot.Finite(parseF(tr.Attr("speed")), 0)
		co = cot.Finite(parseF(tr.Attr("course")), 0)
	}
	p := TrackPoint{Time: e.Time, Lat: e.Point.Lat, Lon: e.Point.Lon, Hae: e.Point.Hae, Speed: sp, Course: co}
	h.tmu.Lock()
	t := h.tracks[e.UID]
	if t == nil {
		if len(h.tracks) > 20000 {
			h.tmu.Unlock()
			return
		}
		t = &track{}
		h.tracks[e.UID] = t
	}
	if cs := e.Callsign(); cs != "" {
		t.callsign = cs
	}
	t.typ = e.Type
	t.groups, t.all = groups, all
	if n := len(t.points); n > 0 {
		last := t.points[n-1]
		if last.Lat == p.Lat && last.Lon == p.Lon && p.Time.Sub(last.Time) < time.Minute {
			h.tmu.Unlock()
			return
		}
	}
	t.points = append(t.points, p)
	if len(t.points) > trackLimit {
		t.points = append(t.points[:0:0], t.points[len(t.points)-trackLimit:]...)
	}
	h.tmu.Unlock()
}

func (h *History) Track(uid string, since time.Time, can historyFilter) (string, []TrackPoint) {
	h.tmu.RLock()
	defer h.tmu.RUnlock()
	t := h.tracks[uid]
	if t == nil || (can != nil && !can(t.groups, t.all)) {
		return "", nil
	}
	var out []TrackPoint
	for _, p := range t.points {
		if p.Time.After(since) {
			out = append(out, p)
		}
	}
	return t.callsign, out
}

func (h *History) flush() {
	h.mu.Lock()
	if h.w != nil {
		h.w.Flush()
	}
	h.mu.Unlock()
}

func (h *History) closeLocked() {
	if h.w != nil {
		h.w.Flush()
	}
	if h.f != nil {
		h.f.Sync()
		h.f.Close()
	}
	h.f, h.w, h.day = nil, nil, ""
}

func (h *History) closeFile() {
	h.mu.Lock()
	h.closeLocked()
	h.mu.Unlock()
}

func (h *History) days(start, end time.Time) []string {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(name, ".jsonl")
		d, err := time.Parse("2006-01-02", day)
		if err != nil {
			continue
		}
		if !start.IsZero() && d.Add(24*time.Hour).Before(start) {
			continue
		}
		if !end.IsZero() && d.After(end) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type historyQuery struct {
	UID    string
	Type   string
	Start  time.Time
	End    time.Time
	Limit  int
	Latest bool
	Can    historyFilter
}

func (h *History) Query(q historyQuery) []*cot.Event {
	uid, start, end, limit, latestOnly, can := q.UID, q.Start, q.End, q.Limit, q.Latest, q.Can
	h.flush()
	files := h.days(start, end)
	if latestOnly {
		for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
			files[i], files[j] = files[j], files[i]
		}
	}
	needle := []byte(`"u":` + mustJSON(uid))
	var out []*cot.Event
	for _, name := range files {
		f, err := os.Open(filepath.Join(h.dir, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		var dayEvents []*cot.Event
		for sc.Scan() {
			line := sc.Bytes()
			if uid != "" && !bytes.Contains(line, needle) {
				continue
			}
			var hl historyLine
			if json.Unmarshal(line, &hl) != nil {
				continue
			}
			if uid != "" && hl.U != uid {
				continue
			}
			if q.Type != "" && !strings.HasPrefix(hl.Y, q.Type) {
				continue
			}
			if can != nil && !can(hl.G, hl.A) {
				continue
			}
			t, _ := cot.ParseTime(hl.T)
			if (!start.IsZero() && t.Before(start)) || (!end.IsZero() && t.After(end)) {
				continue
			}
			e, err := cot.Parse([]byte(hl.X))
			if err != nil {
				continue
			}
			dayEvents = append(dayEvents, e)
		}
		f.Close()
		if latestOnly && len(dayEvents) > 0 {
			return dayEvents[len(dayEvents)-1:]
		}
		out = append(out, dayEvents...)
		if limit > 0 && len(out) > limit {
			out = out[len(out)-limit:]
		}
	}
	return out
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (h *History) Cleanup(days int) int {
	if days <= 0 {
		return 0
	}
	cut := time.Now().UTC().AddDate(0, 0, -days)
	n := 0
	for _, name := range h.days(time.Time{}, time.Time{}) {
		d, err := time.Parse("2006-01-02", strings.TrimSuffix(name, ".jsonl"))
		if err == nil && d.Before(cut) {
			if os.Remove(filepath.Join(h.dir, name)) == nil {
				n++
			}
		}
	}
	h.tmu.Lock()
	for uid, t := range h.tracks {
		if n := len(t.points); n == 0 || time.Since(t.points[n-1].Time) > 7*24*time.Hour {
			delete(h.tracks, uid)
		}
	}
	h.tmu.Unlock()
	return n
}

func (h *History) Usage() (int64, int) {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return 0, 0
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total, len(entries)
}

func kmlEscape(s string) string { return xmlEscapeASCII(s) }

func (s *Server) tracksKML(uids []string, start, end time.Time, can historyFilter) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2"><Document><name>`)
	b.WriteString(kmlEscape(s.Config().Name + " tracks"))
	b.WriteString(`</name>`)
	for _, uid := range uids {
		var pts []TrackPoint
		callsign := uid
		if !start.IsZero() || !end.IsZero() {
			for _, e := range s.history.Query(historyQuery{UID: uid, Start: start, End: end, Limit: 100000, Can: can}) {
				if e.Callsign() != "" {
					callsign = e.Callsign()
				}
				pts = append(pts, TrackPoint{Time: e.Time, Lat: e.Point.Lat, Lon: e.Point.Lon, Hae: e.Point.Hae})
			}
		} else {
			cs, p := s.history.Track(uid, time.Time{}, can)
			pts = p
			if cs != "" {
				callsign = cs
			}
		}
		if len(pts) == 0 {
			continue
		}
		b.WriteString(`<Placemark><name>` + kmlEscape(callsign) + `</name><gx:Track>`)
		for _, p := range pts {
			b.WriteString(`<when>` + cot.FormatTime(p.Time) + `</when>`)
		}
		for _, p := range pts {
			hae := p.Hae
			if hae >= cot.Unknown {
				hae = 0
			}
			b.WriteString(`<gx:coord>` + cot.FormatFloat(p.Lon) + ` ` + cot.FormatFloat(p.Lat) + ` ` + cot.FormatFloat(hae) + `</gx:coord>`)
		}
		b.WriteString(`</gx:Track></Placemark>`)
	}
	b.WriteString(`</Document></kml>`)
	return b.String()
}
