package server

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func (s *Server) vcmDelete(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	uid := firstNonEmpty(r.Form.Get("id"), r.Form.Get("uid"), r.Form.Get("feedId"))
	f, ok := s.videos.Get(uid)
	if !ok {
		writeText(w, http.StatusNotFound, "no such video feed")
		return
	}
	id := identityOf(r)
	if !id.Admin && f.Creator != "" && f.Creator != id.Name {
		writeText(w, http.StatusForbidden, "only the creator or an administrator can delete this feed")
		return
	}
	s.videos.Delete(uid)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) vcuPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	r.ParseForm()
	q := r.Form
	id := identityOf(r)
	f := VideoFeed{UID: firstNonEmpty(q.Get("uuid"), q.Get("feedId"), cot.NewUID()), Alias: q.Get("alias"), Protocol: q.Get("protocol"), Address: q.Get("address"),
		Path: q.Get("path"), RoverPort: q.Get("roverPort"), IgnoreKLV: q.Get("ignoreEmbeddedKLV") == "true", PreferredMAC: q.Get("preferredMacAddress"),
		Buffer: q.Get("buffer"), Timeout: q.Get("timeout"), RTSPReliable: q.Get("rtspReliable"), Thumbnail: q.Get("thumbnail"), Classification: q.Get("classification"),
		Groups: s.identityGroups(id), Creator: id.Name, Active: q.Get("active") != "false" && q.Get("active") != "0"}
	f.Port, _ = strconv.Atoi(q.Get("port"))
	f.Lat, _ = strconv.ParseFloat(q.Get("latitude"), 64)
	f.Lon, _ = strconv.ParseFloat(q.Get("longitude"), 64)
	if f.Address == "" && f.Path == "" {
		writeText(w, http.StatusBadRequest, "address is required")
		return
	}
	if err := s.videos.Put(f); err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("video feed saved", "alias", f.Alias, "by", id.Name)
	writeText(w, http.StatusOK, f.UID)
}

func (s *Server) vcsPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	r.ParseForm()
	f, ok := s.videos.Get(r.Form.Get("feedId"))
	if !ok || !s.videoVisible(identityOf(r), f) {
		writeText(w, http.StatusNotFound, "no such video feed")
		return
	}
	var dests []cot.Dest
	for _, c := range strings.FieldsFunc(r.Form.Get("contacts"), func(r rune) bool { return r == '|' || r == ',' }) {
		c = strings.TrimSpace(c)
		if s.hub.ByUID(c) != nil {
			dests = append(dests, cot.Dest{UID: c})
		} else if c != "" {
			dests = append(dests, cot.Dest{Callsign: c})
		}
	}
	if len(dests) == 0 {
		writeText(w, http.StatusBadRequest, "contacts are required")
		return
	}
	e := s.VideoEvent(f)
	e.SetDests(dests)
	m := NewMessage(e, nil, nil)
	m.Everyone, m.NoReplay = true, true
	s.hub.Publish(m)
	w.WriteHeader(http.StatusOK)
}

func kmlColor(t string) string {
	switch {
	case strings.HasPrefix(t, "a-f") || strings.HasPrefix(t, "a-a"):
		return "ffffff00"
	case strings.HasPrefix(t, "a-h") || strings.HasPrefix(t, "a-s") || strings.HasPrefix(t, "a-j") || strings.HasPrefix(t, "a-k"):
		return "ff0000ff"
	case strings.HasPrefix(t, "a-n"):
		return "ff00ff00"
	}
	return "ff00ffff"
}

func (s *Server) latestKML(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	q := r.Form
	secago := int64(0)
	if v := q.Get("secago"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeText(w, http.StatusBadRequest, `Illegal value for parameter "secago"`)
			return
		}
		secago = n
	}
	types := splitList(q.Get("cotType"))
	id := identityOf(r)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>` + kmlEscape(s.Config().Name) + ` latest</name>`)
	msgs := s.hub.Cached()
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].Event.UID < msgs[j].Event.UID })
	for _, m := range msgs {
		e := m.Event
		if !m.Everyone && !s.visibleTo(id, m.Groups) {
			continue
		}
		if secago > 0 && time.Since(e.Time) > time.Duration(secago)*time.Second {
			continue
		}
		if len(types) > 0 && !typeMatchesPrefix(e.Type, types) {
			continue
		}
		if e.Point.Lat == 0 && e.Point.Lon == 0 {
			continue
		}
		name := firstNonEmpty(e.Callsign(), e.UID)
		b.WriteString(`<Placemark><name>` + kmlEscape(name) + `</name><description>` + kmlEscape(e.Type+" "+cot.FormatTime(e.Time)) + `</description>`)
		b.WriteString(`<Style><IconStyle><color>` + kmlColor(e.Type) + `</color><Icon><href>` + kmlEscape(s.baseURL(r)+"/Marti/api/iconimage?cotType="+url.QueryEscape(e.Type)) + `</href></Icon></IconStyle></Style>`)
		b.WriteString(fmt.Sprintf(`<Point><coordinates>%s,%s,%s</coordinates></Point></Placemark>`, cot.FormatFloat(e.Point.Lon), cot.FormatFloat(e.Point.Lat), cot.FormatFloat(e.Point.Hae)))
	}
	b.WriteString(`</Document></kml>`)
	w.Header().Set("Content-Type", "application/vnd.google-earth.kml+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="LatestKML.kml"`)
	w.Write([]byte(b.String()))
}

func typeMatchesPrefix(t string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(t, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

func (s *Server) kmlMasterSA(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	secago := r.Form.Get("secago")
	if secago != "" {
		if n, err := strconv.Atoi(secago); err != nil || n < 0 {
			writeText(w, http.StatusBadRequest, `Illegal value for parameter "secago"`)
			return
		}
	}
	base := s.baseURL(r) + "/Marti/LatestKML?"
	link := func(name, typ string) string {
		v := url.Values{"cotType": {typ}}
		if secago != "" {
			v.Set("secago", secago)
		}
		return `<NetworkLink><name>` + name + `</name><open>0</open><Link><href>` + kmlEscape(base+v.Encode()) + `</href><refreshMode>onInterval</refreshMode><refreshInterval>10</refreshInterval></Link></NetworkLink>`
	}
	var b strings.Builder
	b.WriteString(`<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><kml xmlns="http://www.opengis.net/kml/2.2"><Folder><name>` + kmlEscape(s.Config().Name) + `</name><open>1</open>`)
	b.WriteString(link("Friendlies", "a-f") + link("Hostiles", "a-h") + link("Neutrals", "a-n") + link("Unknowns", "a-u") + link("Routes", "b-m-r"))
	b.WriteString(`</Folder></kml>`)
	w.Header().Set("Content-Type", "application/vnd.google-earth.kml+xml")
	w.Header().Set("Content-Disposition", "filename=TAK-Master-Links.kml")
	w.Write([]byte(b.String()))
}

type cotSearch struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	Count     int64     `json:"count"`
	BytesSent int64     `json:"bytesSent"`
	Timestamp time.Time `json:"timestamp"`
	Active    bool      `json:"active"`
	Target    string    `json:"target"`
}

type cotSearches struct {
	mu   sync.Mutex
	list map[string]*cotSearch
}

func (cs *cotSearches) put(c *cotSearch) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.list == nil {
		cs.list = map[string]*cotSearch{}
	}
	cs.list[c.ID] = c
	if len(cs.list) > 200 {
		var oldest *cotSearch
		for _, x := range cs.list {
			if !x.Active && (oldest == nil || x.Timestamp.Before(oldest.Timestamp)) {
				oldest = x
			}
		}
		if oldest != nil {
			delete(cs.list, oldest.ID)
		}
	}
}

func (cs *cotSearches) update(id string, fn func(c *cotSearch)) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if c := cs.list[id]; c != nil {
		fn(c)
	}
}

func (cs *cotSearches) snapshot() []cotSearch {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]cotSearch, 0, len(cs.list))
	for _, c := range cs.list {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	return out
}

func haversineM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371000
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp, dl := (lat2-lat1)*math.Pi/180, (lon2-lon1)*math.Pi/180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return 2 * r * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func (s *Server) cotQueryServlet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	r.ParseForm()
	q := r.Form
	host, proto := q.Get("hostName"), strings.ToLower(firstNonEmpty(q.Get("protocol"), "tcp"))
	port, err := strconv.Atoi(q.Get("port"))
	if host == "" || err != nil || port <= 0 || port > 65535 {
		writeText(w, http.StatusBadRequest, "Invalid port number")
		return
	}
	parse := func(k string) (time.Time, bool) {
		v := q.Get(k)
		if v == "" {
			return time.Time{}, true
		}
		t, err := cot.ParseTime(v)
		return t, err == nil
	}
	start, ok1 := parse("minimumStartTime")
	end, ok2 := parse("maximumStartTime")
	if !ok1 || !ok2 {
		writeText(w, http.StatusBadRequest, "Invalid date format. An example of the  correct date format is: 2001-03-29T16:41:03.5Z")
		return
	}
	limit, _ := strconv.Atoi(q.Get("maximumResults"))
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}
	hq := historyQuery{UID: q.Get("uid"), Start: start, End: end, Limit: limit, Latest: q.Get("latestByUid") == "true", Can: s.historyFilter(identityOf(r))}
	events := s.history.Query(hq)
	area := strings.ToLower(q.Get("searchArea"))
	f := func(k string) float64 { v, _ := strconv.ParseFloat(q.Get(k), 64); return v }
	typ := q.Get("cotType")
	var keep []*cot.Event
	for _, e := range events {
		if typ != "" && !typeMatchesPrefix(e.Type, splitList(typ)) {
			continue
		}
		p := e.Point
		switch area {
		case "rectangle":
			if p.Lat > f("rectangleTop") || p.Lat < f("rectangleBottom") || p.Lon < f("rectangleLeft") || p.Lon > f("rectangleRight") {
				continue
			}
		case "circle":
			if haversineM(p.Lat, p.Lon, f("centerLatitude"), f("centerLongitude")) > f("radius") {
				continue
			}
		}
		keep = append(keep, e)
	}
	sort.SliceStable(keep, func(i, j int) bool { return keep[i].Time.Before(keep[j].Time) })
	search := &cotSearch{ID: cot.NewUID(), Status: "SUBMITTED", Timestamp: time.Now().UTC(), Active: true, Target: proto + "://" + net.JoinHostPort(host, strconv.Itoa(port)), Count: int64(len(keep))}
	s.cotSearch.put(search)
	replay := q.Get("replayMode") == "true"
	speed, _ := strconv.ParseFloat(q.Get("replaySpeed"), 64)
	if speed <= 0 {
		speed = 1
	}
	go s.deliverCotSearch(search.ID, proto, net.JoinHostPort(host, strconv.Itoa(port)), keep, replay, speed)
	s.log.Info("CoT query started", "id", search.ID, "results", len(keep), "target", search.Target, "by", identityOf(r).Name)
	writeText(w, http.StatusOK, search.ID)
}

func (s *Server) deliverCotSearch(id, proto, addr string, events []*cot.Event, replay bool, speed float64) {
	network := "tcp"
	if proto == "udp" {
		network = "udp"
	}
	ctx, cancel := context.WithTimeout(s.ctx, time.Hour)
	defer cancel()
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		s.cotSearch.update(id, func(c *cotSearch) { c.Status, c.Message, c.Active = "ERROR", err.Error(), false })
		return
	}
	defer conn.Close()
	status := "SENDING"
	if replay {
		status = "REPLAYING"
	}
	s.cotSearch.update(id, func(c *cotSearch) { c.Status = status })
	var prev time.Time
	for _, e := range events {
		if replay && !prev.IsZero() {
			gap := time.Duration(float64(e.Time.Sub(prev)) / speed)
			if gap > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(min(gap, 10*time.Minute)):
				}
			}
		}
		prev = e.Time
		b := e.XML()
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(b); err != nil {
			s.cotSearch.update(id, func(c *cotSearch) { c.Status, c.Message, c.Active = "ERROR", err.Error(), false })
			return
		}
		s.cotSearch.update(id, func(c *cotSearch) { c.BytesSent += int64(len(b)) })
	}
	s.cotSearch.update(id, func(c *cotSearch) { c.Status, c.Active = "DONE", false })
}

func (s *Server) cotSearchList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.cot.search.model.CotSearch", s.cotSearch.snapshot()))
}

func (s *Server) cotSearchGet(w http.ResponseWriter, r *http.Request) {
	for _, c := range s.cotSearch.snapshot() {
		if c.ID == r.PathValue("id") {
			writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.cot.search.model.CotSearch", c))
			return
		}
	}
	writeJSON(w, http.StatusNotFound, s.envelope("error", "no such search"))
}

func (s *Server) cotSearchDate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("java.util.Date", isoTime(time.Now().UTC())))
}

func (s *Server) dbAdmin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	switch strings.ToLower(firstNonEmpty(r.Form.Get("action"), r.Form.Get("op"), r.Form.Get("operation"))) {
	case "vacuum", "reindex":
		s.runJob("cleanup")
		writeText(w, http.StatusOK, "Success")
	default:
		writeText(w, http.StatusBadRequest, "Invalid parameters")
	}
}

func (s *Server) legacyServletRoutes(m, a func(string, http.HandlerFunc)) {
	m("DELETE /Marti/vcm", s.vcmDelete)
	m("POST /Marti/vcu", s.vcuPost)
	m("POST /Marti/vcs", s.vcsPost)
	m("GET /Marti/LatestKML", s.latestKML)
	m("POST /Marti/LatestKML", s.latestKML)
	m("GET /Marti/KmlMasterSA", s.kmlMasterSA)
	m("POST /Marti/KmlMasterSA", s.kmlMasterSA)
	a("GET /Marti/CotQueryServlet", s.cotQueryServlet)
	a("POST /Marti/CotQueryServlet", s.cotQueryServlet)
	a("GET /Marti/api/cot/search", s.cotSearchList)
	a("GET /Marti/api/cot/search/date", s.cotSearchDate)
	a("GET /Marti/api/cot/search/{id}", s.cotSearchGet)
	a("POST /Marti/DBAdmin", s.dbAdmin)
}
