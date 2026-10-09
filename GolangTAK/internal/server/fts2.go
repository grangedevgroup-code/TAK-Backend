package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/xmltree"
)

func ftsList(b ftsBody, key string) []ftsBody {
	raw, _ := b[key].([]any)
	var out []ftsBody
	for _, v := range raw {
		if m, ok := v.(map[string]any); ok {
			out = append(out, ftsBody(m))
		}
	}
	return out
}

func (b ftsBody) any(keys ...string) string {
	for _, k := range keys {
		if v := b.str(k); v != "" {
			return v
		}
	}
	return ""
}

func ftsGroups(v string) []string {
	var out []string
	for _, g := range strings.Split(v, ",") {
		if g = strings.TrimSpace(g); g != "" && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) ftsSystemUserPost(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	users := ftsList(b, "systemUsers")
	if len(users) == 0 {
		writeText(w, http.StatusBadRequest, "systemUsers is required")
		return
	}
	var out []map[string]any
	for _, u := range users {
		name := u.any("Name", "name")
		pw := u.any("Password", "password", "Token", "token")
		generated := ""
		if pw == "" {
			generated = FriendlySecret()
			pw = generated
		}
		groups := ftsGroups(u.any("Group", "group"))
		for _, g := range groups {
			s.dir.EnsureGroup(g, "", false)
		}
		if _, err := s.dir.AddUser(name, pw, false, groups); err != nil {
			writeText(w, http.StatusBadRequest, name+": "+err.Error())
			return
		}
		res := map[string]any{"Name": name, "Uid": name}
		if generated != "" {
			res["Password"] = generated
		}
		if strings.EqualFold(u.any("Certs", "certs"), "true") {
			res["CertificatePackage"] = s.packageLink(PackageCert, name, "", 24*60, false)
		}
		out = append(out, res)
		s.log.Info("user created through the FreeTAKServer API", "user", name, "by", identityOf(r).Name)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"message": "user created", "systemUsers": out})
}

func (s *Server) ftsSystemUserPut(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, u := range ftsList(b, "systemUsers") {
		name := u.any("uid", "Uid", "Name", "name")
		if _, ok := s.dir.User(name); !ok {
			writeText(w, http.StatusNotFound, "no user "+name)
			return
		}
		if pw := u.any("password", "Password", "token", "Token"); pw != "" {
			if err := s.dir.SetPassword(name, pw); err != nil {
				writeText(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if g := u.any("group", "Group"); g != "" {
			groups := ftsGroups(g)
			for _, x := range groups {
				s.dir.EnsureGroup(x, "", false)
			}
			if err := s.dir.SetGroups(name, groups, groups); err != nil {
				writeText(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	writeText(w, http.StatusOK, "user updated")
}

func (s *Server) ftsSystemUserDelete(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	me := identityOf(r).Name
	for _, u := range ftsList(b, "systemUsers") {
		name := u.any("uid", "Uid", "Name", "name")
		if name == me {
			writeText(w, http.StatusBadRequest, "you cannot delete your own account")
			return
		}
		if _, err := s.dir.DeleteUser(name); err != nil {
			writeText(w, http.StatusNotFound, name+": "+err.Error())
			return
		}
		s.dir.EndUserSessions(name)
	}
	writeText(w, http.StatusOK, "user deleted")
}

func (s *Server) ftsExCheckTable(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	switch r.Method {
	case http.MethodPost:
		s.excheckTemplatePost(w, r)
		return
	case http.MethodDelete:
		b, err := readFTS(r)
		if err != nil {
			writeText(w, http.StatusBadRequest, err.Error())
			return
		}
		ex, _ := b["ExCheck"].(map[string]any)
		eb := ftsBody(ex)
		for _, t := range ftsList(eb, "Templates") {
			uid := t.str("uid")
			res, ok := s.res.Get(uid)
			if !ok || !s.canEdit(id, res) {
				continue
			}
			s.missionDropContent(exTemplates, uid, "")
			s.res.Delete(uid)
		}
		for _, c := range ftsList(eb, "Checklists") {
			m, ok := s.missions.Get(c.str("uid"))
			if !ok || m.Tool != exTool || !s.missionVisible(id, m) {
				continue
			}
			s.missions.db.Delete(m.Name)
			s.notifyMissionAll(m, "t-x-m-d", "DELETE", "")
		}
		writeText(w, http.StatusOK, "deleted")
		return
	}
	templates := []map[string]any{}
	if tm, ok := s.missions.Get(exTemplates); ok {
		for _, c := range tm.Contents {
			n, res, ok := s.loadXMLResource(c.UID)
			if !ok || !s.resourceVisible(id, res) {
				continue
			}
			d := n.Child("checklistDetails")
			if d == nil {
				d = &xmltree.Node{}
			}
			templates = append(templates, map[string]any{"uid": c.UID, "name": childText(d, "name"), "description": childText(d, "description"), "callsign": childText(d, "creatorCallsign"), "creatorUid": c.CreatorUID, "timestamp": c.Added})
		}
	}
	checklists := []map[string]any{}
	for _, m := range s.missions.All() {
		if m.Tool != exTool || m.Name == exTemplates || !s.missionVisible(id, m) {
			continue
		}
		checklists = append(checklists, map[string]any{"uid": m.Name, "name": firstNonEmpty(m.Description, m.Name), "template": m.Parent, "callsign": m.CreatorUID, "timestamp": m.Created})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ExCheck": map[string]any{"Templates": templates, "Checklists": checklists}})
}

func peerHostPort(u string) (string, int) {
	p, err := url.Parse(u)
	if err != nil {
		return u, 0
	}
	n, _ := strconv.Atoi(p.Port())
	return p.Hostname(), n
}

func (s *Server) ftsFederationTable(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.Config()
		status := map[string]PeerStatus{}
		for _, st := range s.peerStatus() {
			status[st.Name] = st
		}
		active := []map[string]any{}
		feds := []map[string]any{}
		for _, p := range cfg.Peers {
			host, port := peerHostPort(p.URL)
			st := status[p.Name]
			state := "Disabled"
			if p.Enabled {
				state = "Enabled"
			}
			feds = append(feds, map[string]any{"name": p.Name, "id": p.Name, "address": host, "port": port, "url": p.URL, "fallBack": false, "status": state, "reconnectInterval": 30, "maxRetries": 0, "lastError": st.Error})
			if st.State == "connected" {
				active = append(active, map[string]any{"id": p.Name, "address": host, "port": port, "initiator": "Self", "readCount": st.Rx, "processedCount": st.Tx})
			}
		}
		if fs, ok := s.federationStatus()["federates"].([]FederateStatus); ok {
			for _, f := range fs {
				active = append(active, map[string]any{"id": f.Name, "address": f.Remote, "port": 0, "initiator": "Remote", "readCount": f.Rx, "processedCount": f.Tx})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"activeFederations": active, "federations": feds})
		return
	}
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = s.UpdateConfig(func(c *Config) error {
		switch r.Method {
		case http.MethodPost:
			for _, f := range ftsList(b, "outgoingFederations") {
				name := f.any("name", "id")
				addr := f.str("address")
				port, _ := f.num("port")
				if name == "" || addr == "" {
					return errors.New("name and address are required")
				}
				if port <= 0 {
					port = 9000
				}
				if slices.ContainsFunc(c.Peers, func(p PeerConfig) bool { return p.Name == name }) {
					return fmt.Errorf("a link named %s already exists", name)
				}
				scheme := "fed"
				if f.str("protocol") == "v2" || int(port) == 9001 {
					scheme = "fed2"
				}
				c.Peers = append(c.Peers, PeerConfig{Name: name, URL: scheme + "://" + net.JoinHostPort(addr, strconv.Itoa(int(port))), Enabled: !strings.EqualFold(f.str("status"), "disabled"), Direction: "both"})
			}
		case http.MethodPut:
			for _, f := range ftsList(b, "federations") {
				id := f.any("id", "name")
				i := slices.IndexFunc(c.Peers, func(p PeerConfig) bool { return p.Name == id })
				if i < 0 {
					return fmt.Errorf("no federation %s", id)
				}
				if st := f.str("status"); st != "" {
					c.Peers[i].Enabled = !strings.EqualFold(st, "disabled")
				}
				if n := f.str("name"); n != "" && n != id {
					c.Peers[i].Name = n
				}
			}
		case http.MethodDelete:
			for _, f := range ftsList(b, "federations") {
				id := f.any("id", "name")
				c.Peers = slices.DeleteFunc(c.Peers, func(p PeerConfig) bool { return p.Name == id })
			}
		}
		return validateConfig(c)
	})
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reloadPeers()
	writeText(w, http.StatusOK, "federations updated")
}

func (s *Server) ftsKML(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, ok1 := b.num("latitude")
	lon, ok2 := b.num("longitude")
	if !ok1 || !ok2 || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		writeText(w, http.StatusBadRequest, "latitude and longitude are required")
		return
	}
	name := firstNonEmpty(b.str("name"), "KML point")
	var rows []string
	switch body := b["body"].(type) {
	case map[string]any:
		keys := make([]string, 0, len(body))
		for k := range body {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			rows = append(rows, k+": "+ftsBody(body).str(k))
		}
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) == nil {
			for k, v := range m {
				rows = append(rows, k+": "+ftsBody{"v": v}.str("v"))
			}
			slices.Sort(rows)
		} else if body != "" {
			rows = append(rows, body)
		}
	}
	uid := firstNonEmpty(b.str("uid"), cot.NewUID())
	e := cot.New(uid, "b-m-p-s-m", "h-g-i-g-o", s.ftsTimeout(b, 24*time.Hour))
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", name)
	if len(rows) > 0 {
		e.Detail.AddNew("remarks").Text = strings.Join(rows, "\n")
	}
	e.Detail.AddNew("archive")
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, uid)
}

func parseZone(q url.Values) (func(lat, lon float64) bool, error) {
	if z := q.Get("zone"); z != "" {
		poly := parseFilterPolygon(z)
		if poly == nil {
			return nil, errors.New("zone must be at least three \"longitude latitude\" points separated by commas")
		}
		return func(lat, lon float64) bool { return pointInPolygon(lat, lon, poly) }, nil
	}
	f := func(keys ...string) (float64, bool) {
		for _, k := range keys {
			if v, err := strconv.ParseFloat(q.Get(k), 64); err == nil {
				return v, true
			}
		}
		return 0, false
	}
	n, ok1 := f("north", "maxLatitude", "top")
	so, ok2 := f("south", "minLatitude", "bottom")
	e, ok3 := f("east", "maxLongitude", "right")
	wv, ok4 := f("west", "minLongitude", "left")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, errors.New("give north, south, east and west, or a zone polygon")
	}
	if so > n {
		so, n = n, so
	}
	return func(lat, lon float64) bool {
		if lat < so || lat > n {
			return false
		}
		if wv <= e {
			return lon >= wv && lon <= e
		}
		return lon >= wv || lon <= e
	}, nil
}

func (s *Server) ftsGeoByZone(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	inside, err := parseZone(q)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	attitude := ftsAttitude[strings.ToLower(q.Get("attitude"))]
	id := identityOf(r)
	out := []map[string]any{}
	for _, m := range s.hub.Cached() {
		e := m.Event
		if !strings.HasPrefix(e.Type, "a-") || (!m.Everyone && !id.Admin && !s.visibleTo(id, m.Groups)) {
			continue
		}
		if attitude != "" && (len(e.Type) < 3 || e.Type[2:3] != attitude) {
			continue
		}
		if !inside(e.Point.Lat, e.Point.Lon) {
			continue
		}
		out = append(out, map[string]any{"uid": e.UID, "type": e.Type, "name": e.Callsign(), "latitude": e.Point.Lat, "longitude": e.Point.Lon, "how": e.How, "time": e.Time, "stale": e.Stale})
	}
	writeJSON(w, http.StatusOK, out)
}
