package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func (s *Server) martiVersion(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusOK, "GolangTAKServer "+s.Version)
}

func (s *Server) martiVersionConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("ServerConfig", map[string]any{
		"version":  "GolangTAKServer " + s.Version,
		"api":      "3",
		"hostname": s.hostOf(r),
	}))
}

func (s *Server) martiVersionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("ServerVersion", map[string]any{"version": s.Version, "name": "GolangTAKServer"}))
}

func (s *Server) martiNodeID(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusOK, s.Config().NodeID)
}

func (s *Server) martiIsSecure(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, r.TLS != nil)
}

func (s *Server) martiUserRoles(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	roles := []string{"ROLE_ANONYMOUS"}
	if id != nil && !id.Anon {
		roles = []string{"ROLE_USER"}
		if id.Admin {
			roles = []string{"ROLE_ADMIN"}
		}
	}
	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) martiIsAdmin(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	writeJSON(w, http.StatusOK, id != nil && id.Admin)
}

func (s *Server) visibleTo(id *Identity, groups GroupMask) bool {
	if id == nil {
		return false
	}
	if id.Admin {
		return true
	}
	return id.Out.Intersects(groups) || id.In.Intersects(groups)
}

func (s *Server) deviceMask(dev Device) GroupMask {
	if dev.User != "" {
		if u, ok := s.dir.User(dev.User); ok {
			return s.dir.Mask(u.In)
		}
	}
	return s.dir.Anonymous().In
}

func (s *Server) martiClientEndpoints(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	secAgo, _ := strconv.Atoi(r.URL.Query().Get("secAgo"))
	connectedOnly := boolParam(r, "showCurrentlyConnectedClients")
	connected := map[string]*Client{}
	for _, c := range s.hub.Clients() {
		if c.Relay {
			continue
		}
		if uid := c.UID(); uid != "" {
			connected[uid] = c
		}
	}
	var data []map[string]any
	for _, dev := range s.devices.All() {
		c, live := connected[dev.UID]
		if connectedOnly && !live {
			continue
		}
		if secAgo > 0 && !live && time.Since(dev.LastSeen) > time.Duration(secAgo)*time.Second {
			continue
		}
		if live && !s.visibleTo(id, c.InMask()) {
			continue
		}
		if !live && !s.visibleTo(id, s.deviceMask(dev)) {
			continue
		}
		status := "Disconnected"
		last := dev.LastSeen
		if live {
			status = "Connected"
			last = c.LastSeen()
		}
		data = append(data, map[string]any{
			"callsign":      dev.Callsign,
			"uid":           dev.UID,
			"username":      firstNonEmpty(dev.User, "anonymous"),
			"lastEventTime": isoTime(last),
			"lastStatus":    status,
		})
	}
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.ClientEndpoint", data))
}

func (s *Server) martiContacts(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []map[string]any{}
	entry := func(info ClientInfo, user string, groups []string) map[string]any {
		return map[string]any{
			"filterGroups": groups,
			"notes":        user,
			"callsign":     info.Callsign,
			"team":         firstNonEmpty(info.Team, "Cyan"),
			"role":         firstNonEmpty(info.Role, "Team Member"),
			"takv":         strings.TrimSpace(info.Platform + " " + info.Version),
			"uid":          info.UID,
		}
	}
	for _, c := range s.hub.Clients() {
		if c.Relay || !s.visibleTo(id, c.InMask()) {
			continue
		}
		if info := c.Info(); info.UID != "" {
			out = append(out, entry(info, c.User(), s.dir.Names(c.InMask())))
		}
	}
	for _, info := range s.hub.Contacts() {
		if owner := s.hub.ByUID(info.UID); owner != nil && !owner.Relay {
			continue
		}
		out = append(out, entry(info, "", []string{}))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) groupJSON(g Group, dir string, active bool) map[string]any {
	typ := "SYSTEM"
	return map[string]any{
		"name":        g.Name,
		"direction":   dir,
		"created":     g.Created.UTC().Format("2006-01-02"),
		"type":        typ,
		"bitpos":      g.Bit,
		"active":      active,
		"description": g.Description,
	}
}

func (s *Server) userGroups(id *Identity) []map[string]any {
	var out []map[string]any
	anon, _ := s.dir.Group(s.dir.AnonGroup())
	if id == nil || id.Anon || id.Name == "" {
		return []map[string]any{s.groupJSON(anon, DirIn, true), s.groupJSON(anon, DirOut, true)}
	}
	u, ok := s.dir.User(id.Name)
	if !ok {
		return []map[string]any{s.groupJSON(anon, DirIn, true), s.groupJSON(anon, DirOut, true)}
	}
	for _, name := range u.In {
		if g, ok := s.dir.Group(name); ok {
			out = append(out, s.groupJSON(g, DirIn, !slices.Contains(u.Inactive, name+"|"+DirIn)))
		}
	}
	for _, name := range u.Out {
		if g, ok := s.dir.Group(name); ok {
			out = append(out, s.groupJSON(g, DirOut, !slices.Contains(u.Inactive, name+"|"+DirOut)))
		}
	}
	if len(out) == 0 {
		out = []map[string]any{s.groupJSON(anon, DirIn, true), s.groupJSON(anon, DirOut, true)}
	}
	return out
}

func (s *Server) martiGroupsAll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.groups.Group", s.userGroups(identityOf(r))))
}

func (s *Server) martiGroupCache(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", s.Config().Channels))
}

func (s *Server) martiGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := s.dir.Group(r.PathValue("name"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such group"})
		return
	}
	dir := strings.ToUpper(r.PathValue("direction"))
	if dir != DirIn && dir != DirOut {
		dir = DirOut
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.groups.Group", s.groupJSON(g, dir, true)))
}

type activeGroup struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Active    bool   `json:"active"`
}

func (s *Server) martiGroupsActive(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || id.Anon || id.Name == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	var body []activeGroup
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of groups"})
		return
	}
	s.applyActiveGroups(w, r, id.Name, body)
}

func (s *Server) martiGroupsActiveForce(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || !id.Admin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator access required"})
		return
	}
	user := r.URL.Query().Get("username")
	if _, ok := s.dir.User(user); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
		return
	}
	var body []activeGroup
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of groups"})
		return
	}
	s.applyActiveGroups(w, r, user, body)
}

func (s *Server) martiGroupsActiveBits(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || id.Anon || id.Name == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	var bits []int
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&bits); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of group bit positions"})
		return
	}
	u, ok := s.dir.User(id.Name)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}
	var body []activeGroup
	add := func(names []string, dir string) {
		for _, name := range names {
			if g, ok := s.dir.Group(name); ok {
				body = append(body, activeGroup{Name: name, Direction: dir, Active: slices.Contains(bits, g.Bit)})
			}
		}
	}
	add(u.In, DirIn)
	add(u.Out, DirOut)
	s.applyActiveGroups(w, r, id.Name, body)
}

func (s *Server) applyActiveGroups(w http.ResponseWriter, r *http.Request, user string, body []activeGroup) {
	u, ok := s.dir.User(user)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}
	changes := map[string]bool{}
	for _, g := range body {
		dir := strings.ToUpper(g.Direction)
		if dir != DirIn && dir != DirOut {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "direction must be IN or OUT"})
			return
		}
		member := (dir == DirIn && slices.Contains(u.In, g.Name)) || (dir == DirOut && slices.Contains(u.Out, g.Name))
		if !member {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": user + " is not in group " + g.Name})
			return
		}
		changes[g.Name+"|"+dir] = g.Active
	}
	if err := s.dir.SetActive(user, changes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("channel selection changed", "user", user, "client", r.URL.Query().Get("clientUid"), "by", identityOf(r).Name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiGroupsBulkUpdate(w http.ResponseWriter, r *http.Request) {
	var users []string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&users); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of user names"})
		return
	}
	for _, u := range users {
		s.refreshUser(u)
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", true))
}

func (s *Server) martiGroupsUpdate(w http.ResponseWriter, r *http.Request) {
	if u := r.PathValue("user"); u != "" {
		s.refreshUser(u)
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", true))
}

func (s *Server) martiSubscriptions(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var data []map[string]any
	for _, c := range s.hub.Clients() {
		if c.Relay || !s.visibleTo(id, c.InMask()) {
			continue
		}
		data = append(data, s.subscriptionInfo(c))
	}
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, s.envelope("SubscriptionInfo", data))
}

func (s *Server) subscriptionInfo(c *Client) map[string]any {
	info := c.Info()
	return map[string]any{
		"dn":                        "",
		"callsign":                  info.Callsign,
		"clientUid":                 info.UID,
		"lastReportMillisecondsAgo": time.Since(c.LastSeen()).Milliseconds(),
		"takClient":                 info.Platform != "",
		"lastReportDiffMillis":      time.Since(c.LastSeen()).Milliseconds(),
		"username":                  c.User(),
		"protocol":                  c.Kind,
		"xpath":                     "",
		"subscriptionUid":           strconv.FormatUint(c.ID, 10),
		"team":                      info.Team,
		"role":                      info.Role,
		"takv":                      strings.TrimSpace(info.Platform + " " + info.Version),
		"groups":                    s.dir.Names(c.InMask()),
		"incognito":                 c.incognito.Load(),
		"handlerType":               c.Kind,
		"ipAddress":                 remoteIP(c.Remote),
	}
}

func (s *Server) martiCotXML(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if m := s.hub.CachedEvent(uid); m != nil && s.visibleTo(identityOf(r), m.Groups) {
		writeXML(w, http.StatusOK, string(m.XML()))
		return
	}
	if s.history != nil {
		if evs := s.history.Query(historyQuery{UID: uid, Limit: 1, Latest: true, Can: s.historyFilter(identityOf(r))}); len(evs) > 0 {
			writeXML(w, http.StatusOK, evs[len(evs)-1].String())
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "no event found for uid " + uid})
}

func (s *Server) martiCotXMLAll(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	q := r.URL.Query()
	var start, end time.Time
	if v := q.Get("secago"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			start = time.Now().Add(-time.Duration(n) * time.Second)
		}
	}
	if v := q.Get("start"); v != "" {
		start, _ = cot.ParseTime(v)
	}
	if v := q.Get("end"); v != "" {
		end, _ = cot.ParseTime(v)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><events>`)
	if s.history != nil {
		for _, e := range s.history.Query(historyQuery{UID: uid, Start: start, End: end, Limit: 10000, Can: s.historyFilter(identityOf(r))}) {
			b.Write(e.XML())
		}
	}
	b.WriteString("</events>")
	writeXML(w, http.StatusOK, b.String())
}

func (s *Server) martiCotSA(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := identityOf(r)
	left, _ := strconv.ParseFloat(q.Get("left"), 64)
	right, _ := strconv.ParseFloat(q.Get("right"), 64)
	top, _ := strconv.ParseFloat(q.Get("top"), 64)
	bottom, _ := strconv.ParseFloat(q.Get("bottom"), 64)
	hasBox := q.Get("left") != "" && q.Get("right") != "" && q.Get("top") != "" && q.Get("bottom") != ""
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><events>`)
	for _, m := range s.hub.Cached() {
		if !m.Everyone && !s.visibleTo(id, m.Groups) {
			continue
		}
		p := m.Event.Point
		if hasBox && (p.Lat > top || p.Lat < bottom || p.Lon < left || p.Lon > right) {
			continue
		}
		b.Write(m.XML())
	}
	b.WriteString("</events>")
	writeXML(w, http.StatusOK, b.String())
}
