package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (s *Server) martiResource(w http.ResponseWriter, r *http.Request) {
	res, ok := s.res.Get(r.PathValue("hash"))
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "resource not found"))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("Resource", resourceJSON(res)))
}

func (s *Server) martiFilePutMetadata(w http.ResponseWriter, r *http.Request) {
	res, ok := s.res.Get(r.PathValue("hash"))
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	if !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusForbidden, "only the submitter or an administrator can change this file")
		return
	}
	q := r.URL.Query()
	var exp *int64
	if v := q.Get("expiration"); v != "" {
		n, err := parseInt64(v)
		if err != nil {
			writeText(w, http.StatusBadRequest, "expiration must be seconds since 1970 or -1")
			return
		}
		exp = &n
	}
	var keywords []string
	for _, v := range q["keywords"] {
		keywords = append(keywords, splitList(v)...)
	}
	s.res.Update(res.UID, func(x *Resource) {
		if u := q.Get("user"); u != "" {
			x.Submitter = u
		}
		if exp != nil {
			x.Expiration = *exp
		}
		if q.Has("keywords") {
			x.Keywords = keywords
			if x.Keywords == nil {
				x.Keywords = []string{}
			}
		}
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiSetMetadata(w http.ResponseWriter, r *http.Request) {
	res, ok := s.res.Get(r.PathValue("hash"))
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	if !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusForbidden, "only the submitter or an administrator can change this file")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	value := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(body)), `"`))
	field := strings.ToLower(r.PathValue("metadata"))
	var fail string
	s.res.Update(res.UID, func(x *Resource) {
		switch field {
		case "tool":
			x.Tool = firstNonEmpty(value, "public")
		case "name", "filename", "downloadpath":
			if value != "" {
				x.Name = safeFileName(value)
			}
		case "mimetype":
			x.MIMEType = value
		case "creatoruid":
			x.CreatorUID = value
		case "submissionuser", "submitter":
			x.Submitter = value
		case "keywords":
			x.Keywords = splitList(value)
		case "expiration":
			if n, err := parseInt64(value); err == nil {
				x.Expiration = n
			} else {
				fail = "expiration must be a number"
			}
		case "latitude":
			x.Lat, _ = strconv.ParseFloat(value, 64)
		case "longitude":
			x.Lon, _ = strconv.ParseFloat(value, 64)
		case "altitude":
			x.Alt, _ = strconv.ParseFloat(value, 64)
		default:
			fail = "unknown metadata field " + r.PathValue("metadata")
		}
	})
	if fail != "" {
		writeText(w, http.StatusBadRequest, fail)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) takUserJSON(c *Client) map[string]any {
	groups := []map[string]any{}
	in, out := c.InMask(), c.OutMask()
	for _, name := range s.dir.Names(in.Union(out)) {
		g, ok := s.dir.Group(name)
		if !ok {
			continue
		}
		if in.Has(g.Bit) {
			groups = append(groups, s.groupJSON(g, DirIn, true))
		}
		if out.Has(g.Bit) {
			groups = append(groups, s.groupJSON(g, DirOut, true))
		}
	}
	user := c.User()
	authorities := []string{"ROLE_ANONYMOUS"}
	if id := c.Identity(); id != nil && !id.Anon {
		authorities = []string{"ROLE_USER"}
		if id.Admin {
			authorities = []string{"ROLE_ADMIN"}
		}
	}
	connType := "CORE"
	switch c.Kind {
	case KindFederation:
		connType = "FEDERATE"
	case KindWebSocket:
		connType = "WEBSOCKET"
	}
	return map[string]any{
		"id": strconv.FormatUint(c.ID, 10), "connectionId": strconv.FormatUint(c.ID, 10), "name": firstNonEmpty(user, "anonymous"),
		"connectionType": connType, "address": remoteIP(c.Remote), "created": isoTime(c.Connected), "authorities": authorities,
		"uid": c.UID(), "callsign": c.Callsign(), "groups": groups,
	}
}

func (s *Server) martiUsersAll(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []map[string]any{}
	for _, c := range s.hub.Clients() {
		if c.Relay && c.Kind != KindFederation {
			continue
		}
		if !s.visibleTo(id, c.InMask().Union(c.OutMask())) {
			continue
		}
		out = append(out, s.takUserJSON(c))
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.groups.User", out))
}

func (s *Server) martiUserByConnection(w http.ResponseWriter, r *http.Request) {
	c := s.clientByUID(r.PathValue("id"))
	if c == nil || !s.visibleTo(identityOf(r), c.InMask().Union(c.OutMask())) {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such connection"))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.groups.User", s.takUserJSON(c)))
}

func (s *Server) martiHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) martiVer(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusOK, s.Version)
}

func (s *Server) martiIsLdapAdmin(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	writeJSON(w, http.StatusOK, id != nil && id.Admin && s.Config().LDAP.Enabled)
}

func (s *Server) martiGroupMembers(w http.ResponseWriter, r *http.Request) {
	filters := r.URL.Query()["groupNameFilter"]
	var want []string
	for _, f := range filters {
		want = append(want, splitList(f)...)
	}
	out := map[string][]string{}
	for _, u := range s.dir.Users() {
		for _, g := range append(append([]string{}, u.In...), u.Out...) {
			if len(want) > 0 && !slices.ContainsFunc(want, func(f string) bool { return strings.Contains(strings.ToLower(g), strings.ToLower(f)) }) {
				continue
			}
			if !slices.Contains(out[g], u.Name) {
				out[g] = append(out[g], u.Name)
			}
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.util.Map", out))
}

func (s *Server) martiCotByUIDs(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var uids []string
	if t := bytes.TrimSpace(body); len(t) > 0 {
		if err := json.Unmarshal(t, &uids); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of UIDs"})
			return
		}
	}
	for _, v := range r.URL.Query()["uid"] {
		uids = append(uids, splitList(v)...)
	}
	if len(uids) == 0 {
		s.martiCotSA(w, r)
		return
	}
	id := identityOf(r)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><events>`)
	for _, uid := range uids {
		if m := s.hub.CachedEvent(uid); m != nil && (m.Everyone || s.visibleTo(id, m.Groups)) {
			b.Write(m.XML())
			continue
		}
		if s.history != nil {
			if evs := s.history.Query(historyQuery{UID: uid, Limit: 1, Latest: true, Can: s.historyFilter(id)}); len(evs) > 0 {
				b.Write(evs[len(evs)-1].XML())
			}
		}
	}
	b.WriteString("</events>")
	writeXML(w, http.StatusOK, b.String())
}

func (s *Server) martiServerTime(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, map[string]any{"time": now.UnixMilli(), "iso": isoTime(now)})
}

func (s *Server) martiGetCotData(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	uid := r.Form.Get("uid")
	if uid == "" {
		writeText(w, http.StatusBadRequest, "either uid or cotId must be specified as a request parameter")
		return
	}
	id := identityOf(r)
	var xml []byte
	if m := s.hub.CachedEvent(uid); m != nil && (m.Everyone || s.visibleTo(id, m.Groups)) {
		xml = m.XML()
	} else if s.history != nil {
		if evs := s.history.Query(historyQuery{UID: uid, Limit: 1, Latest: true, Can: s.historyFilter(id)}); len(evs) > 0 {
			xml = evs[len(evs)-1].XML()
		}
	}
	if xml == nil {
		writeText(w, http.StatusNotFound, "no event for uid "+uid)
		return
	}
	if r.Form.Get("xml") != "" || strings.Contains(r.Header.Get("Accept"), "xml") {
		writeXML(w, http.StatusOK, string(xml))
		return
	}
	m := s.hub.CachedEvent(uid)
	if m == nil {
		writeXML(w, http.StatusOK, string(xml))
		return
	}
	e := m.Event
	remarks := ""
	if n := e.D("remarks"); n != nil {
		remarks = n.Text
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uid": e.UID, "type": e.Type, "how": e.How, "lat": e.Point.Lat, "lon": e.Point.Lon, "hae": e.Point.Hae,
		"ce": e.Point.Ce, "le": e.Point.Le, "remarks": remarks, "detail": e.Detail.String(),
	})
}
