package server

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type VBMConfig struct {
	Enabled               bool   `json:"vbmEnabled"`
	SADisabled            bool   `json:"saDisabled"`
	ChatDisabled          bool   `json:"chatDisabled"`
	NetworkClassification string `json:"networkClassification,omitempty"`
	CopTool               string `json:"copTool,omitempty"`
}

type uidProps struct {
	UID   string              `json:"uid"`
	Props map[string][]string `json:"props"`
}

type sequences struct {
	mu sync.Mutex
	m  map[string]int
}

func openProps(dataDir string) (*store.Collection[uidProps], error) {
	return store.Open[uidProps](filepath.Join(dataDir, "db", "properties.jsonl"), true)
}

func (s *Server) takExtraRoutes(m, a func(string, http.HandlerFunc)) {
	m("GET /Marti/api/properties/uids", func(w http.ResponseWriter, r *http.Request) {
		keys := s.props.Keys()
		sort.Strings(keys)
		writeJSON(w, http.StatusOK, s.envelope("UIDs", keys))
	})
	m("GET /Marti/api/properties/{uid}/{key}", s.propsGet)
	m("PUT /Marti/api/properties/{uid}", s.propsPut)
	m("DELETE /Marti/api/properties/{uid}/{key}", s.propsDelete)

	m("GET /Marti/api/uidsearch", s.uidSearch)
	m("GET /Marti/api/cot/matchUid", s.cotMatchUID)
	a("GET /Marti/api/database/cotCount", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.envelope("java.util.Map", map[string]int{"cotEvents": len(s.hub.Cached()), "cotImages": 0}))
	})
	m("GET /Marti/api/missioncount", s.missionCount)
	m("GET /Marti/api/sync/sequence/{key}", func(w http.ResponseWriter, r *http.Request) {
		s.seq.mu.Lock()
		if s.seq.m == nil {
			s.seq.m = map[string]int{}
		}
		s.seq.m[r.PathValue("key")]++
		n := s.seq.m[r.PathValue("key")]
		s.seq.mu.Unlock()
		writeText(w, http.StatusOK, strconv.Itoa(n))
	})
	m("GET /Marti/api/cops", s.copList)
	m("GET /Marti/api/cops/hierarchy", s.copHierarchy)
	m("GET /Marti/vbm/api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.Config().VBM) })
	a("POST /Marti/vbm/api/config", s.vbmSet)
	m("GET /Marti/vbm/api/classification", func(w http.ResponseWriter, r *http.Request) {
		writeText(w, http.StatusOK, s.Config().VBM.NetworkClassification)
	})
	a("GET /Marti/api/activeconnections", s.activeConnections)
}

func (s *Server) propsGet(w http.ResponseWriter, r *http.Request) {
	p, _ := s.props.Get(r.PathValue("uid"))
	key := r.PathValue("key")
	if key == "all" {
		out := p.Props
		if out == nil {
			out = map[string][]string{}
		}
		writeJSON(w, http.StatusOK, s.envelope("Properties", out))
		return
	}
	vals := p.Props[key]
	if vals == nil {
		vals = []string{}
	}
	writeJSON(w, http.StatusOK, s.envelope("Properties", vals))
}

func (s *Server) propsPut(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var kv map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&kv); err != nil || len(kv) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `expected {"key": "value"}`})
		return
	}
	var key, val string
	if k, ok := kv["key"].(string); ok {
		key, val = k, jsonString(kv["value"])
	} else {
		for k, v := range kv {
			key, val = k, strings.TrimSpace(strings.Trim(jsonString(v), `"`))
		}
	}
	if key == "" || len(key) > 256 || len(val) > 8192 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key and value are required"})
		return
	}
	s.props.Update(uid, func(p uidProps, _ bool) (uidProps, bool, error) {
		p.UID = uid
		if p.Props == nil {
			p.Props = map[string][]string{}
		}
		if !slices.Contains(p.Props[key], val) {
			p.Props[key] = append(p.Props[key], val)
		}
		return p, true, nil
	})
	writeJSON(w, http.StatusOK, s.envelope("KeyValuePair", map[string]string{key: val}))
}

func jsonString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func (s *Server) propsDelete(w http.ResponseWriter, r *http.Request) {
	uid, key := r.PathValue("uid"), r.PathValue("key")
	if key == "all" {
		s.props.Delete(uid)
	} else {
		s.props.Update(uid, func(p uidProps, exists bool) (uidProps, bool, error) {
			if !exists {
				return p, false, nil
			}
			delete(p.Props, key)
			return p, true, nil
		})
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) uidSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	start, err1 := time.Parse("2006-01-02", q.Get("startDate"))
	end, err2 := time.Parse("2006-01-02", q.Get("endDate"))
	if err1 != nil || err2 != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "startDate and endDate are required as YYYY-MM-DD"})
		return
	}
	end = end.Add(24 * time.Hour)
	out := []map[string]string{}
	for _, d := range s.devices.All() {
		if d.LastSeen.Before(start) || d.FirstSeen.After(end) {
			continue
		}
		out = append(out, map[string]string{"uid": d.UID, "callsign": d.Callsign})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["callsign"] < out[j]["callsign"] })
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.UIDResult", out))
}

func (s *Server) cotMatchUID(w http.ResponseWriter, r *http.Request) {
	needle := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	id := identityOf(r)
	seen := map[string]bool{}
	out := []string{}
	for _, m := range s.hub.Cached() {
		uid := m.Event.UID
		if seen[uid] || (!m.Everyone && !s.visibleTo(id, m.Groups)) {
			continue
		}
		if needle == "" || strings.Contains(strings.ToLower(uid), needle) {
			seen[uid] = true
			out = append(out, uid)
		}
	}
	sort.Strings(out)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) missionCount(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	withPassword := q.Get("passwordProtected") != "false"
	tool := q.Get("tool")
	n := 0
	for _, m := range s.missions.All() {
		if !withPassword && m.PasswordHash != "" {
			continue
		}
		if tool != "" && !strings.EqualFold(firstNonEmpty(m.Tool, "public"), tool) {
			continue
		}
		n++
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", n))
}

func (s *Server) copTool() string { return firstNonEmpty(s.Config().VBM.CopTool, "vbm") }

func (s *Server) copMissions(r *http.Request) []Mission {
	id := identityOf(r)
	tool := s.copTool()
	var out []Mission
	for _, m := range s.missions.All() {
		if strings.EqualFold(m.Tool, tool) && s.missionVisible(id, m) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) copList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	path := strings.Trim(q.Get("path"), "/")
	list := []any{}
	for _, m := range s.copMissions(r) {
		p := strings.Trim(m.Path, "/")
		if path != "" && p != path && !strings.HasPrefix(p, path+"/") {
			continue
		}
		list = append(list, s.missionJSON(m, missionOpts{}))
	}
	if off, err := strconv.Atoi(q.Get("offset")); err == nil && off > 0 {
		list = list[min(off, len(list)):]
	}
	if size, err := strconv.Atoi(q.Get("size")); err == nil && size > 0 && size < len(list) {
		list = list[:size]
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", list))
}

type copNode struct {
	Name     string     `json:"name"`
	Children []*copNode `json:"children"`
}

func (s *Server) copHierarchy(w http.ResponseWriter, r *http.Request) {
	root := &copNode{}
	index := map[string]*copNode{}
	for _, m := range s.copMissions(r) {
		p := strings.Trim(m.Path, "/")
		if p == "" {
			continue
		}
		parent, acc := root, ""
		for _, level := range strings.Split(p, "/") {
			acc += "/" + level
			n := index[acc]
			if n == nil {
				n = &copNode{Name: level, Children: []*copNode{}}
				index[acc] = n
				parent.Children = append(parent.Children, n)
			}
			parent = n
		}
	}
	if root.Children == nil {
		root.Children = []*copNode{}
	}
	writeJSON(w, http.StatusOK, s.envelope("CopHierarchyNode", root.Children))
}

func (s *Server) vbmSet(w http.ResponseWriter, r *http.Request) {
	var v VBMConfig
	if err := readJSON(r, &v); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.UpdateConfig(func(c *Config) error {
		v.CopTool = c.VBM.CopTool
		c.VBM = v
		return nil
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) activeConnections(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, p := range s.peerStatus() {
		if p.State != "connected" {
			continue
		}
		out = append(out, map[string]any{"federateId": p.Name, "connectionId": p.URL, "remoteAddress": p.URL, "direction": strings.ToUpper(p.Direction),
			"connectionStatusValue": "CONNECTED", "since": p.Since, "messagesReceived": p.Rx, "messagesSent": p.Tx})
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.FederationApi.ConnectionInfoSummary", out))
}

func (h *Hub) vbmBlocks(m *Message) bool {
	v := h.vbm.Load()
	if v == nil || !v.Enabled || m.Source == nil || m.Source.Relay {
		return false
	}
	e := m.Event
	return (v.SADisabled && e.IsSA()) || (v.ChatDisabled && e.IsChat())
}
