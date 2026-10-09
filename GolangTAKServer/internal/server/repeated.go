package server

import (
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type RepeatedMessage struct {
	UID      string    `json:"uid"`
	Type     string    `json:"type"`
	Callsign string    `json:"callsign"`
	XML      string    `json:"xml"`
	Groups   []string  `json:"groups"`
	Everyone bool      `json:"everyone"`
	Lifetime int64     `json:"lifetimeSec"`
	Creator  string    `json:"creator"`
	Created  time.Time `json:"created"`
}

type Repeated struct {
	db *store.Collection[RepeatedMessage]
}

func OpenRepeated(dataDir string) (*Repeated, error) {
	db, err := store.Open[RepeatedMessage](filepath.Join(dataDir, "db", "repeated.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &Repeated{db: db}, nil
}

func (rp *Repeated) Close() { rp.db.Close() }

func (s *Server) addRepeated(m *Message, creator string) RepeatedMessage {
	e := m.Event
	life := int64(e.Stale.Sub(e.Start) / time.Second)
	if life < 60 {
		life = 300
	}
	rm := RepeatedMessage{UID: e.UID, Type: e.Type, Callsign: e.Callsign(), XML: e.String(), Groups: s.dir.Names(m.Groups), Everyone: m.Everyone, Lifetime: life, Creator: creator, Created: time.Now().UTC()}
	s.repeated.db.Put(rm.UID, rm)
	s.log.Info("message will be repeated", "uid", rm.UID, "type", rm.Type, "by", creator)
	return rm
}

func (s *Server) repeatedMessage(rm RepeatedMessage) *Message {
	e, err := cot.Parse([]byte(rm.XML))
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	e.Time, e.Start, e.Stale = now, now, now.Add(time.Duration(rm.Lifetime)*time.Second)
	m := NewMessage(e, nil, s.dir.Mask(rm.Groups))
	m.Everyone = rm.Everyone || len(rm.Groups) == 0
	return m
}

func (s *Server) repeatedList() []RepeatedMessage {
	list := s.repeated.db.All()
	sort.Slice(list, func(i, j int) bool { return list[i].Created.After(list[j].Created) })
	return list
}

func (s *Server) sendRepeated(c *Client) {
	if s.repeated == nil {
		return
	}
	for _, rm := range s.repeated.db.All() {
		if m := s.repeatedMessage(rm); m != nil && s.hub.visible(c, m) {
			c.Send(m)
		}
	}
}

func (s *Server) repeatAll() {
	if s.repeated == nil {
		return
	}
	for _, rm := range s.repeated.db.All() {
		if m := s.repeatedMessage(rm); m != nil {
			s.hub.Publish(m)
		}
	}
}

func (s *Server) removeRepeated(uid string) bool {
	rm, ok := s.repeated.db.Get(uid)
	if !ok {
		return false
	}
	s.repeated.db.Delete(uid)
	m := NewMessage(cot.DeleteFor(uid, rm.Type), nil, s.dir.Mask(rm.Groups))
	m.Everyone = rm.Everyone || len(rm.Groups) == 0
	m.NoReplay = true
	s.hub.Publish(m)
	s.log.Info("message no longer repeated", "uid", uid)
	return true
}

func (s *Server) apiRepeatedList(w http.ResponseWriter, r *http.Request) {
	out := s.repeatedList()
	for i := range out {
		out[i].XML = ""
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiRepeatedAdd(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	c := s.hub.CachedEvent(uid)
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no current object with that UID; it must be on the map to repeat it"})
		return
	}
	rm := s.addRepeated(c, identityOf(r).Name)
	rm.XML = ""
	writeJSON(w, http.StatusOK, rm)
}

func (s *Server) apiRepeatedDelete(w http.ResponseWriter, r *http.Request) {
	if !s.removeRepeated(r.PathValue("uid")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "that object is not being repeated"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ftsRepeatedGet(w http.ResponseWriter, r *http.Request) {
	msgs := map[string]string{}
	for _, rm := range s.repeatedList() {
		if m := s.repeatedMessage(rm); m != nil {
			msgs[rm.UID] = m.Event.String()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

func (s *Server) ftsRepeatedDelete(w http.ResponseWriter, r *http.Request) {
	ids := splitList(r.URL.Query().Get("ids"))
	if len(ids) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "ids is a required parameter"})
		return
	}
	ok := true
	for _, id := range ids {
		if !s.removeRepeated(strings.TrimSpace(id)) {
			ok = false
		}
	}
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "operation failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "operation successful"})
}
