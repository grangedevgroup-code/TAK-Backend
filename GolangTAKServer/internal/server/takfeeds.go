package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type PredicateFeed struct {
	UUID               string   `json:"uuid"`
	Name               string   `json:"name"`
	PredicateLang      string   `json:"predicateLang"`
	DataSourceEndpoint string   `json:"dataSourceEndpoint"`
	Predicate          string   `json:"predicate"`
	AuthType           string   `json:"authType"`
	Tags               []string `json:"tags"`
	Archive            bool     `json:"archive"`
	Sync               bool     `json:"sync"`
	FilterGroups       []string `json:"filterGroups"`
	Federated          bool     `json:"federated"`
}

func openPredicateFeeds(dataDir string) (*store.Collection[PredicateFeed], error) {
	return store.Open[PredicateFeed](filepath.Join(dataDir, "db", "predicate-feeds.jsonl"), true)
}

func (s *Server) predicateFeedViews() []dataFeedView {
	if s.predFeeds == nil {
		return nil
	}
	var out []dataFeedView
	for _, p := range s.predFeeds.All() {
		out = append(out, dataFeedView{UUID: p.UUID, Name: p.Name, Type: "Predicate", Tags: p.Tags, Auth: firstNonEmpty(p.AuthType, "ANONYMOUS"),
			Archive: p.Archive, Sync: p.Sync, FilterGroups: p.FilterGroups, Federated: p.Federated, Anongroup: len(p.FilterGroups) == 0, Enabled: true,
			PredicateLang: p.PredicateLang, DataSourceEndpoint: p.DataSourceEndpoint, Predicate: p.Predicate})
	}
	return out
}

type takDataFeedBody struct {
	UUID         string   `json:"uuid"`
	Name         string   `json:"name"`
	AltName      string   `json:"_name"`
	Type         string   `json:"type"`
	Protocol     string   `json:"protocol"`
	Port         int      `json:"port"`
	Group        string   `json:"group"`
	Iface        string   `json:"iface"`
	Auth         string   `json:"auth"`
	Archive      *bool    `json:"archive"`
	Sync         *bool    `json:"sync"`
	Tag          []string `json:"tag"`
	Tags         []string `json:"tags"`
	FilterGroup  []string `json:"filtergroup"`
	FilterGroups []string `json:"filterGroups"`
	URL          string   `json:"url"`
	Enabled      *bool    `json:"enabled"`
}

func (b takDataFeedBody) apply(f *DataFeedConfig) {
	if n := firstNonEmpty(b.Name, b.AltName); n != "" {
		f.Name = n
	}
	if b.Protocol != "" {
		f.Protocol = strings.ToLower(b.Protocol)
	}
	if b.Port != 0 {
		f.Port = b.Port
	}
	if b.Group != "" {
		f.Address = b.Group
	}
	if b.Iface != "" {
		f.Interface = b.Iface
	}
	if b.URL != "" {
		f.URL = b.URL
	}
	if b.Archive != nil {
		f.Archive = *b.Archive
	}
	if b.Sync != nil {
		f.Sync = *b.Sync
	}
	if b.Enabled != nil {
		f.Enabled = *b.Enabled
	}
	if t := append(b.Tag, b.Tags...); len(t) > 0 || b.Tag != nil || b.Tags != nil {
		f.Tags = t
	}
	if g := append(b.FilterGroup, b.FilterGroups...); len(g) > 0 || b.FilterGroup != nil || b.FilterGroups != nil {
		f.Groups = g
	}
	if strings.EqualFold(b.Auth, "x509") && f.Protocol != "tls" && f.Protocol != "ssl" {
		f.Protocol = "tls"
	}
}

func readTAKDataFeed(r *http.Request) (takDataFeedBody, error) {
	var b takDataFeedBody
	err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b)
	return b, err
}

func (s *Server) findFeedIndex(c *Config, key string) int {
	for i, f := range c.DataFeeds {
		if f.UUID == key || strings.EqualFold(f.Name, key) {
			return i
		}
	}
	return -1
}

func (s *Server) martiDataFeedCreate(w http.ResponseWriter, r *http.Request) {
	b, err := readTAKDataFeed(r)
	if err != nil || firstNonEmpty(b.Name, b.AltName) == "" {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a data feed with a name"))
		return
	}
	f := DataFeedConfig{UUID: firstNonEmpty(b.UUID, cot.NewUID()), Protocol: "tcp", Enabled: true, Sync: true, Tags: []string{}, Groups: []string{}}
	b.apply(&f)
	_, err = s.UpdateConfig(func(c *Config) error {
		if s.findFeedIndex(c, f.Name) >= 0 || s.findFeedIndex(c, f.UUID) >= 0 {
			return errors.New("a data feed with that name already exists")
		}
		c.DataFeeds = append(c.DataFeeds, f)
		return validateConfig(c)
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	s.syncDataFeeds()
	v, _ := s.dataFeedConfig(f.UUID)
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", v))
}

func (s *Server) martiDataFeedGet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("name")
	id := identityOf(r)
	for _, f := range s.allDataFeeds() {
		if (f.UUID == key || strings.EqualFold(f.Name, key)) && s.feedVisible(id, f) {
			writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", f))
			return
		}
	}
	writeJSON(w, http.StatusNotFound, s.envelope("error", "no such data feed"))
}

func (s *Server) martiDataFeedModify(w http.ResponseWriter, r *http.Request) {
	b, err := readTAKDataFeed(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a data feed"))
		return
	}
	var uuid string
	_, err = s.UpdateConfig(func(c *Config) error {
		i := s.findFeedIndex(c, r.PathValue("name"))
		if i < 0 {
			return errNoFeed
		}
		b.apply(&c.DataFeeds[i])
		uuid = c.DataFeeds[i].UUID
		return validateConfig(c)
	})
	if errors.Is(err, errNoFeed) {
		writeJSON(w, http.StatusNotFound, s.envelope("error", err.Error()))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	s.syncDataFeeds()
	v, _ := s.dataFeedConfig(uuid)
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", v))
}

var errNoFeed = errors.New("no such data feed")

func (s *Server) martiDataFeedDelete(w http.ResponseWriter, r *http.Request) {
	_, err := s.UpdateConfig(func(c *Config) error {
		i := s.findFeedIndex(c, r.PathValue("name"))
		if i < 0 {
			return errNoFeed
		}
		c.DataFeeds = append(c.DataFeeds[:i], c.DataFeeds[i+1:]...)
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, s.envelope("error", err.Error()))
		return
	}
	s.syncDataFeeds()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiPredicateFeedSave(w http.ResponseWriter, r *http.Request) {
	var p PredicateFeed
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a predicate data feed"))
		return
	}
	if r.Method == http.MethodPost && p.UUID == "" {
		p.UUID = cot.NewUID()
	}
	if p.UUID == "" {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "predicate feed in request has empty uuid"))
		return
	}
	old, exists := s.predFeeds.Get(p.UUID)
	if r.Method == http.MethodPut && !exists {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such predicate data feed"))
		return
	}
	if r.Method == http.MethodPost && exists {
		writeJSON(w, http.StatusConflict, s.envelope("error", "a predicate data feed with that uuid already exists"))
		return
	}
	if r.Method == http.MethodPut && !boolParam(r, "updateGroups") {
		p.FilterGroups = old.FilterGroups
	}
	if p.Name == "" {
		p.Name = firstNonEmpty(old.Name, p.UUID)
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	if p.FilterGroups == nil {
		p.FilterGroups = []string{}
	}
	if err := s.predFeeds.Put(p.UUID, p); err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("tak.server.plugins.PredicateDataFeed", p))
}

func (s *Server) martiPredicateFeedGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.predFeeds.Get(r.PathValue("uuid"))
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such predicate data feed"))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("tak.server.plugins.PredicateDataFeed", p))
}

func (s *Server) martiPredicateFeedDelete(w http.ResponseWriter, r *http.Request) {
	if !s.predFeeds.Has(r.PathValue("uuid")) {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such predicate data feed"))
		return
	}
	s.predFeeds.Delete(r.PathValue("uuid"))
	w.WriteHeader(http.StatusOK)
}

func parsePolygonBody(body []byte) [][2]float64 {
	var raw []any
	if json.Unmarshal(body, &raw) != nil {
		return parseFilterPolygon(string(body))
	}
	var poly [][2]float64
	num := func(v any) (float64, bool) { f, ok := v.(float64); return f, ok }
	for _, item := range raw {
		switch p := item.(type) {
		case []any:
			if len(p) >= 2 {
				lon, ok1 := num(p[0])
				lat, ok2 := num(p[1])
				if ok1 && ok2 {
					poly = append(poly, [2]float64{lat, lon})
				}
			}
		case map[string]any:
			lat, ok1 := num(firstAny(p, "lat", "latitude"))
			lon, ok2 := num(firstAny(p, "lon", "lng", "longitude"))
			if ok1 && ok2 {
				poly = append(poly, [2]float64{lat, lon})
			}
		}
	}
	return poly
}

func firstAny(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}

func (s *Server) martiDataFeedsInPolygon(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte(r.URL.Query().Get("polygon"))
	}
	poly := parsePolygonBody(body)
	if len(poly) < 3 {
		writeJSON(w, http.StatusBadRequest, s.envelope("tak.server.feeds.DataFeed", []string{}))
		return
	}
	id := identityOf(r)
	out := []string{}
	for _, f := range s.allDataFeeds() {
		if !s.feedVisible(id, f) {
			continue
		}
		for _, m := range s.dfeeds.state(f.UUID).cached(s.feedRetention()) {
			if pointInPolygon(m.Event.Point.Lat, m.Event.Point.Lon, poly) {
				out = append(out, f.UUID)
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", out))
}
