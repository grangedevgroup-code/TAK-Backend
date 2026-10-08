package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/xmltree"
)

const (
	KindFeed = "feed"

	FeedADSB       = "golangtak-adsb"
	FeedAIS        = "golangtak-ais"
	FeedMeshtastic = "golangtak-meshtastic"

	feedSyncLimit = 20000
)

type DataFeedConfig struct {
	UUID      string   `json:"uuid"`
	Name      string   `json:"name"`
	Protocol  string   `json:"protocol"`
	Port      int      `json:"port"`
	Address   string   `json:"address,omitempty"`
	Interface string   `json:"iface,omitempty"`
	Groups    []string `json:"groups"`
	Tags      []string `json:"tags"`
	Archive   bool     `json:"archive"`
	Sync      bool     `json:"sync"`
	Enabled   bool     `json:"enabled"`
}

type MissionFeed struct {
	UID            string   `json:"uid"`
	DataFeedUID    string   `json:"dataFeedUid"`
	FilterPolygon  string   `json:"filterPolygon,omitempty"`
	FilterCotTypes []string `json:"filterCotTypes,omitempty"`
	FilterCallsign string   `json:"filterCallsign,omitempty"`
}

type dataFeedState struct {
	uuid   string
	mu     sync.Mutex
	count  int64
	bytes  int64
	first  time.Time
	last   time.Time
	minLat float64
	minLon float64
	maxLat float64
	maxLon float64
	types  map[string]bool
	latest map[string]*Message
	err    string
}

type missionFeedRef struct {
	mission string
	feed    MissionFeed
	poly    [][2]float64
}

type dataFeeds struct {
	mu     sync.Mutex
	states map[string]*dataFeedState
	index  map[string][]missionFeedRef
}

func newDataFeeds() *dataFeeds {
	return &dataFeeds{states: map[string]*dataFeedState{}, index: map[string][]missionFeedRef{}}
}

func (d *dataFeeds) state(uuid string) *dataFeedState {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.states[uuid]
	if st == nil {
		st = &dataFeedState{uuid: uuid, types: map[string]bool{}, latest: map[string]*Message{}}
		d.states[uuid] = st
	}
	return st
}

func (d *dataFeeds) setError(uuid, msg string) {
	st := d.state(uuid)
	st.mu.Lock()
	st.err = msg
	st.mu.Unlock()
}

func (st *dataFeedState) record(m *Message, sync bool, retention time.Duration) {
	e := m.Event
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.count == 0 {
		st.first = now
		st.minLat, st.maxLat, st.minLon, st.maxLon = e.Point.Lat, e.Point.Lat, e.Point.Lon, e.Point.Lon
	}
	st.count++
	st.bytes += int64(len(m.XML()))
	st.last = now
	if e.Point.Lat != 0 || e.Point.Lon != 0 {
		st.minLat, st.maxLat = min(st.minLat, e.Point.Lat), max(st.maxLat, e.Point.Lat)
		st.minLon, st.maxLon = min(st.minLon, e.Point.Lon), max(st.maxLon, e.Point.Lon)
	}
	if len(st.types) < 1000 {
		st.types[e.Type] = true
	}
	if !sync {
		return
	}
	if _, ok := st.latest[e.UID]; !ok && len(st.latest) >= feedSyncLimit {
		cutoff := now.Add(-retention)
		for k, old := range st.latest {
			if old.Received.Before(cutoff) || old.Event.IsStale(now) {
				delete(st.latest, k)
			}
		}
		if len(st.latest) >= feedSyncLimit {
			return
		}
	}
	st.latest[e.UID] = m
}

func (st *dataFeedState) cached(retention time.Duration) []*Message {
	now := time.Now()
	cutoff := now.Add(-retention)
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*Message, 0, len(st.latest))
	for k, m := range st.latest {
		if m.Received.Before(cutoff) {
			delete(st.latest, k)
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Event.UID < out[j].Event.UID })
	return out
}

type dataFeedView struct {
	UUID                       string   `json:"uuid"`
	Name                       string   `json:"name"`
	Type                       string   `json:"type"`
	Tags                       []string `json:"tags"`
	Auth                       string   `json:"auth"`
	Port                       int      `json:"port,omitempty"`
	AuthRequired               bool     `json:"authRequired"`
	Protocol                   string   `json:"protocol,omitempty"`
	Group                      string   `json:"group,omitempty"`
	Iface                      string   `json:"iface,omitempty"`
	Archive                    bool     `json:"archive"`
	Anongroup                  bool     `json:"anongroup"`
	ArchiveOnly                bool     `json:"archiveOnly"`
	Sync                       bool     `json:"sync"`
	CoreVersion                int      `json:"coreVersion"`
	FilterGroups               []string `json:"filterGroups"`
	SyncCacheRetentionSeconds  int      `json:"syncCacheRetentionSeconds"`
	Federated                  bool     `json:"federated"`
	BinaryPayloadWebsocketOnly bool     `json:"binaryPayloadWebsocketOnly"`

	Enabled  bool   `json:"enabled"`
	Messages int64  `json:"messages"`
	LastSeen string `json:"lastSeen,omitempty"`
	Error    string `json:"error,omitempty"`
	BuiltIn  bool   `json:"builtIn,omitempty"`
}

func (s *Server) feedRetention() time.Duration {
	return time.Hour
}

func (s *Server) allDataFeeds() []dataFeedView {
	cfg := s.Config()
	var out []dataFeedView
	add := func(v dataFeedView) {
		if v.Tags == nil {
			v.Tags = []string{}
		}
		if v.FilterGroups == nil {
			v.FilterGroups = []string{}
		}
		v.SyncCacheRetentionSeconds = int(s.feedRetention() / time.Second)
		v.CoreVersion = 2
		st := s.dfeeds.state(v.UUID)
		st.mu.Lock()
		v.Messages = st.count
		if !st.last.IsZero() {
			v.LastSeen = isoTime(st.last)
		}
		if v.Error == "" {
			v.Error = st.err
		}
		st.mu.Unlock()
		out = append(out, v)
	}
	for _, f := range cfg.DataFeeds {
		auth := "ANONYMOUS"
		if strings.EqualFold(f.Protocol, "tls") {
			auth = "X_509"
		}
		add(dataFeedView{UUID: f.UUID, Name: f.Name, Type: "Streaming", Tags: f.Tags, Auth: auth, AuthRequired: auth == "X_509", Port: f.Port, Protocol: strings.ToLower(f.Protocol), Group: f.Address, Iface: f.Interface, Archive: f.Archive, Anongroup: len(f.Groups) == 0, Sync: f.Sync, FilterGroups: f.Groups, Enabled: f.Enabled})
	}
	group := func(g string) []string {
		if g == "" {
			return nil
		}
		return []string{g}
	}
	add(dataFeedView{UUID: FeedADSB, Name: "ADS-B aircraft", Type: "API", Tags: []string{"adsb", "aircraft"}, Auth: "ANONYMOUS", Anongroup: cfg.Feeds.ADSB.Group == "", Sync: true, FilterGroups: group(cfg.Feeds.ADSB.Group), Enabled: cfg.Feeds.ADSB.Enabled, BuiltIn: true})
	add(dataFeedView{UUID: FeedAIS, Name: "AIS ships", Type: "API", Tags: []string{"ais", "maritime"}, Auth: "ANONYMOUS", Anongroup: cfg.Feeds.AIS.Group == "", Sync: true, FilterGroups: group(cfg.Feeds.AIS.Group), Enabled: cfg.Feeds.AIS.Enabled, BuiltIn: true})
	add(dataFeedView{UUID: FeedMeshtastic, Name: "Meshtastic", Type: "Plugin", Tags: []string{"meshtastic", "lora"}, Auth: "ANONYMOUS", Anongroup: cfg.Meshtastic.Group == "", Archive: true, Sync: true, FilterGroups: group(cfg.Meshtastic.Group), Enabled: cfg.Meshtastic.Enabled, BuiltIn: true})
	for _, f := range s.federatedFeeds() {
		add(f)
	}
	return out
}

func (s *Server) dataFeedConfig(uuid string) (dataFeedView, bool) {
	for _, f := range s.allDataFeeds() {
		if f.UUID == uuid {
			return f, true
		}
	}
	return dataFeedView{}, false
}

func (s *Server) feedVisible(id *Identity, f dataFeedView) bool {
	if id.Admin || len(f.FilterGroups) == 0 {
		return true
	}
	return slices.ContainsFunc(f.FilterGroups, func(g string) bool { return slices.Contains(s.identityGroups(id), g) })
}

func (s *Server) onFeedMessage(m *Message) {
	f, ok := s.dataFeedConfig(m.Feed)
	sync := !ok || f.Sync
	s.dfeeds.state(m.Feed).record(m, sync, s.feedRetention())
	s.feedToMissions(m)
}

func (s *Server) startDataFeeds() {
	for _, f := range s.Config().DataFeeds {
		if !f.Enabled {
			continue
		}
		if err := s.startDataFeed(f); err != nil {
			s.dfeeds.setError(f.UUID, err.Error())
			s.log.Error("data feed could not start", "feed", f.Name, "err", err)
			continue
		}
		s.dfeeds.setError(f.UUID, "")
		s.log.Info("data feed listening", "feed", f.Name, "protocol", f.Protocol, "port", f.Port)
	}
}

func (s *Server) feedClient(f DataFeedConfig, addr string) *Client {
	for _, g := range f.Groups {
		s.dir.EnsureGroup(g, "Data feed", false)
	}
	c := s.relayClient(KindFeed, f.Name, addr, f.Groups)
	c.filter = func(*Message) bool { return false }
	s.hub.Add(c)
	return c
}

func (s *Server) startDataFeed(f DataFeedConfig) error {
	if f.Port <= 0 || f.Port > 65535 {
		return fmt.Errorf("port %d is not valid", f.Port)
	}
	addr := s.addr(f.Port)
	switch strings.ToLower(f.Protocol) {
	case "tcp", "stcp", "tls", "ssl":
		ln, err := s.listenTCP(f.Port)
		if err != nil {
			return err
		}
		secure := strings.EqualFold(f.Protocol, "tls") || strings.EqualFold(f.Protocol, "ssl")
		if secure {
			ln = tls.NewListener(ln, s.streamTLSConfig(true))
		}
		c := s.feedClient(f, addr)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.hub.Remove(c)
			for {
				conn, err := ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
					continue
				}
				go s.serveFeedConn(f, c, conn, secure)
			}
		}()
	case "udp", "mcast", "multicast":
		var pc net.PacketConn
		if strings.EqualFold(f.Protocol, "udp") {
			p, err := net.ListenPacket("udp", addr)
			if err != nil {
				return portError("udp", addr, err)
			}
			pc = p
		} else {
			ga, err := net.ResolveUDPAddr("udp", net.JoinHostPort(f.Address, strconv.Itoa(f.Port)))
			if err != nil || ga.IP == nil || !ga.IP.IsMulticast() {
				return fmt.Errorf("multicast feeds need a multicast address, not %q", f.Address)
			}
			var ifi *net.Interface
			if f.Interface != "" {
				if ifi, err = net.InterfaceByName(f.Interface); err != nil {
					return err
				}
			}
			uc, err := net.ListenMulticastUDP("udp", ifi, ga)
			if err != nil {
				return err
			}
			pc = uc
		}
		s.track(pc)
		c := s.feedClient(f, addr)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.hub.Remove(c)
			buf := make([]byte, 65536)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
						return
					}
					continue
				}
				for _, e := range decodeDatagram(append([]byte(nil), buf[:n]...)) {
					c.touch()
					s.ingestFeed(c, f, e, from.String())
				}
			}
		}()
	default:
		return fmt.Errorf("protocol %q is not supported; use tcp, tls, udp or mcast", f.Protocol)
	}
	return nil
}

func (s *Server) serveFeedConn(f DataFeedConfig, c *Client, conn net.Conn, secure bool) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	if secure {
		tc := conn.(*tls.Conn)
		tc.SetDeadline(time.Now().Add(20 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		tc.SetDeadline(time.Time{})
		pc := tc.ConnectionState().PeerCertificates
		if len(pc) == 0 {
			return
		}
		if _, err := s.identityFromCert(pc[0]); err != nil {
			s.log.Warn("data feed certificate rejected", "feed", f.Name, "remote", remote, "err", err)
			return
		}
	}
	cfg := s.Config()
	idle := time.Duration(cfg.Limits.IdleTimeoutSec) * time.Second
	r := takproto.NewReader(conn, cfg.Limits.MaxMessageBytes)
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		fr, err := r.Next()
		if err != nil {
			return
		}
		e := frameEvent(fr)
		if e == nil {
			continue
		}
		c.touch()
		s.ingestFeed(c, f, e, remote)
	}
}

func frameEvent(f takproto.Frame) *cot.Event {
	if f.Proto {
		msg, err := takproto.Unmarshal(f.Data)
		if err != nil || msg.Event == nil {
			return nil
		}
		return msg.Event
	}
	n, err := xmltree.Parse(f.Data)
	if err != nil || n.Name != "event" {
		return nil
	}
	e, err := cot.FromNode(n)
	if err != nil {
		return nil
	}
	return e
}

func (s *Server) ingestFeed(c *Client, f DataFeedConfig, e *cot.Event, from string) {
	if e.IsPing() || consumedTypes[e.Type] || strings.HasPrefix(e.Type, "t-x-takp") || e.FlowTag(s.FlowKey()) != "" {
		return
	}
	mask := c.InMask()
	if len(f.Groups) > 0 {
		mask = s.dir.Mask(f.Groups)
	}
	m := NewMessage(e, c, mask)
	m.Everyone = len(f.Groups) == 0
	m.Feed = f.UUID
	m.NoHistory = !f.Archive
	s.hub.Publish(m)
}

func parseFilterPolygon(s string) [][2]float64 {
	var pts [][2]float64
	for _, p := range strings.Split(s, ",") {
		xy := strings.Fields(p)
		if len(xy) != 2 {
			return nil
		}
		x, err1 := strconv.ParseFloat(xy[0], 64)
		y, err2 := strconv.ParseFloat(xy[1], 64)
		if err1 != nil || err2 != nil {
			return nil
		}
		pts = append(pts, [2]float64{y, x})
	}
	if len(pts) < 3 {
		return nil
	}
	return pts
}

func pointInPolygon(lat, lon float64, poly [][2]float64) bool {
	inside := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		yi, xi := poly[i][0], poly[i][1]
		yj, xj := poly[j][0], poly[j][1]
		if (yi > lat) != (yj > lat) && lon < (xj-xi)*(lat-yi)/(yj-yi)+xi {
			inside = !inside
		}
	}
	return inside
}

func (r missionFeedRef) matches(e *cot.Event) bool {
	if len(r.feed.FilterCotTypes) > 0 && !slices.ContainsFunc(r.feed.FilterCotTypes, func(t string) bool { return e.Type == t || strings.HasPrefix(e.Type, t) }) {
		return false
	}
	if r.feed.FilterCallsign != "" && !strings.EqualFold(e.Callsign(), r.feed.FilterCallsign) {
		return false
	}
	if r.poly != nil && !pointInPolygon(e.Point.Lat, e.Point.Lon, r.poly) {
		return false
	}
	return true
}

func (s *Server) rebuildFeedIndex() {
	idx := map[string][]missionFeedRef{}
	for _, m := range s.missions.All() {
		for _, f := range m.Feeds {
			idx[f.DataFeedUID] = append(idx[f.DataFeedUID], missionFeedRef{mission: m.Name, feed: f, poly: parseFilterPolygon(f.FilterPolygon)})
		}
	}
	s.dfeeds.mu.Lock()
	s.dfeeds.index = idx
	s.dfeeds.mu.Unlock()
}

func (s *Server) feedToMissions(msg *Message) {
	s.dfeeds.mu.Lock()
	refs := s.dfeeds.index[msg.Feed]
	s.dfeeds.mu.Unlock()
	done := map[string]bool{}
	for _, r := range refs {
		if done[r.mission] || !r.matches(msg.Event) {
			continue
		}
		m, ok := s.missions.Get(r.mission)
		if !ok {
			continue
		}
		done[r.mission] = true
		s.deliverToSubscribers(m, msg, "")
	}
}

func (s *Server) missionFeedJSON(f MissionFeed) map[string]any {
	types, _ := json.Marshal(f.FilterCotTypes)
	if f.FilterCotTypes == nil {
		types = []byte("[]")
	}
	out := map[string]any{"uid": f.UID, "dataFeedUid": f.DataFeedUID, "filterCotTypesSerialized": string(types), "filterCotTypes": f.FilterCotTypes}
	if out["filterCotTypes"] == nil {
		out["filterCotTypes"] = []string{}
	}
	if f.FilterPolygon != "" {
		out["filterPolygon"] = f.FilterPolygon
	}
	if f.FilterCallsign != "" {
		out["filterCallsign"] = f.FilterCallsign
	}
	if df, ok := s.dataFeedConfig(f.DataFeedUID); ok {
		out["name"] = df.Name
	}
	return out
}

func polygonParam(points []string) string {
	var clean []string
	for _, p := range points {
		for _, q := range strings.Split(p, ";") {
			q = strings.ReplaceAll(strings.TrimSpace(q), " ", "")
			if q != "" {
				clean = append(clean, q)
			}
		}
	}
	if len(clean) < 3 {
		return ""
	}
	for _, p := range clean {
		xy := strings.Split(p, ",")
		if len(xy) != 2 {
			return ""
		}
		if _, err := strconv.ParseFloat(xy[0], 64); err != nil {
			return ""
		}
		if _, err := strconv.ParseFloat(xy[1], 64); err != nil {
			return ""
		}
	}
	if clean[0] != clean[len(clean)-1] {
		clean = append(clean, clean[0])
	}
	for i, p := range clean {
		clean[i] = strings.Replace(p, ",", " ", 1)
	}
	return strings.Join(clean, ",")
}

func (s *Server) loadMissionAny(w http.ResponseWriter, r *http.Request) (Mission, bool) {
	if _, ok := s.missions.Get(r.PathValue("name")); !ok {
		if mm, ok := s.missions.ByGUID(r.PathValue("name")); ok {
			r.SetPathValue("name", mm.Name)
		}
	}
	return s.loadMission(w, r)
}

func (s *Server) missionFeedAdd(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMissionAny(w, r)
	if !ok || !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	q := r.URL.Query()
	feedUID := strings.TrimSpace(q.Get("dataFeedUid"))
	df, ok := s.dataFeedConfig(feedUID)
	if feedUID == "" || !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no data feed with that dataFeedUid"})
		return
	}
	if !s.feedVisible(identityOf(r), df) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you cannot use that data feed"})
		return
	}
	mf := MissionFeed{UID: firstNonEmpty(q.Get("uid"), cot.NewUID()), DataFeedUID: feedUID, FilterCallsign: strings.TrimSpace(q.Get("filterCallsign"))}
	if raw := q.Get("filterCotTypes"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &mf.FilterCotTypes); err != nil {
			mf.FilterCotTypes = splitList(raw)
		}
		sort.Strings(mf.FilterCotTypes)
	}
	if pts := q["filterPolygon"]; len(pts) > 0 {
		mf.FilterPolygon = polygonParam(pts)
	}
	creator := firstNonEmpty(q.Get("creatorUid"), s.callerUID(r))
	m, created := s.addMissionFeed(m.Name, mf, creator)
	if created {
		s.rolMissionFeed(m, mf, df, "create")
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionFeed", s.missionFeedJSON(mf)))
}

func (s *Server) addMissionFeed(name string, mf MissionFeed, creator string) (Mission, bool) {
	created := false
	m, err := s.missions.Update(name, func(x *Mission) error {
		if slices.ContainsFunc(x.Feeds, func(f MissionFeed) bool { return f.UID == mf.UID }) {
			return nil
		}
		x.Feeds = append(x.Feeds, mf)
		x.addChange(MissionChange{Type: "CREATE_DATA_FEED", CreatorUID: creator, ContentUID: mf.UID, Feed: &mf})
		created = true
		return nil
	})
	if err != nil || !created {
		return m, false
	}
	s.rebuildFeedIndex()
	s.notifyFeedChange(m, "CREATE_DATA_FEED", creator, mf)
	return m, true
}

func (s *Server) removeMissionFeed(name, uid, creator string) (Mission, MissionFeed, bool) {
	var removed MissionFeed
	found := false
	m, err := s.missions.Update(name, func(x *Mission) error {
		idx := slices.IndexFunc(x.Feeds, func(f MissionFeed) bool { return f.UID == uid })
		if idx < 0 {
			return nil
		}
		removed = x.Feeds[idx]
		x.Feeds = slices.Delete(x.Feeds, idx, idx+1)
		x.addChange(MissionChange{Type: "DELETE_DATA_FEED", CreatorUID: creator, ContentUID: uid, Feed: &removed})
		found = true
		return nil
	})
	if err != nil || !found {
		return m, removed, false
	}
	s.rebuildFeedIndex()
	s.notifyFeedChange(m, "DELETE_DATA_FEED", creator, removed)
	return m, removed, true
}

func (s *Server) missionFeedDelete(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMissionAny(w, r)
	if !ok || !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	creator := firstNonEmpty(r.URL.Query().Get("creatorUid"), s.callerUID(r))
	m, removed, found := s.removeMissionFeed(m.Name, r.PathValue("uid"), creator)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "that feed is not in the mission"})
		return
	}
	if df, ok := s.dataFeedConfig(removed.DataFeedUID); ok {
		s.rolMissionFeed(m, removed, df, "delete")
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) notifyFeedChange(m Mission, typ, author string, f MissionFeed) {
	e := s.missionEvent(m, "t-x-m-c", "CHANGE", author)
	mc := s.changeXML(m, typ, author, nil, nil)
	mf := mc.AddNew("missionFeed")
	mf.AddNew("uid").Text = f.UID
	mf.AddNew("dataFeedUid").Text = f.DataFeedUID
	if f.FilterPolygon != "" {
		mf.AddNew("filterPolygon").Text = f.FilterPolygon
	}
	types, _ := json.Marshal(f.FilterCotTypes)
	mf.AddNew("filterCotTypesSerialized").Text = string(types)
	if f.FilterCallsign != "" {
		mf.AddNew("filterCallsign").Text = f.FilterCallsign
	}
	if df, ok := s.dataFeedConfig(f.DataFeedUID); ok {
		mf.AddNew("name").Text = df.Name
	}
	mc.AddNew("contentUid").Text = f.UID
	e.Detail.Child("mission").AddNew("MissionChanges").Add(mc)
	s.sendToSubscribers(m, e, "")
}

func (s *Server) martiDataFeeds(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []dataFeedView{}
	for _, f := range s.allDataFeeds() {
		if s.feedVisible(id, f) {
			out = append(out, f)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", out))
}

func (s *Server) visibleFeed(w http.ResponseWriter, r *http.Request, uuid string) (dataFeedView, bool) {
	f, ok := s.dataFeedConfig(uuid)
	if !ok || !s.feedVisible(identityOf(r), f) {
		writeJSON(w, http.StatusNotFound, s.envelope("tak.server.feeds.DataFeed", nil))
		return f, false
	}
	return f, true
}

func (s *Server) feedStatsJSON(uuid string) map[string]any {
	st := s.dfeeds.state(uuid)
	st.mu.Lock()
	defer st.mu.Unlock()
	types := make([]string, 0, len(st.types))
	for t := range st.types {
		types = append(types, t)
	}
	sort.Strings(types)
	out := map[string]any{"dataFeedUUID": uuid, "dataFeedCotTypes": types, "dataFeedMinLat": st.minLat, "dataFeedMinLon": st.minLon, "dataFeedMaxLat": st.maxLat, "dataFeedMaxLon": st.maxLon, "dataFeedNumMessages": st.count, "dataFeedTotalByteSize": st.bytes}
	if !st.last.IsZero() {
		out["dataFeedMsgMillis"] = st.last.UnixMilli()
		out["dataFeedFirstMsgMillis"] = st.first.UnixMilli()
		if secs := st.last.Sub(st.first).Seconds(); secs > 0 {
			out["dataFeedMsgAvgRatePerSec"] = float64(st.count) / secs
			out["dataFeedMsgAvgBytesPerSec"] = float64(st.bytes) / secs
		}
	}
	return out
}

func (s *Server) martiDataFeedStats(w http.ResponseWriter, r *http.Request) {
	if uuid := r.PathValue("uuid"); uuid != "" {
		if _, ok := s.visibleFeed(w, r, uuid); !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeedStats", s.feedStatsJSON(uuid)))
		return
	}
	out := []map[string]any{}
	id := identityOf(r)
	for _, f := range s.allDataFeeds() {
		if s.feedVisible(id, f) {
			out = append(out, s.feedStatsJSON(f.UUID))
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeedStats", out))
}

func (s *Server) martiDataFeedTypes(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if _, ok := s.visibleFeed(w, r, uuid); !ok {
		return
	}
	seen := map[string]bool{}
	types := []string{}
	for _, m := range s.dfeeds.state(uuid).cached(s.feedRetention()) {
		if !seen[m.Event.Type] {
			seen[m.Event.Type] = true
			types = append(types, m.Event.Type)
		}
	}
	sort.Strings(types)
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", types))
}

func (s *Server) martiDataFeedCots(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if _, ok := s.visibleFeed(w, r, uuid); !ok {
		return
	}
	typ := r.PathValue("type")
	out := []string{}
	for _, m := range s.dfeeds.state(uuid).cached(s.feedRetention()) {
		if typ == "" || typ == "all" || m.Event.Type == typ || strings.HasPrefix(m.Event.Type, typ) {
			out = append(out, string(m.XML()))
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", out))
}

func (s *Server) martiDataFeedsInBounds(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.PathValue("bbox"), ",")
	if len(parts) != 4 {
		writeJSON(w, http.StatusBadRequest, s.envelope("tak.server.feeds.DataFeed", []string{}))
		return
	}
	var v [4]float64
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("tak.server.feeds.DataFeed", []string{}))
			return
		}
		v[i] = f
	}
	maxLat, minLon, minLat, maxLon := v[0], v[1], v[2], v[3]
	id := identityOf(r)
	out := []string{}
	for _, f := range s.allDataFeeds() {
		if !s.feedVisible(id, f) {
			continue
		}
		for _, m := range s.dfeeds.state(f.UUID).cached(s.feedRetention()) {
			p := m.Event.Point
			if p.Lat >= minLat && p.Lat <= maxLat && p.Lon >= minLon && p.Lon <= maxLon {
				out = append(out, f.UUID)
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("tak.server.feeds.DataFeed", out))
}

func (s *Server) apiDataFeeds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.allDataFeeds())
}
