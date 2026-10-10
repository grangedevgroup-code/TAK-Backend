package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

const (
	KindCluster       = "cluster"
	clusterCodePrefix = "golangtakserver-cluster:"
)

type ClusterConfig struct {
	Enabled bool     `json:"enabled"`
	Secret  string   `json:"secret,omitempty"`
	Dial    []string `json:"dial,omitempty"`
	Members []string `json:"members,omitempty"`
}

type clusterVersion struct {
	TS  int64 `json:"t"`
	Del bool  `json:"d,omitempty"`
}

type replColl struct {
	name    string
	snap    func() map[string][]byte
	apply   func(key string, raw []byte, del bool) error
	setHook func(func(string, []byte, bool))
	adjust  func(key string, raw []byte, del bool) []byte
	after   func(key string, raw []byte, del bool)
}

type clusterLink struct {
	node   string
	name   string
	url    string
	out    chan []byte
	client *Client
	since  time.Time
	dialer bool
	synced atomic.Bool
	rx, tx atomic.Uint64
	here   map[string]string
	hereMu sync.Mutex
	done   chan struct{}
}

type clusterState struct {
	mu       sync.Mutex
	colls    map[string]*replColl
	versions *store.Collection[clusterVersion]
	links    map[string]*clusterLink
	clock    atomic.Int64
	applying sync.Mutex
	dialErr  map[string]string
}

type clusterMsg struct {
	T      string          `json:"t"`
	Node   string          `json:"node,omitempty"`
	Name   string          `json:"name,omitempty"`
	URL    string          `json:"url,omitempty"`
	URLs   []string        `json:"urls,omitempty"`
	C      string          `json:"c,omitempty"`
	K      string          `json:"k,omitempty"`
	V      json.RawMessage `json:"v,omitempty"`
	D      bool            `json:"d,omitempty"`
	TS     int64           `json:"ts,omitempty"`
	X      string          `json:"x,omitempty"`
	G      []string        `json:"g,omitempty"`
	E      bool            `json:"e,omitempty"`
	M      string          `json:"m,omitempty"`
	Except string          `json:"ex,omitempty"`
	UID    string          `json:"uid,omitempty"`
	On     bool            `json:"on,omitempty"`
}

func replicated[T any](name string, c *store.Collection[T]) *replColl {
	return &replColl{name: name, snap: c.Snapshot, apply: c.ApplyRaw, setHook: c.SetOnChange}
}

func (s *Server) clusterOn() bool { return s.cluster != nil && s.Config().Cluster.Enabled }

func (s *Server) nodeURL() string {
	cfg := s.Config()
	return "https://" + net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Ports.Enroll))
}

func (s *Server) openCluster() error {
	v, err := store.Open[clusterVersion](filepath.Join(s.DataDir, "db", "cluster-versions.jsonl"), false)
	if err != nil {
		return err
	}
	cs := &clusterState{colls: map[string]*replColl{}, versions: v, links: map[string]*clusterLink{}, dialErr: map[string]string{}}
	s.cluster = cs
	d := s.dir
	add := func(r *replColl) { cs.colls[r.name] = r }
	users := replicated("users", d.users)
	users.after = func(key string, _ []byte, _ bool) {
		d.forget(key)
		if d.OnChange != nil {
			d.OnChange(key)
		}
	}
	add(users)
	groups := replicated("groups", d.groups)
	groups.adjust = d.adjustRemoteGroup
	add(groups)
	add(replicated("tokens", d.tokens))
	revoked := replicated("revoked", d.revoked)
	revoked.after = func(key string, raw []byte, del bool) {
		var r Revoked
		if del || json.Unmarshal(raw, &r) != nil {
			return
		}
		d.mu.Lock()
		d.revSet[strings.ToLower(r.Serial)] = true
		d.mu.Unlock()
	}
	add(revoked)
	add(replicated("auth-tokens", s.acct.tokens))
	add(replicated("pending-chat", s.chats.db))
	add(replicated("devices", s.devices.db))
	add(replicated("citrap", s.reports.db))
	add(replicated("maplayers", s.mapLayers.db))
	add(replicated("missions", s.missions.db))
	add(replicated("mission-cot", s.missions.cots))
	add(replicated("profiles", s.profiles.items))
	add(replicated("profile-plugins", s.profiles.plugins))
	add(replicated("repeated", s.repeated.db))
	add(replicated("injectors", s.injectors.db))
	add(replicated("properties", s.props))
	add(replicated("video", s.videos.db))
	res := replicated("resources", s.res.db)
	res.after = s.clusterFetchBlob
	add(res)
	for _, r := range cs.colls {
		r := r
		r.setHook(func(key string, raw []byte, del bool) { s.clusterLocalChange(r.name, key, raw, del) })
	}
	return nil
}

func (d *Directory) adjustRemoteGroup(key string, raw []byte, del bool) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if del {
		if bit, ok := d.bits[key]; ok {
			delete(d.bits, key)
			delete(d.names, bit)
		}
		return raw
	}
	var g Group
	if json.Unmarshal(raw, &g) != nil {
		return raw
	}
	if bit, ok := d.bits[g.Name]; ok {
		g.Bit = bit
	} else {
		bit = 0
		for {
			if _, used := d.names[bit]; !used {
				break
			}
			bit++
		}
		g.Bit = bit
		d.bits[g.Name] = bit
		d.names[bit] = g.Name
	}
	b, _ := json.Marshal(g)
	return b
}

func (cs *clusterState) tick() int64 {
	for {
		now := time.Now().UnixNano()
		cur := cs.clock.Load()
		next := max(now, cur+1)
		if cs.clock.CompareAndSwap(cur, next) {
			return next
		}
	}
}

func (cs *clusterState) observe(ts int64) {
	for {
		cur := cs.clock.Load()
		if ts <= cur || cs.clock.CompareAndSwap(cur, ts) {
			return
		}
	}
}

func vkey(coll, key string) string { return coll + "\x00" + key }

func (s *Server) clusterLocalChange(coll, key string, raw []byte, del bool) {
	cs := s.cluster
	if cs == nil || !s.Config().Cluster.Enabled {
		return
	}
	ts := cs.tick()
	cs.versions.Put(vkey(coll, key), clusterVersion{TS: ts, Del: del})
	s.clusterBroadcast(clusterMsg{T: "kv", C: coll, K: key, V: raw, D: del, TS: ts}, nil)
}

func (s *Server) clusterStamp() {
	cs := s.cluster
	if cs == nil || cs.versions.Len() > 0 {
		return
	}
	for name, r := range cs.colls {
		ts := cs.tick()
		for k := range r.snap() {
			cs.versions.Put(vkey(name, k), clusterVersion{TS: ts})
		}
	}
}

func (s *Server) clusterApply(m clusterMsg) {
	cs := s.cluster
	r := cs.colls[m.C]
	if r == nil || m.K == "" {
		return
	}
	cs.observe(m.TS)
	cs.applying.Lock()
	defer cs.applying.Unlock()
	vk := vkey(m.C, m.K)
	if cur, ok := cs.versions.Get(vk); ok && cur.TS >= m.TS {
		return
	}
	raw := []byte(m.V)
	if r.adjust != nil {
		raw = r.adjust(m.K, raw, m.D)
	}
	if err := r.apply(m.K, raw, m.D); err != nil {
		s.log.Debug("cluster change not applied", "collection", m.C, "key", m.K, "err", err)
		return
	}
	cs.versions.Put(vk, clusterVersion{TS: m.TS, Del: m.D})
	if r.after != nil {
		r.after(m.K, raw, m.D)
	}
}

func (s *Server) clusterSnapshot(l *clusterLink) {
	cs := s.cluster
	names := make([]string, 0, len(cs.colls))
	for n := range cs.colls {
		names = append(names, n)
	}
	sort.Strings(names)
	tombs := map[string]map[string]int64{}
	for _, k := range cs.versions.Keys() {
		v, ok := cs.versions.Get(k)
		if !ok || !v.Del {
			continue
		}
		coll, key, _ := strings.Cut(k, "\x00")
		if tombs[coll] == nil {
			tombs[coll] = map[string]int64{}
		}
		tombs[coll][key] = v.TS
	}
	for _, name := range names {
		for k, raw := range cs.colls[name].snap() {
			ts := int64(0)
			if v, ok := cs.versions.Get(vkey(name, k)); ok {
				ts = v.TS
			}
			if !l.send(clusterMsg{T: "kv", C: name, K: k, V: raw, TS: ts}) {
				return
			}
		}
		for k, ts := range tombs[name] {
			if !l.send(clusterMsg{T: "kv", C: name, K: k, D: true, TS: ts}) {
				return
			}
		}
	}
	for _, c := range s.hub.Clients() {
		if !c.Relay && c.UID() != "" {
			l.send(clusterMsg{T: "here", UID: c.UID(), Name: c.Callsign(), On: true})
		}
	}
	l.send(clusterMsg{T: "synced"})
}

func (l *clusterLink) send(m clusterMsg) bool {
	b, err := json.Marshal(m)
	if err != nil {
		return true
	}
	select {
	case l.out <- b:
		l.tx.Add(1)
		return true
	case <-l.done:
		return false
	case <-time.After(30 * time.Second):
		return false
	}
}

func (s *Server) clusterBroadcast(m clusterMsg, except *clusterLink) {
	cs := s.cluster
	if cs == nil {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	cs.mu.Lock()
	links := make([]*clusterLink, 0, len(cs.links))
	for _, l := range cs.links {
		if l != except {
			links = append(links, l)
		}
	}
	cs.mu.Unlock()
	for _, l := range links {
		select {
		case l.out <- b:
			l.tx.Add(1)
		default:
			s.log.Warn("cluster link is too slow; dropping it", "node", l.name)
			l.close()
		}
	}
}

func (l *clusterLink) close() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}

func (s *Server) clusterFetchBlob(key string, raw []byte, del bool) {
	if del {
		return
	}
	var res Resource
	if json.Unmarshal(raw, &res) != nil || !store.ValidHash(res.Hash) || s.res.blobs.Exists(res.Hash) {
		return
	}
	go func() {
		cs := s.cluster
		cs.mu.Lock()
		links := make([]*clusterLink, 0, len(cs.links))
		for _, l := range cs.links {
			links = append(links, l)
		}
		cs.mu.Unlock()
		for _, l := range links {
			if l.url == "" {
				continue
			}
			err := s.clusterDownload(l.url, res.Hash)
			if err == nil {
				return
			}
			s.log.Warn("could not copy a file from another cluster node", "node", l.name, "file", res.Name, "err", err)
		}
	}()
}

func (s *Server) clusterTLS(host string) *tls.Config {
	return &tls.Config{RootCAs: s.pki.CA.Pool(), ServerName: host, MinVersion: tls.VersionTLS12}
}

func (s *Server) clusterDownload(base, hash string) error {
	u, err := url.Parse(base)
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{TLSClientConfig: s.clusterTLS(u.Hostname())}}
	req, _ := http.NewRequestWithContext(s.ctx, http.MethodGet, strings.TrimRight(base, "/")+"/api/cluster/blob/"+hash, nil)
	req.Header.Set("Authorization", "Cluster "+s.Config().Cluster.Secret)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	got, _, err := s.res.blobs.Put(resp.Body, s.uploadLimit())
	if err != nil {
		return err
	}
	if got != hash {
		s.res.blobs.Delete(got)
		return errors.New("downloaded file does not match its hash")
	}
	return nil
}

func (s *Server) clusterAuthorized(r *http.Request) bool {
	cfg := s.Config().Cluster
	if !cfg.Enabled || cfg.Secret == "" {
		return false
	}
	scheme, cred, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "cluster") && subtle.ConstantTimeCompare([]byte(cred), []byte(cfg.Secret)) == 1
}

func (s *Server) apiClusterBlob(w http.ResponseWriter, r *http.Request) {
	if !s.clusterAuthorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, err := s.res.blobs.Read(r.PathValue("hash"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) apiClusterSocket(w http.ResponseWriter, r *http.Request) {
	if !s.clusterAuthorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	s.runClusterLink(conn, false, "")
}

func (s *Server) runClusterLink(conn *websocket.Conn, dialer bool, dialURL string) {
	defer conn.CloseNow()
	conn.MaxMessage = 64 << 20
	cfg := s.Config()
	hello, _ := json.Marshal(clusterMsg{T: "hello", Node: cfg.NodeID, Name: cfg.Name, URL: s.nodeURL()})
	conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	if err := conn.WriteText(string(hello)); err != nil {
		return
	}
	_, b, err := conn.ReadMessage()
	if err != nil {
		return
	}
	var h clusterMsg
	if json.Unmarshal(b, &h) != nil || h.T != "hello" || h.Node == "" || h.Node == cfg.NodeID {
		return
	}
	l := &clusterLink{node: h.Node, name: firstNonEmpty(h.Name, h.Node), url: firstNonEmpty(h.URL, dialURL), out: make(chan []byte, 8192), since: time.Now(), dialer: dialer, here: map[string]string{}, done: make(chan struct{})}
	if dialer && dialURL != "" {
		l.url = dialURL
	}
	cs := s.cluster
	cs.mu.Lock()
	if old := cs.links[h.Node]; old != nil {
		cs.mu.Unlock()
		s.log.Debug("duplicate cluster link ignored", "node", l.name)
		return
	}
	l.client = s.relayClient(KindCluster, "cluster-"+l.name, conn.RemoteAddr().String(), nil)
	l.client.filter = func(*Message) bool { return false }
	cs.links[h.Node] = l
	cs.mu.Unlock()
	s.hub.Add(l.client)
	if !dialer && h.URL != "" {
		self := s.nodeURL()
		s.UpdateConfig(func(c *Config) error {
			if h.URL != self && !slices.Contains(c.Cluster.Members, h.URL) && !slices.Contains(c.Cluster.Dial, h.URL) {
				c.Cluster.Members = append(c.Cluster.Members, h.URL)
			}
			return nil
		})
		var others []string
		for _, u := range append(append([]string{}, s.Config().Cluster.Dial...), s.Config().Cluster.Members...) {
			if u != h.URL && !slices.Contains(others, u) {
				others = append(others, u)
			}
		}
		l.send(clusterMsg{T: "members", URLs: others})
	}
	s.log.Info("cluster node connected", "node", l.name, "url", l.url)
	defer func() {
		l.close()
		cs.mu.Lock()
		if cs.links[h.Node] == l {
			delete(cs.links, h.Node)
		}
		cs.mu.Unlock()
		s.hub.Remove(l.client)
		s.log.Info("cluster node disconnected", "node", l.name)
	}()
	go s.clusterSnapshot(l)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			l.rx.Add(1)
			var m clusterMsg
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			s.clusterReceive(l, m)
		}
	}()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-readDone:
			return
		case <-l.done:
			return
		case <-s.ctx.Done():
			conn.Close(websocket.CloseGoingAway, "server stopping")
			return
		case <-ping.C:
			if conn.Ping(nil) != nil {
				return
			}
		case b := <-l.out:
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if conn.WriteText(string(b)) != nil {
				return
			}
		}
	}
}

func (s *Server) clusterReceive(l *clusterLink, m clusterMsg) {
	switch m.T {
	case "kv":
		s.clusterApply(m)
	case "synced":
		l.synced.Store(true)
		s.log.Info("cluster node in sync", "node", l.name)
	case "members":
		added := false
		self := s.nodeURL()
		s.UpdateConfig(func(c *Config) error {
			for _, u := range m.URLs {
				if u != "" && u != self && !slices.Contains(c.Cluster.Dial, u) && !slices.Contains(c.Cluster.Members, u) {
					c.Cluster.Dial = append(c.Cluster.Dial, u)
					added = true
				}
			}
			return nil
		})
		if added {
			s.clusterDialAll()
		}
	case "cot":
		e, err := cot.Parse([]byte(m.X))
		if err != nil {
			return
		}
		msg := NewMessage(e, l.client, s.dir.Mask(m.G))
		msg.Everyone = m.E
		s.hub.Publish(msg)
	case "msub":
		mission, ok := s.missions.Get(m.M)
		if !ok {
			return
		}
		e, err := cot.Parse([]byte(m.X))
		if err != nil {
			return
		}
		msg := NewMessage(e, l.client, nil)
		msg.NoReplay = true
		s.deliverToSubscribers(mission, msg, m.Except)
	case "here":
		l.hereMu.Lock()
		if m.On {
			l.here[m.UID] = m.Name
		} else {
			delete(l.here, m.UID)
		}
		l.hereMu.Unlock()
	}
}

func (s *Server) clusterHas(uid string) bool { return s.clusterHasDest(cot.Dest{UID: uid}) }

func (s *Server) clusterHasDest(d cot.Dest) bool {
	cs := s.cluster
	if cs == nil || (d.UID == "" && d.Callsign == "") {
		return false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, l := range cs.links {
		l.hereMu.Lock()
		found := false
		if d.UID != "" {
			_, found = l.here[d.UID]
		}
		if !found && d.Callsign != "" {
			for _, cs := range l.here {
				if strings.EqualFold(cs, d.Callsign) {
					found = true
					break
				}
			}
		}
		l.hereMu.Unlock()
		if found {
			return true
		}
	}
	return false
}

func fromCluster(m *Message) bool { return m != nil && m.Source != nil && m.Source.Kind == KindCluster }

func (s *Server) clusterForward() {
	sub := s.hub.Subscribe(16384, func(m *Message) bool { return !fromCluster(m) })
	defer s.hub.Unsubscribe(sub)
	for {
		select {
		case <-s.ctx.Done():
			return
		case m := <-sub.C:
			if !s.clusterOn() || m.Event == nil {
				continue
			}
			s.clusterBroadcast(clusterMsg{T: "cot", X: string(m.XML()), G: s.dir.Names(m.Groups), E: m.Everyone}, nil)
		}
	}
}

func (s *Server) clusterPresence(c *Client, on bool) {
	if !s.clusterOn() || c.Relay || c.UID() == "" {
		return
	}
	s.clusterBroadcast(clusterMsg{T: "here", UID: c.UID(), Name: c.Callsign(), On: on}, nil)
}

func (s *Server) clusterMissionDeliver(m Mission, msg *Message, except string) {
	if !s.clusterOn() || fromCluster(msg) {
		return
	}
	s.clusterBroadcast(clusterMsg{T: "msub", M: m.Name, X: string(msg.XML()), Except: except}, nil)
}

func (s *Server) clusterDialAll() {
	if !s.clusterOn() {
		return
	}
	for _, u := range s.Config().Cluster.Dial {
		s.clusterDial(u)
	}
}

func (s *Server) clusterDial(target string) {
	cs := s.cluster
	cs.mu.Lock()
	if _, busy := cs.dialErr[target]; busy {
		cs.mu.Unlock()
		return
	}
	cs.dialErr[target] = "connecting"
	cs.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		delay := time.Second
		for s.ctx.Err() == nil && s.clusterOn() && slices.Contains(s.Config().Cluster.Dial, target) {
			u, err := url.Parse(target)
			if err == nil {
				ws := strings.Replace(strings.TrimRight(target, "/"), "https://", "wss://", 1) + "/api/cluster/ws"
				h := http.Header{}
				h.Set("Authorization", "Cluster "+s.Config().Cluster.Secret)
				ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
				var conn *websocket.Conn
				conn, _, err = websocket.Dial(ctx, ws, &websocket.DialOptions{TLS: s.clusterTLS(u.Hostname()), Header: h})
				cancel()
				if err == nil {
					cs.mu.Lock()
					cs.dialErr[target] = ""
					cs.mu.Unlock()
					delay = time.Second
					s.runClusterLink(conn, true, target)
					err = errors.New("disconnected")
				}
			}
			cs.mu.Lock()
			cs.dialErr[target] = err.Error()
			cs.mu.Unlock()
			select {
			case <-s.ctx.Done():
			case <-time.After(delay):
			}
			delay = min(delay*2, 30*time.Second)
		}
		cs.mu.Lock()
		delete(cs.dialErr, target)
		cs.mu.Unlock()
	}()
}

func (s *Server) startCluster() {
	if s.cluster == nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.clusterForward()
	}()
	if s.clusterOn() {
		s.clusterStamp()
		s.clusterDialAll()
	}
}

type clusterCode struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
	CA     string `json:"ca"`
	CAKey  string `json:"caKey"`
	Name   string `json:"name"`
}

func (s *Server) ClusterInvite() (string, error) {
	cfg, err := s.UpdateConfig(func(c *Config) error {
		if c.Cluster.Secret == "" {
			c.Cluster.Secret = NewSecret(32)
		}
		c.Cluster.Enabled = true
		return nil
	})
	if err != nil {
		return "", err
	}
	s.clusterStamp()
	keyPEM, err := pki.KeyPEM(s.pki.CA.Key)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(clusterCode{URL: s.nodeURL(), Secret: cfg.Cluster.Secret, CA: string(s.pki.CA.CertPEM), CAKey: string(keyPEM), Name: cfg.Name}) // #nosec G117 -- the join code carries the cluster secret by design
	return clusterCodePrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

func (s *Server) ClusterJoin(code string) error {
	code = strings.Join(strings.Fields(code), "")
	body, ok := strings.CutPrefix(code, clusterCodePrefix)
	if !ok {
		return errors.New("this is not a cluster code (it should start with " + clusterCodePrefix + ")")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return errors.New("the cluster code is damaged; copy it again in full")
	}
	var cc clusterCode
	if err := json.Unmarshal(raw, &cc); err != nil || cc.URL == "" || cc.Secret == "" || cc.CA == "" || cc.CAKey == "" {
		return errors.New("the cluster code is damaged; copy it again in full")
	}
	if cc.URL == s.nodeURL() {
		return errors.New("this code was created on this server; use it on the server that should join")
	}
	if _, err := pki.LoadCA([]byte(cc.CA), []byte(cc.CAKey), ""); err != nil {
		return fmt.Errorf("the cluster code's certificate authority is not valid: %w", err)
	}
	dir := certDir(s.DataDir)
	if err := writeFileAtomic(filepath.Join(dir, "ca.key"), []byte(cc.CAKey), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "ca.pem"), []byte(cc.CA), 0o644); err != nil {
		return err
	}
	for _, f := range []string{"server.pem", "server.key", "selftest.pem", "selftest.key", "truststore.p12"} {
		os.Remove(filepath.Join(dir, f))
	}
	if s.cluster != nil {
		for _, k := range s.cluster.versions.Keys() {
			s.cluster.versions.Delete(k)
		}
	}
	_, err = s.UpdateConfig(func(c *Config) error {
		c.Cluster = ClusterConfig{Enabled: true, Secret: cc.Secret, Dial: []string{cc.URL}}
		return nil
	})
	if err != nil {
		return err
	}
	s.log.Info("joined cluster; restarting with the cluster certificate authority", "via", cc.URL)
	s.requestRestart()
	return nil
}

func (s *Server) ClusterLeave() error {
	_, err := s.UpdateConfig(func(c *Config) error {
		c.Cluster = ClusterConfig{}
		return nil
	})
	if err != nil {
		return err
	}
	if s.cluster != nil {
		s.cluster.mu.Lock()
		for _, l := range s.cluster.links {
			l.close()
		}
		s.cluster.mu.Unlock()
	}
	return nil
}

type ClusterNodeStatus struct {
	Name     string    `json:"name"`
	Node     string    `json:"node,omitempty"`
	URL      string    `json:"url,omitempty"`
	State    string    `json:"state"`
	Error    string    `json:"error,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	Synced   bool      `json:"synced"`
	Received uint64    `json:"received"`
	Sent     uint64    `json:"sent"`
	Devices  int       `json:"devices"`
}

func (s *Server) ClusterStatus() map[string]any {
	cfg := s.Config()
	nodes := []ClusterNodeStatus{}
	if s.cluster != nil {
		cs := s.cluster
		cs.mu.Lock()
		seen := map[string]bool{}
		for _, l := range cs.links {
			l.hereMu.Lock()
			n := len(l.here)
			l.hereMu.Unlock()
			nodes = append(nodes, ClusterNodeStatus{Name: l.name, Node: l.node, URL: l.url, State: "connected", Since: l.since, Synced: l.synced.Load(), Received: l.rx.Load(), Sent: l.tx.Load(), Devices: n})
			seen[l.url] = true
		}
		for u, e := range cs.dialErr {
			if !seen[u] && e != "" {
				nodes = append(nodes, ClusterNodeStatus{Name: u, URL: u, State: "connecting", Error: e})
			}
		}
		cs.mu.Unlock()
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return map[string]any{"enabled": cfg.Cluster.Enabled, "node": cfg.NodeID, "url": s.nodeURL(), "nodes": nodes}
}

func (s *Server) apiClusterStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ClusterStatus())
}

func (s *Server) apiClusterInvite(w http.ResponseWriter, r *http.Request) {
	code, err := s.ClusterInvite()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	s.clusterDialAll()
	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

func (s *Server) apiClusterJoin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.ClusterJoin(body.Code); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "restarting": true})
}

func (s *Server) apiClusterLeave(w http.ResponseWriter, r *http.Request) {
	if err := s.ClusterLeave(); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
