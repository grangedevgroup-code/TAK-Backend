package server

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

type Subscriber struct {
	C      chan *Message
	filter func(*Message) bool
	drops  atomic.Uint64
}

type Hub struct {
	srv        *Server
	log        *slog.Logger
	mu         sync.RWMutex
	clients    map[uint64]*Client
	byUID      map[string]*Client
	byCallsign map[string]*Client
	nextID     atomic.Uint64
	cmu        sync.Mutex
	cache      map[string]*Message
	emu        sync.Mutex
	emergency  map[string]*Message
	smu        sync.RWMutex
	subs       map[*Subscriber]struct{}
	Events     atomic.Uint64
	Delivered  atomic.Uint64
	Bytes      atomic.Uint64
	queueLen   int
	maxClients int
	cacheLimit int
	OnIdentify func(c *Client)
	OnCoT      func(m *Message)
	OnMissions func(m *Message, missions []string)
	OnOffline  func(dest cot.Dest, m *Message)
	OnRemove   func(c *Client)
}

func NewHub(srv *Server, log *slog.Logger, queueLen, maxClients, cacheLimit int) *Hub {
	return &Hub{
		srv:        srv,
		log:        log,
		clients:    map[uint64]*Client{},
		byUID:      map[string]*Client{},
		byCallsign: map[string]*Client{},
		cache:      map[string]*Message{},
		emergency:  map[string]*Message{},
		subs:       map[*Subscriber]struct{}{},
		queueLen:   queueLen,
		maxClients: maxClients,
		cacheLimit: cacheLimit,
	}
}

func (h *Hub) NewClient(kind, remote string, id *Identity) *Client {
	c := &Client{
		ID:        h.nextID.Add(1),
		Kind:      kind,
		Remote:    remote,
		Connected: time.Now(),
		out:       make(chan *Message, h.queueLen),
		closed:    make(chan struct{}),
		hub:       h,
		remote:    map[string]string{},
	}
	if id != nil {
		c.SetIdentity(id)
	}
	switch kind {
	case KindPeer, KindFederation, KindMesh, KindUDP, KindAPI:
		c.Relay = true
	}
	return c
}

func (h *Hub) Add(c *Client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !c.Relay && h.maxClients > 0 && h.countLocked() >= h.maxClients {
		return false
	}
	h.clients[c.ID] = c
	return true
}

func (h *Hub) countLocked() int {
	n := 0
	for _, c := range h.clients {
		if !c.Relay {
			n++
		}
	}
	return n
}

func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.countLocked()
}

func (h *Hub) CountFrom(ip string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, c := range h.clients {
		if !c.Relay && remoteIP(c.Remote) == ip {
			n++
		}
	}
	return n
}

func (h *Hub) Clients() []*Client {
	h.mu.RLock()
	out := make([]*Client, 0, len(h.clients))
	for _, c := range h.clients {
		out = append(out, c)
	}
	h.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (h *Hub) Client(id uint64) *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clients[id]
}

func (h *Hub) ByUID(uid string) *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byUID[uid]
}

func (h *Hub) ByCallsign(cs string) *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byCallsign[cs]
}

func (h *Hub) Remove(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c.ID]; !ok {
		h.mu.Unlock()
		c.Close()
		return
	}
	delete(h.clients, c.ID)
	var gone []*Message
	c.mu.Lock()
	uid, cs, last := c.info.UID, c.info.Callsign, c.lastSA
	remote := c.remote
	c.remote = map[string]string{}
	c.mu.Unlock()
	if uid != "" && h.byUID[uid] == c {
		var other *Client
		for _, x := range h.clients {
			if !x.Relay && x.UID() == uid {
				other = x
				break
			}
		}
		if other != nil {
			h.byUID[uid] = other
		} else {
			delete(h.byUID, uid)
			if last != nil {
				gone = append(gone, last)
			}
		}
	}
	if cs != "" && h.byCallsign[cs] == c {
		var other *Client
		for _, x := range h.clients {
			if !x.Relay && x.Callsign() == cs {
				other = x
				break
			}
		}
		if other != nil {
			h.byCallsign[cs] = other
		} else {
			delete(h.byCallsign, cs)
		}
	}
	for ruid, rcs := range remote {
		if h.byUID[ruid] == c {
			delete(h.byUID, ruid)
			if m := h.cachedLocked(ruid); m != nil {
				gone = append(gone, m)
			}
		}
		if rcs != "" && h.byCallsign[rcs] == c {
			delete(h.byCallsign, rcs)
		}
	}
	h.mu.Unlock()
	c.Close()
	if h.OnRemove != nil {
		h.OnRemove(c)
	}
	for _, m := range gone {
		h.forget(m.Event.UID)
		h.disconnectNotice(m, c)
	}
}

func (h *Hub) cachedLocked(uid string) *Message {
	h.cmu.Lock()
	defer h.cmu.Unlock()
	return h.cache[uid]
}

func (h *Hub) disconnectNotice(last *Message, from *Client) {
	e := cot.DeleteFor(last.Event.UID, last.Event.Type)
	m := NewMessage(e, from, last.Groups)
	m.Everyone = last.Everyone
	m.NoReplay = true
	m.Disconnect = true
	h.broadcast(m)
}

func (h *Hub) AddRemote(c *Client, uid, callsign string) {
	if uid == "" {
		return
	}
	h.mu.Lock()
	c.mu.Lock()
	prev := c.remote[uid]
	c.remote[uid] = firstNonEmpty(callsign, prev)
	c.mu.Unlock()
	if existing := h.byUID[uid]; existing == nil || existing.Relay {
		h.byUID[uid] = c
	}
	if callsign != "" {
		if existing := h.byCallsign[callsign]; existing == nil || existing.Relay {
			h.byCallsign[callsign] = c
		}
	}
	h.mu.Unlock()
}

func (h *Hub) RemoveRemote(c *Client, uid string) *Message {
	h.mu.Lock()
	c.mu.Lock()
	cs, ok := c.remote[uid]
	delete(c.remote, uid)
	c.mu.Unlock()
	if h.byUID[uid] == c {
		delete(h.byUID, uid)
	}
	if ok && cs != "" && h.byCallsign[cs] == c {
		delete(h.byCallsign, cs)
	}
	h.mu.Unlock()
	last := h.CachedEvent(uid)
	h.forget(uid)
	return last
}

func (h *Hub) Subscribe(buffer int, filter func(*Message) bool) *Subscriber {
	s := &Subscriber{C: make(chan *Message, buffer), filter: filter}
	h.smu.Lock()
	h.subs[s] = struct{}{}
	h.smu.Unlock()
	return s
}

func (h *Hub) Unsubscribe(s *Subscriber) {
	h.smu.Lock()
	delete(h.subs, s)
	h.smu.Unlock()
}

func (h *Hub) notifySubs(m *Message) {
	h.smu.RLock()
	defer h.smu.RUnlock()
	for s := range h.subs {
		if s.filter != nil && !s.filter(m) {
			continue
		}
		select {
		case s.C <- m:
		default:
			s.drops.Add(1)
		}
	}
}

func (h *Hub) Identify(c *Client, m *Message) {
	e := m.Event
	if !e.IsSA() {
		return
	}
	device, platform, osv, version := e.Takv()
	team, role := e.Team()
	cs := e.Callsign()
	h.mu.Lock()
	c.mu.Lock()
	if c.Relay {
		prev, known := c.remote[e.UID]
		c.remote[e.UID] = cs
		c.mu.Unlock()
		if !known || prev != cs || h.byUID[e.UID] != c {
			if prev != "" && prev != cs && h.byCallsign[prev] == c {
				delete(h.byCallsign, prev)
			}
			if existing := h.byUID[e.UID]; existing == nil || existing.Relay {
				h.byUID[e.UID] = c
			}
			if cs != "" {
				if existing := h.byCallsign[cs]; existing == nil || existing.Relay {
					h.byCallsign[cs] = c
				}
			}
		}
		h.mu.Unlock()
		return
	}
	if c.info.UID != "" && c.info.UID != e.UID {
		c.mu.Unlock()
		h.mu.Unlock()
		return
	}
	first := c.info.UID == ""
	oldCS := c.info.Callsign
	c.info.UID = e.UID
	c.info.Callsign = cs
	c.info.Team, c.info.Role = team, role
	if platform != "" {
		c.info.Device, c.info.Platform, c.info.OS, c.info.Version = device, platform, osv, version
	}
	if ct := e.D("contact"); ct != nil && ct.Attr("phone") != "" {
		c.info.Phone = ct.Attr("phone")
	}
	c.info.Type = e.Type
	c.info.Lat, c.info.Lon, c.info.Hae = e.Point.Lat, e.Point.Lon, e.Point.Hae
	if tr := e.D("track"); tr != nil {
		c.info.Speed = cot.Finite(parseF(tr.Attr("speed")), 0)
		c.info.Course = cot.Finite(parseF(tr.Attr("course")), 0)
	}
	if st := e.D("status"); st != nil {
		c.info.Battery = st.Attr("battery")
	}
	c.info.LastSA = time.Now()
	c.lastSA = m
	c.mu.Unlock()
	h.byUID[e.UID] = c
	if oldCS != "" && oldCS != cs && h.byCallsign[oldCS] == c {
		delete(h.byCallsign, oldCS)
	}
	if cs != "" {
		h.byCallsign[cs] = c
	}
	h.mu.Unlock()
	if first && h.OnIdentify != nil {
		h.OnIdentify(c)
	}
}

func parseF(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return v
}

func (h *Hub) Publish(m *Message) {
	e := m.Event
	h.Events.Add(1)
	if h.OnCoT != nil {
		h.OnCoT(m)
	}
	h.notifySubs(m)
	if e.IsDelete() {
		for _, l := range e.Links() {
			if l.UID != "" {
				h.forget(l.UID)
				h.cancelEmergency(l.UID)
			}
		}
	}
	if e.Is("b-a-") {
		if e.EmergencyCancel() {
			h.cancelEmergency(e.UID)
		} else if e.IsEmergency() {
			h.emu.Lock()
			h.emergency[e.UID] = m
			h.emu.Unlock()
		}
	}
	var explicit []cot.Dest
	var missions []string
	for _, d := range e.Dests() {
		if d.Mission != "" {
			missions = append(missions, d.Mission)
		}
		if d.UID != "" || d.Callsign != "" {
			explicit = append(explicit, d)
		}
	}
	if len(missions) > 0 && h.OnMissions != nil {
		h.OnMissions(m, missions)
	}
	if len(explicit) > 0 {
		h.deliverExplicit(m, explicit)
		return
	}
	if len(missions) > 0 {
		return
	}
	h.remember(m)
	h.broadcast(m)
}

func (h *Hub) cancelEmergency(uid string) {
	h.emu.Lock()
	delete(h.emergency, uid)
	h.emu.Unlock()
}

func (h *Hub) visible(c *Client, m *Message) bool {
	if m.Everyone {
		return true
	}
	return c.OutMask().Intersects(m.Groups)
}

func (h *Hub) broadcast(m *Message) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.clients {
		if c == m.Source || !h.visible(c, m) {
			continue
		}
		if c.Send(m) {
			h.Delivered.Add(1)
		}
	}
}

func (h *Hub) deliverExplicit(m *Message, dests []cot.Dest) {
	strict := h.srv != nil && h.srv.Config().StrictGroups
	seen := map[*Client]bool{}
	var missing []cot.Dest
	h.mu.RLock()
	for _, d := range dests {
		var target *Client
		if d.UID != "" {
			target = h.byUID[d.UID]
		}
		if target == nil && d.Callsign != "" {
			target = h.byCallsign[d.Callsign]
		}
		if target == nil {
			missing = append(missing, d)
			continue
		}
		if target == m.Source || seen[target] {
			continue
		}
		seen[target] = true
		if strict && !h.visible(target, m) {
			continue
		}
		if target.Send(m) {
			h.Delivered.Add(1)
		}
	}
	h.mu.RUnlock()
	if len(missing) > 0 && h.OnOffline != nil {
		for _, d := range missing {
			h.OnOffline(d, m)
		}
	}
}

func cacheable(e *cot.Event) bool {
	if e.IsControl() || e.IsChat() || e.Is("y-") || e.Is("b-f-t-") || e.Is("t-") {
		return false
	}
	return true
}

func (h *Hub) remember(m *Message) {
	e := m.Event
	if m.NoReplay || !cacheable(e) || e.IsStale(time.Now()) {
		return
	}
	h.cmu.Lock()
	defer h.cmu.Unlock()
	if _, ok := h.cache[e.UID]; !ok && len(h.cache) >= h.cacheLimit {
		now := time.Now()
		for k, v := range h.cache {
			if v.Event.IsStale(now) {
				delete(h.cache, k)
			}
		}
		for k := range h.cache {
			if len(h.cache) < h.cacheLimit {
				break
			}
			delete(h.cache, k)
		}
	}
	h.cache[e.UID] = m
}

func (h *Hub) forget(uid string) {
	h.cmu.Lock()
	delete(h.cache, uid)
	h.cmu.Unlock()
}

func (h *Hub) Cached() []*Message {
	now := time.Now()
	h.cmu.Lock()
	out := make([]*Message, 0, len(h.cache))
	for k, m := range h.cache {
		if m.Event.IsStale(now) {
			delete(h.cache, k)
			continue
		}
		out = append(out, m)
	}
	h.cmu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Received.Before(out[j].Received) })
	return out
}

func (h *Hub) CachedEvent(uid string) *Message {
	h.cmu.Lock()
	defer h.cmu.Unlock()
	m := h.cache[uid]
	if m != nil && m.Event.IsStale(time.Now()) {
		delete(h.cache, uid)
		return nil
	}
	return m
}

func (h *Hub) Replay(c *Client, mode string, limit int) int {
	if mode == "none" || limit == 0 {
		return 0
	}
	list := h.Cached()
	var sa, rest []*Message
	for _, m := range list {
		if m.Source == c || !h.visible(c, m) {
			continue
		}
		if m.Event.IsSA() {
			sa = append(sa, m)
		} else if mode != "sa" {
			rest = append(rest, m)
		}
	}
	sent := 0
	for _, m := range append(sa, rest...) {
		if limit > 0 && sent >= limit {
			break
		}
		if c.Send(m) {
			sent++
		}
	}
	return sent
}

func (h *Hub) RepeatEmergencies() {
	now := time.Now()
	h.emu.Lock()
	var list []*Message
	for k, m := range h.emergency {
		if m.Event.IsStale(now) {
			delete(h.emergency, k)
			continue
		}
		list = append(list, m)
	}
	h.emu.Unlock()
	for _, m := range list {
		h.broadcast(m)
	}
}

func (h *Hub) Emergencies() []*Message {
	h.emu.Lock()
	defer h.emu.Unlock()
	out := make([]*Message, 0, len(h.emergency))
	for _, m := range h.emergency {
		out = append(out, m)
	}
	return out
}

func (h *Hub) Prune() {
	now := time.Now()
	h.cmu.Lock()
	for k, m := range h.cache {
		if m.Event.IsStale(now) {
			delete(h.cache, k)
		}
	}
	h.cmu.Unlock()
}

func (h *Hub) View(c *Client) ClientView {
	v := ClientView{
		ID: c.ID, Kind: c.Kind, Name: c.Name, Remote: c.Remote, User: c.User(), Connected: c.Connected, LastSeen: c.LastSeen(),
		Rx: c.rx.Load(), Tx: c.tx.Load(), Dropped: c.drops.Load(), Info: c.Info(), Protocol: "xml", Internal: c.Internal(),
	}
	if c.UseProto() {
		v.Protocol = "protobuf"
	}
	if h.srv != nil && h.srv.dir != nil {
		v.Groups = h.srv.dir.Names(c.OutMask().Union(c.InMask()))
	}
	c.mu.Lock()
	v.Contacts = len(c.remote)
	c.mu.Unlock()
	return v
}

func (h *Hub) Contacts() []ClientInfo {
	var out []ClientInfo
	for _, c := range h.Clients() {
		if c.Relay {
			c.mu.Lock()
			remote := make(map[string]string, len(c.remote))
			for k, v := range c.remote {
				remote[k] = v
			}
			c.mu.Unlock()
			for uid, cs := range remote {
				info := ClientInfo{UID: uid, Callsign: cs}
				if m := h.CachedEvent(uid); m != nil {
					info.Type = m.Event.Type
					info.Lat, info.Lon = m.Event.Point.Lat, m.Event.Point.Lon
					info.Team, info.Role = m.Event.Team()
					_, info.Platform, _, info.Version = m.Event.Takv()
					info.LastSA = m.Received
				}
				out = append(out, info)
			}
			continue
		}
		if info := c.Info(); info.UID != "" {
			out = append(out, info)
		}
	}
	return out
}
