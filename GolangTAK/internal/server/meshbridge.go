package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/meshtastic"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/mqtt"
)

type meshNode struct {
	num       uint32
	longName  string
	shortName string
	hw        uint32
	lat, lon  float64
	alt       float64
	hasAlt    bool
	hasPos    bool
	battery   uint32
	speed     float64
	course    float64
	hasTrack  bool
	takUID    string
	callsign  string
	team      string
	role      string
	lastSeen  time.Time
	lastPub   time.Time
}

type MeshNodeView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Short    string    `json:"short"`
	Callsign string    `json:"callsign,omitempty"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Battery  uint32    `json:"battery"`
	LastSeen time.Time `json:"lastSeen"`
}

type MeshStatus struct {
	Enabled       bool           `json:"enabled"`
	GatewayID     string         `json:"gatewayId"`
	BrokerPort    int            `json:"brokerPort"`
	BrokerClients int            `json:"brokerClients"`
	BrokerError   string         `json:"brokerError,omitempty"`
	Upstream      string         `json:"upstream,omitempty"`
	UpstreamState string         `json:"upstreamState,omitempty"`
	UpstreamError string         `json:"upstreamError,omitempty"`
	PacketsIn     uint64         `json:"packetsIn"`
	PacketsOut    uint64         `json:"packetsOut"`
	Undecryptable uint64         `json:"undecryptable"`
	Nodes         []MeshNodeView `json:"nodes"`
}

type meshKey struct {
	name string
	key  []byte
}

type meshBridge struct {
	s         *Server
	cfg       MeshtasticConfig
	keys      map[string][]byte
	byHash    map[uint32][]meshKey
	down      meshKey
	client    *Client
	broker    *mqtt.Broker
	brokerErr string
	mu        sync.Mutex
	nodes     map[uint32]*meshNode
	seen      map[uint64]time.Time
	lastSent  map[string]time.Time
	upMu      sync.Mutex
	up        *mqtt.Client
	upState   string
	upErr     string
	in        atomic.Uint64
	out       atomic.Uint64
	bad       atomic.Uint64
}

func meshKeys(cfg MeshtasticConfig) (map[string][]byte, map[uint32][]meshKey, error) {
	keys := map[string][]byte{}
	byHash := map[uint32][]meshKey{}
	for _, ch := range cfg.Channels {
		name := strings.TrimSpace(ch.Name)
		if name == "" {
			return nil, nil, errors.New("every Meshtastic channel needs a name")
		}
		k, err := meshtastic.ParseKey(ch.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("channel %s: %w", name, err)
		}
		keys[name] = k
		h := meshtastic.ChannelHash(name, k)
		byHash[h] = append(byHash[h], meshKey{name: name, key: k})
	}
	return keys, byHash, nil
}

func (s *Server) startMeshtastic() {
	cfg := s.Config().Meshtastic
	if !cfg.Enabled {
		return
	}
	keys, byHash, err := meshKeys(cfg)
	if err != nil {
		s.log.Error("Meshtastic bridge not started", "err", err)
		return
	}
	b := &meshBridge{s: s, cfg: cfg, keys: keys, byHash: byHash, nodes: map[uint32]*meshNode{}, seen: map[uint64]time.Time{}, lastSent: map[string]time.Time{}}
	downName := firstNonEmpty(cfg.DownlinkChannel, cfg.Channels[0].Name)
	b.down = meshKey{name: downName, key: keys[downName]}
	var groups []string
	if cfg.Group != "" {
		if _, err := s.dir.EnsureGroup(cfg.Group, "Meshtastic", false); err == nil {
			groups = []string{cfg.Group}
		}
	}
	b.client = s.relayClient(KindMeshtastic, "Meshtastic", "mqtt", groups)
	b.client.filter = func(*Message) bool { return false }
	s.hub.Add(b.client)
	s.mesh = b
	if cfg.BrokerPort > 0 {
		addr := s.addr(cfg.BrokerPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			b.brokerErr = portError("tcp", addr, err).Error()
			s.log.Error("Meshtastic MQTT broker not started", "err", b.brokerErr)
		} else {
			s.track(ln)
			b.broker = &mqtt.Broker{Log: s.log, OnPublish: b.inbound, Auth: b.auth, MaxPacket: 256 << 10}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				b.broker.Serve(ln)
			}()
			s.stoppers = append(s.stoppers, b.broker.Close)
			s.log.Info("Meshtastic MQTT broker listening", "addr", addr)
		}
	}
	if cfg.Upstream != "" {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			b.upstreamLoop()
		}()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		b.maintain()
	}()
	if cfg.Downlink {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			b.downlinkLoop()
		}()
	}
}

func (b *meshBridge) auth(clientID, user, pass string, remote net.Addr) bool {
	if b.cfg.BrokerAnonymous {
		return true
	}
	if user == "" {
		return false
	}
	_, err := b.s.dir.CheckPassword(remoteIP(remote.String()), user, pass)
	return err == nil
}

func (b *meshBridge) status() MeshStatus {
	st := MeshStatus{Enabled: true, GatewayID: meshtastic.NodeID(b.cfg.NodeNum), BrokerPort: b.cfg.BrokerPort, BrokerError: b.brokerErr,
		PacketsIn: b.in.Load(), PacketsOut: b.out.Load(), Undecryptable: b.bad.Load(), Nodes: []MeshNodeView{}}
	if b.broker != nil {
		st.BrokerClients = b.broker.Clients()
	}
	if b.cfg.Upstream != "" {
		st.Upstream = redactURL(b.cfg.Upstream)
		b.upMu.Lock()
		st.UpstreamState, st.UpstreamError = b.upState, b.upErr
		b.upMu.Unlock()
	}
	b.mu.Lock()
	for _, n := range b.nodes {
		st.Nodes = append(st.Nodes, MeshNodeView{ID: meshtastic.NodeID(n.num), Name: n.longName, Short: n.shortName, Callsign: n.callsign, Lat: n.lat, Lon: n.lon, Battery: n.battery, LastSeen: n.lastSeen})
	}
	b.mu.Unlock()
	sort.Slice(st.Nodes, func(i, j int) bool { return st.Nodes[i].LastSeen.After(st.Nodes[j].LastSeen) })
	return st
}

func (s *Server) meshStatus() MeshStatus {
	if s.mesh == nil {
		return MeshStatus{Enabled: s.Config().Meshtastic.Enabled, Nodes: []MeshNodeView{}}
	}
	return s.mesh.status()
}

func (b *meshBridge) upstreamLoop() {
	delay := time.Second
	set := func(state, err string) {
		b.upMu.Lock()
		b.upState, b.upErr = state, err
		b.upMu.Unlock()
	}
	for {
		set("connecting", "")
		ctx, cancel := context.WithTimeout(b.s.ctx, 20*time.Second)
		c, err := mqtt.Dial(ctx, b.cfg.Upstream, mqtt.ClientOptions{ClientID: "golangtak-" + strings.TrimPrefix(meshtastic.NodeID(b.cfg.NodeNum), "!")})
		cancel()
		if err == nil {
			err = c.Subscribe(strings.TrimRight(b.cfg.Root, "/") + "/2/#")
			if err != nil {
				c.Close()
			}
		}
		if err != nil {
			set("waiting", err.Error())
			b.s.log.Warn("Meshtastic upstream broker unavailable", "broker", redactURL(b.cfg.Upstream), "err", err)
		} else {
			set("connected", "")
			b.s.log.Info("Meshtastic upstream broker connected", "broker", redactURL(b.cfg.Upstream))
			delay = time.Second
			b.upMu.Lock()
			b.up = c
			b.upMu.Unlock()
		loop:
			for {
				select {
				case <-b.s.ctx.Done():
					c.Close()
					return
				case m, ok := <-c.Messages():
					if !ok {
						break loop
					}
					b.inbound(m)
				}
			}
			b.upMu.Lock()
			b.up = nil
			b.upMu.Unlock()
			set("waiting", "connection lost")
		}
		select {
		case <-b.s.ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}

func (b *meshBridge) maintain() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-b.s.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		b.mu.Lock()
		for k, at := range b.seen {
			if now.Sub(at) > 10*time.Minute {
				delete(b.seen, k)
			}
		}
		for k, n := range b.nodes {
			if now.Sub(n.lastSeen) > 48*time.Hour {
				delete(b.nodes, k)
			}
		}
		for k, at := range b.lastSent {
			if now.Sub(at) > time.Hour {
				delete(b.lastSent, k)
			}
		}
		b.mu.Unlock()
	}
}

func (b *meshBridge) inbound(m mqtt.Message) {
	switch {
	case strings.Contains(m.Topic, "/2/e/") || strings.Contains(m.Topic, "/2/c/"):
		env, err := meshtastic.ParseEnvelope(m.Payload)
		if err != nil {
			b.bad.Add(1)
			return
		}
		b.handlePacket(env.Packet, env.ChannelID)
	case strings.Contains(m.Topic, "/2/json/"):
		b.handleJSON(m.Payload)
	}
}

func knownPort(p uint32) bool {
	switch p {
	case meshtastic.PortText, meshtastic.PortPosition, meshtastic.PortNodeInfo, meshtastic.PortRouting, meshtastic.PortWaypoint,
		meshtastic.PortTelemetry, meshtastic.PortATAK, meshtastic.PortMapReport, 2, 6, 7, 9, 10, 32, 33, 34, 64, 65, 66, 68, 69, 70, 71, 74, 256, 257:
		return true
	}
	return false
}

func (b *meshBridge) decrypt(p *meshtastic.Packet, channelID string) *meshtastic.Data {
	try := func(k []byte) *meshtastic.Data {
		plain, err := meshtastic.Crypt(k, p.ID, p.From, p.Encrypted)
		if err != nil {
			return nil
		}
		d, err := meshtastic.ParseData(plain)
		if err != nil || !knownPort(d.Portnum) {
			return nil
		}
		return d
	}
	if k, ok := b.keys[channelID]; ok {
		if d := try(k); d != nil {
			return d
		}
	}
	for _, mk := range b.byHash[p.Channel] {
		if mk.name == channelID {
			continue
		}
		if d := try(mk.key); d != nil {
			return d
		}
	}
	return nil
}

func (b *meshBridge) node(num uint32) *meshNode {
	n := b.nodes[num]
	if n == nil {
		n = &meshNode{num: num}
		b.nodes[num] = n
	}
	n.lastSeen = time.Now()
	return n
}

func printable(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func (b *meshBridge) handlePacket(p *meshtastic.Packet, channelID string) {
	if p == nil || p.From == 0 || p.From == b.cfg.NodeNum {
		return
	}
	if p.ID != 0 {
		key := uint64(p.From)<<32 | uint64(p.ID)
		b.mu.Lock()
		_, dup := b.seen[key]
		b.seen[key] = time.Now()
		b.mu.Unlock()
		if dup {
			return
		}
	}
	data := p.Decoded
	if data == nil && len(p.Encrypted) > 0 {
		data = b.decrypt(p, channelID)
		if data == nil {
			b.bad.Add(1)
			return
		}
	}
	if data == nil {
		return
	}
	b.in.Add(1)
	b.mu.Lock()
	n := b.node(p.From)
	var publish bool
	var chat string
	switch data.Portnum {
	case meshtastic.PortNodeInfo:
		if u, err := meshtastic.ParseUser(data.Payload); err == nil {
			if printable(u.LongName) {
				n.longName = u.LongName
			}
			if printable(u.ShortName) {
				n.shortName = u.ShortName
			}
			n.hw = u.HWModel
			publish = n.hasPos
		}
	case meshtastic.PortPosition:
		if pos, err := meshtastic.ParsePosition(data.Payload); err == nil && pos.HasPosition {
			n.lat, n.lon, n.hasPos = pos.Lat(), pos.Lon(), true
			n.alt, n.hasAlt = float64(pos.Altitude), pos.HasAltitude
			if c, ok := pos.Course(); ok {
				n.course, n.hasTrack = c, true
			}
			if pos.HasSpeed {
				n.speed, n.hasTrack = float64(pos.GroundSpeed), true
			}
			publish = true
		}
	case meshtastic.PortTelemetry:
		if dm, err := meshtastic.ParseDeviceMetrics(data.Payload); err == nil && dm != nil && dm.HasBattery {
			n.battery = min(dm.Battery, 100)
		}
	case meshtastic.PortText:
		if p.To == meshtastic.Broadcast && utf8.Valid(data.Payload) {
			chat = strings.TrimSpace(string(data.Payload))
		}
	case meshtastic.PortATAK:
		t, err := meshtastic.ParseTAK(data.Payload)
		if err != nil {
			break
		}
		if !t.Compressed {
			if printable(t.Callsign) {
				n.callsign = t.Callsign
			}
			if printable(t.DeviceCallsign) && validUIDChars(t.DeviceCallsign) {
				n.takUID = t.DeviceCallsign
			}
		}
		if t.Team > 0 {
			n.team = meshtastic.TeamName(t.Team)
		}
		if t.Role > 0 {
			n.role = meshtastic.RoleName(t.Role)
		}
		if t.Battery > 0 {
			n.battery = min(t.Battery, 100)
		}
		if t.PLI != nil && !(t.PLI.LatI == 0 && t.PLI.LonI == 0) {
			n.lat, n.lon, n.hasPos = float64(t.PLI.LatI)/1e7, float64(t.PLI.LonI)/1e7, true
			n.alt, n.hasAlt = float64(t.PLI.Altitude), true
			n.speed, n.course, n.hasTrack = float64(t.PLI.Speed), float64(t.PLI.Course), true
			publish = true
		}
		if t.Chat != nil && !t.Compressed && printable(t.Chat.Message) {
			chat = t.Chat.Message
		}
	}
	var ev *cot.Event
	if publish && time.Since(n.lastPub) >= 2*time.Second {
		n.lastPub = time.Now()
		ev = b.nodeEvent(n)
	}
	var chatEv *cot.Event
	if chat != "" {
		chatEv = cot.Chat(b.nodeUID(n), b.nodeCallsign(n), "All Chat Rooms", "All Chat Rooms", chat, nil)
	}
	b.mu.Unlock()
	if ev != nil {
		b.publish(ev, false)
	}
	if chatEv != nil {
		b.publish(chatEv, true)
	}
}

func broadcastChat(e *cot.Event) bool {
	if ch := e.D("__chat"); ch != nil {
		room := firstNonEmpty(ch.Attr("id"), ch.Attr("chatroom"))
		if strings.EqualFold(room, "All Chat Rooms") {
			return true
		}
	}
	return len(e.Dests()) == 0
}

func validUIDChars(s string) bool {
	if len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r == '<' || r == '>' || r == '"' || r == '&' || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func (b *meshBridge) nodeUID(n *meshNode) string {
	if n.takUID != "" {
		return n.takUID
	}
	return "MESHTASTIC-" + meshtastic.NodeID(n.num)
}

func (b *meshBridge) nodeCallsign(n *meshNode) string {
	return firstNonEmpty(n.callsign, n.longName, n.shortName, meshtastic.NodeID(n.num))
}

func (b *meshBridge) nodeEvent(n *meshNode) *cot.Event {
	e := cot.New(b.nodeUID(n), "a-f-G-U-C", "m-g", 15*time.Minute)
	hae := cot.Unknown
	if n.hasAlt {
		hae = n.alt
	}
	e.Point = cot.Point{Lat: n.lat, Lon: n.lon, Hae: hae, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", b.nodeCallsign(n))
	e.Detail.AddNew("__group", "name", firstNonEmpty(n.team, "Cyan"), "role", firstNonEmpty(n.role, "Team Member"))
	e.Detail.AddNew("takv", "platform", "Meshtastic", "device", "Meshtastic", "os", "", "version", "")
	if n.battery > 0 {
		e.Detail.AddNew("status", "battery", itoa(int(n.battery)))
	}
	if n.hasTrack {
		e.Detail.AddNew("track", "speed", cot.FormatFloat(n.speed), "course", cot.FormatFloat(n.course))
	}
	remark := "Meshtastic node " + meshtastic.NodeID(n.num)
	if n.shortName != "" {
		remark += " (" + n.shortName + ")"
	}
	e.Detail.AddNew("remarks").Text = remark
	return e
}

func (b *meshBridge) publish(e *cot.Event, chat bool) {
	m := NewMessage(e, b.client, b.client.InMask())
	m.Everyone = b.cfg.Group == ""
	m.NoReplay = chat
	m.Feed = FeedMeshtastic
	b.s.hub.Identify(b.client, m)
	b.s.hub.Publish(m)
}

type meshJSON struct {
	From    uint32          `json:"from"`
	To      uint32          `json:"to"`
	ID      uint32          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func (b *meshBridge) handleJSON(raw []byte) {
	var j meshJSON
	if json.Unmarshal(raw, &j) != nil || j.From == 0 {
		return
	}
	var d meshtastic.Data
	switch j.Type {
	case "text":
		var p struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(j.Payload, &p) != nil {
			return
		}
		d = meshtastic.Data{Portnum: meshtastic.PortText, Payload: []byte(p.Text)}
	case "position":
		var p struct {
			Lat   int32  `json:"latitude_i"`
			Lon   int32  `json:"longitude_i"`
			Alt   int32  `json:"altitude"`
			Speed uint32 `json:"ground_speed"`
			Track uint32 `json:"ground_track"`
		}
		if json.Unmarshal(j.Payload, &p) != nil {
			return
		}
		pos := meshtastic.Position{LatI: p.Lat, LonI: p.Lon, Altitude: p.Alt, GroundSpeed: p.Speed, GroundTrack: p.Track}
		d = meshtastic.Data{Portnum: meshtastic.PortPosition, Payload: pos.Marshal()}
	case "nodeinfo":
		var p struct {
			ID    string `json:"id"`
			Long  string `json:"longname"`
			Short string `json:"shortname"`
			HW    uint32 `json:"hardware"`
		}
		if json.Unmarshal(j.Payload, &p) != nil {
			return
		}
		u := meshtastic.User{ID: p.ID, LongName: p.Long, ShortName: p.Short, HWModel: p.HW}
		d = meshtastic.Data{Portnum: meshtastic.PortNodeInfo, Payload: u.Marshal()}
	default:
		return
	}
	b.handlePacket(&meshtastic.Packet{From: j.From, To: j.To, ID: j.ID, Decoded: &d}, "")
}

func randomID() uint32 {
	var b [4]byte
	rand.Read(b[:])
	v := binary.LittleEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

func (b *meshBridge) send(d *meshtastic.Data) {
	id := randomID()
	p := &meshtastic.Packet{From: b.cfg.NodeNum, To: meshtastic.Broadcast, ID: id, HopLimit: 3, HopStart: 3,
		Channel: meshtastic.ChannelHash(b.down.name, b.down.key)}
	if len(b.down.key) == 0 {
		p.Decoded = d
	} else {
		enc, err := meshtastic.Crypt(b.down.key, id, b.cfg.NodeNum, d.Marshal())
		if err != nil {
			return
		}
		p.Encrypted = enc
	}
	gw := meshtastic.NodeID(b.cfg.NodeNum)
	env := &meshtastic.Envelope{Packet: p, ChannelID: b.down.name, GatewayID: gw}
	topic := strings.TrimRight(b.cfg.Root, "/") + "/2/e/" + b.down.name + "/" + gw
	payload := env.Marshal()
	if b.broker != nil {
		b.broker.Publish(topic, payload)
	}
	b.upMu.Lock()
	up := b.up
	b.upMu.Unlock()
	if up != nil {
		up.Publish(topic, payload)
	}
	b.out.Add(1)
}

func (b *meshBridge) announce() {
	name := b.s.Config().Name
	if len(name) > 36 {
		name = name[:36]
	}
	u := meshtastic.User{ID: meshtastic.NodeID(b.cfg.NodeNum), LongName: name, ShortName: "TAK"}
	b.send(&meshtastic.Data{Portnum: meshtastic.PortNodeInfo, Payload: u.Marshal()})
}

func (b *meshBridge) downlinkLoop() {
	mask := b.client.InMask()
	sub := b.s.hub.Subscribe(512, func(m *Message) bool {
		if m.Source == b.client || m.Source == nil {
			return false
		}
		if m.Source.Relay && m.Source.Kind == KindMeshtastic {
			return false
		}
		if !m.Event.IsSA() && !(m.Event.IsChat() && broadcastChat(m.Event)) {
			return false
		}
		return b.cfg.Group == "" || m.Everyone || m.Groups.Intersects(mask)
	})
	defer b.s.hub.Unsubscribe(sub)
	nodeinfo := time.NewTimer(20 * time.Second)
	defer nodeinfo.Stop()
	interval := time.Duration(b.cfg.IntervalSec) * time.Second
	for {
		select {
		case <-b.s.ctx.Done():
			return
		case <-nodeinfo.C:
			b.announce()
			nodeinfo.Reset(3 * time.Hour)
		case m := <-sub.C:
			e := m.Event
			if e.IsChat() {
				text := strings.TrimSpace(e.Remarks())
				if text == "" {
					continue
				}
				from := e.Callsign()
				if ch := e.D("__chat"); ch != nil {
					from = firstNonEmpty(ch.Attr("senderCallsign"), from)
				}
				msg := firstNonEmpty(from, "TAK") + ": " + text
				if len(msg) > 200 {
					msg = msg[:200]
				}
				b.send(&meshtastic.Data{Portnum: meshtastic.PortText, Payload: []byte(msg)})
				continue
			}
			if e.Point.Lat == 0 && e.Point.Lon == 0 {
				continue
			}
			b.mu.Lock()
			last := b.lastSent[e.UID]
			ok := time.Since(last) >= interval
			if ok {
				b.lastSent[e.UID] = time.Now()
			}
			b.mu.Unlock()
			if !ok {
				continue
			}
			team, role := e.Team()
			t := &meshtastic.TAKPacket{Callsign: e.Callsign(), DeviceCallsign: e.UID, Team: meshtastic.TeamNumber(team), Role: meshtastic.RoleNumber(role)}
			if st := e.D("status"); st != nil {
				if v, err := strconv.ParseUint(strings.TrimSpace(st.Attr("battery")), 10, 32); err == nil && v > 0 {
					t.Battery = uint32(min(v, 100))
				}
			}
			pli := &meshtastic.PLI{LatI: int32(e.Point.Lat * 1e7), LonI: int32(e.Point.Lon * 1e7)}
			if e.Point.Hae < cot.Unknown && e.Point.Hae > -1000 {
				pli.Altitude = int32(e.Point.Hae)
			}
			if tr := e.D("track"); tr != nil {
				if sp := cot.Finite(parseF(tr.Attr("speed")), 0); sp > 0 {
					pli.Speed = uint32(sp)
				}
				if c := cot.Finite(parseF(tr.Attr("course")), 0); c > 0 && c < 360 {
					pli.Course = uint32(c)
				}
			}
			t.PLI = pli
			b.send(&meshtastic.Data{Portnum: meshtastic.PortATAK, Payload: t.Marshal()})
		}
	}
}
