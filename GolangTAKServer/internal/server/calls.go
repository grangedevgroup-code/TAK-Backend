package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/turn"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

type CallsConfig struct {
	Disabled     bool   `json:"disabled,omitempty"`
	TURNPort     int    `json:"turnPort,omitempty"`
	RelayPorts   string `json:"relayPorts,omitempty"`
	RelayAddress string `json:"relayAddress,omitempty"`
}

const maxRoomSize = 8

var roomIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)

func (c CallsConfig) turnPort() int {
	switch {
	case c.TURNPort < 0:
		return 0
	case c.TURNPort == 0:
		return 3478
	}
	return c.TURNPort
}

func RelayRange(c CallsConfig) (int, int) { return c.relayRange() }

func (c CallsConfig) relayRange() (int, int) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(c.RelayPorts), "-")
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || a < 1024 || b > 65535 || b < a {
		return 49160, 49200
	}
	return a, b
}

type callConn struct {
	id     string
	user   string
	admin  bool
	groups []string
	out    chan []byte
	room   string
}

type callRoom struct {
	members map[*callConn]bool
	invited map[string]bool
	created time.Time
}

type callHub struct {
	mu     sync.Mutex
	conns  map[*callConn]bool
	rooms  map[string]*callRoom
	turn   *turn.Server
	secret []byte
}

func newCallHub() *callHub {
	k := make([]byte, 32)
	rand.Read(k)
	return &callHub{conns: map[*callConn]bool{}, rooms: map[string]*callRoom{}, secret: k}
}

func (s *Server) startCalls() {
	cfg := s.Config()
	cc := cfg.Calls
	if cc.Disabled || cc.turnPort() == 0 {
		return
	}
	lo, hi := cc.relayRange()
	var relayIP net.IP
	for _, h := range []string{cc.RelayAddress, cfg.Address} {
		if ip := net.ParseIP(strings.TrimSpace(h)); ip != nil {
			relayIP = ip
			break
		}
		if h != "" {
			if ips, err := net.LookupIP(h); err == nil && len(ips) > 0 {
				relayIP = ips[0]
				break
			}
		}
	}
	if relayIP == nil {
		relayIP = net.ParseIP(PrimaryIP())
	}
	ts, err := turn.Listen(net.JoinHostPort(cfg.Bind, strconv.Itoa(cc.turnPort())), turn.Config{
		Realm: "golangtakserver", Secret: s.calls.secret, RelayIP: relayIP, PortMin: lo, PortMax: hi, Log: s.log,
	})
	if err != nil {
		s.log.Warn("call relay (TURN) not started", "port", cc.turnPort(), "err", err)
		return
	}
	s.calls.turn = ts
	s.log.Info("call relay (STUN/TURN) listening", "port", cc.turnPort(), "relay", relayIP.String(), "relayPorts", strconv.Itoa(lo)+"-"+strconv.Itoa(hi))
	s.stoppers = append(s.stoppers, ts.Close)
}

func (s *Server) iceServers(r *http.Request, user string) []map[string]any {
	if s.calls.turn == nil {
		return []map[string]any{}
	}
	cfg := s.Config()
	reqHost := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		reqHost = h
	}
	var hosts []string
	for _, h := range []string{reqHost, cfg.Calls.RelayAddress, cfg.Address} {
		h = strings.Trim(strings.TrimSpace(h), "[]")
		if h == "" || strings.EqualFold(h, "localhost") || slices.Contains(hosts, h) {
			continue
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			continue
		}
		hosts = append(hosts, h)
	}
	port := strconv.Itoa(cfg.Calls.turnPort())
	var stun, relay []string
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
			h = "[" + h + "]"
		}
		stun = append(stun, "stun:"+h+":"+port)
		relay = append(relay, "turn:"+h+":"+port+"?transport=udp")
	}
	if len(hosts) == 0 {
		return []map[string]any{}
	}
	name, pass := turn.Credentials(s.calls.secret, user, 12*time.Hour)
	return []map[string]any{
		{"urls": stun},
		{"urls": relay, "username": name, "credential": pass},
	}
}

func (s *Server) apiCallsInfo(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": !s.Config().Calls.Disabled, "ice": s.iceServers(r, id.Name), "relay": s.calls.turn != nil})
}

func (s *Server) canCall(a, b *callConn) bool {
	if a.admin || b.admin || a.user == b.user {
		return true
	}
	return slices.ContainsFunc(a.groups, func(g string) bool { return slices.Contains(b.groups, g) })
}

func (h *callHub) sendLocked(c *callConn, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case c.out <- b:
	default:
	}
}

func (s *Server) presenceLocked() {
	h := s.calls
	for c := range h.conns {
		users := map[string]bool{}
		for o := range h.conns {
			if o != c && o.user != c.user && s.canCall(c, o) {
				users[o.user] = true
			}
		}
		list := make([]string, 0, len(users))
		for u := range users {
			list = append(list, u)
		}
		sort.Strings(list)
		h.sendLocked(c, map[string]any{"t": "presence", "users": list})
	}
}

func (s *Server) leaveRoomLocked(c *callConn) {
	h := s.calls
	room := h.rooms[c.room]
	if room == nil {
		c.room = ""
		return
	}
	delete(room.members, c)
	for o := range room.members {
		h.sendLocked(o, map[string]any{"t": "left", "room": c.room, "peer": c.id, "user": c.user})
	}
	if len(room.members) == 0 {
		delete(h.rooms, c.room)
	}
	c.room = ""
}

func (s *Server) callMessage(c *callConn, raw []byte) {
	var msg struct {
		T     string          `json:"t"`
		Room  string          `json:"room"`
		To    json.RawMessage `json:"to"`
		Video bool            `json:"video"`
		Data  json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		return
	}
	h := s.calls
	h.mu.Lock()
	defer h.mu.Unlock()
	switch msg.T {
	case "ring":
		if !roomIDRe.MatchString(msg.Room) {
			return
		}
		var to []string
		json.Unmarshal(msg.To, &to)
		room := h.rooms[msg.Room]
		if room == nil {
			room = &callRoom{members: map[*callConn]bool{}, invited: map[string]bool{c.user: true}, created: time.Now()}
			h.rooms[msg.Room] = room
		} else if !room.members[c] && !room.invited[c.user] {
			return
		}
		for _, u := range to {
			for o := range h.conns {
				if o.user == u && s.canCall(c, o) {
					room.invited[u] = true
					h.sendLocked(o, map[string]any{"t": "ring", "room": msg.Room, "from": c.user, "video": msg.Video})
				}
			}
		}
	case "join":
		room := h.rooms[msg.Room]
		if room == nil || !room.invited[c.user] {
			h.sendLocked(c, map[string]any{"t": "error", "room": msg.Room, "error": "the call has ended or you were not invited"})
			return
		}
		if len(room.members) >= maxRoomSize {
			h.sendLocked(c, map[string]any{"t": "error", "room": msg.Room, "error": "the call is full"})
			return
		}
		if c.room != "" && c.room != msg.Room {
			s.leaveRoomLocked(c)
		}
		peers := []map[string]string{}
		for o := range room.members {
			peers = append(peers, map[string]string{"id": o.id, "user": o.user})
			h.sendLocked(o, map[string]any{"t": "joined", "room": msg.Room, "peer": c.id, "user": c.user})
		}
		room.members[c] = true
		c.room = msg.Room
		h.sendLocked(c, map[string]any{"t": "peers", "room": msg.Room, "peers": peers})
	case "signal":
		var to string
		json.Unmarshal(msg.To, &to)
		room := h.rooms[c.room]
		if room == nil || len(msg.Data) > 60000 {
			return
		}
		for o := range room.members {
			if o.id == to {
				h.sendLocked(o, map[string]any{"t": "signal", "from": c.id, "user": c.user, "data": msg.Data})
			}
		}
	case "decline":
		if room := h.rooms[msg.Room]; room != nil {
			for o := range room.members {
				h.sendLocked(o, map[string]any{"t": "declined", "room": msg.Room, "user": c.user})
			}
		}
	case "leave":
		s.leaveRoomLocked(c)
	}
}

func (s *Server) apiCallsSocket(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if s.Config().Calls.Disabled {
		apiError(w, http.StatusNotFound, errCallsOff)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.MaxMessage = 64 << 10
	c := &callConn{id: NewSecret(9), user: id.Name, admin: id.Admin, groups: s.identityGroups(id), out: make(chan []byte, 64)}
	h := s.calls
	h.mu.Lock()
	h.conns[c] = true
	h.sendLocked(c, map[string]any{"t": "hello", "id": c.id, "user": c.user, "ice": s.iceServers(r, c.user)})
	s.presenceLocked()
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		s.leaveRoomLocked(c)
		delete(h.conns, c)
		s.presenceLocked()
		h.mu.Unlock()
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			s.callMessage(c, data)
		}
	}()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-done:
			return
		case <-s.ctx.Done():
			conn.Close(websocket.CloseGoingAway, "server stopping")
			return
		case <-ping.C:
			if conn.Ping(nil) != nil {
				return
			}
		case b := <-c.out:
			conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if conn.WriteText(string(b)) != nil {
				return
			}
		}
	}
}

var errCallsOff = errors.New("calls are turned off under Settings, Calls")
