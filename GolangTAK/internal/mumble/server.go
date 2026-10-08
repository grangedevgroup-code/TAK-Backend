package mumble

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	msgVersion = iota
	msgUDPTunnel
	msgAuthenticate
	msgPing
	msgReject
	msgServerSync
	msgChannelRemove
	msgChannelState
	msgUserRemove
	msgUserState
	msgBanList
	msgTextMessage
	msgPermissionDenied
	msgACL
	msgQueryUsers
	msgCryptSetup
	msgContextActionModify
	msgContextAction
	msgUserList
	msgVoiceTarget
	msgPermissionQuery
	msgCodecVersion
	msgUserStats
	msgRequestBlob
	msgServerConfig
	msgSuggestConfig
)

const (
	permWrite       = 0x1
	permTraverse    = 0x2
	permEnter       = 0x4
	permSpeak       = 0x8
	permMuteDeafen  = 0x10
	permMove        = 0x20
	permWhisper     = 0x100
	permTextMessage = 0x200
	permListen      = 0x800
	permKick        = 0x10000

	userPerms  = permTraverse | permEnter | permSpeak | permWhisper | permTextMessage | permListen
	adminPerms = userPerms | permWrite | permMuteDeafen | permMove | permKick

	maxMessage    = 8 << 20
	maxText       = 5000
	maxImageText  = 131072
	maxComment    = 5000
	maxBandwidth  = 558000
	serverVersion = 1<<16 | 4<<8
)

type Channel struct {
	ID          uint32
	Parent      uint32
	Name        string
	Description string
	Group       string
	Position    int
}

type Identity struct {
	Name   string
	Groups []string
	Admin  bool
}

type AuthFunc func(user, pass, remote string) (*Identity, error)

var ErrRejected = errors.New("rejected")

type UserInfo struct {
	Session  uint32    `json:"session"`
	Name     string    `json:"name"`
	Channel  string    `json:"channel"`
	Remote   string    `json:"remote"`
	Muted    bool      `json:"muted"`
	Deafened bool      `json:"deafened"`
	Since    time.Time `json:"since"`
}

type Server struct {
	Auth     AuthFunc
	Log      *slog.Logger
	Name     string
	Welcome  string
	MaxUsers int

	mu          sync.Mutex
	channels    map[uint32]*Channel
	nextChannel uint32
	users       map[uint32]*user
	nextSession uint32
	lns         []net.Listener
	closed      bool
	wg          sync.WaitGroup

	udp *net.UDPConn

	VoicePackets atomic.Int64
}

type target struct {
	sessions []uint32
	channels []uint32
	children bool
}

type user struct {
	s         *Server
	nc        net.Conn
	session   uint32
	name      string
	groups    []string
	admin     bool
	channel   uint32
	selfMute  bool
	selfDeaf  bool
	mute      bool
	deaf      bool
	comment   string
	listening map[uint32]bool
	targets   map[uint32]target
	out       chan []byte
	done      chan struct{}
	closeOnce sync.Once
	since     time.Time
	lastSeen  atomic.Int64
	crypt     *cryptState
	udpAddr   atomic.Pointer[net.UDPAddr]
	opus      bool
}

func NewServer(name string) *Server {
	s := &Server{Name: name, MaxUsers: 200, channels: map[uint32]*Channel{}, users: map[uint32]*user{}, nextChannel: 1, nextSession: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.channels[0] = &Channel{ID: 0, Name: name}
	return s
}

func (s *Server) SetChannels(list []Channel) {
	s.mu.Lock()
	byName := map[string]*Channel{}
	for _, c := range s.channels {
		if c.ID != 0 {
			byName[c.Name] = c
		}
	}
	keep := map[uint32]bool{0: true}
	var added []*Channel
	for _, c := range list {
		if old, ok := byName[c.Name]; ok {
			old.Description, old.Group, old.Position = c.Description, c.Group, c.Position
			keep[old.ID] = true
			continue
		}
		nc := c
		nc.ID = s.nextChannel
		s.nextChannel++
		s.channels[nc.ID] = &nc
		keep[nc.ID] = true
		added = append(added, &nc)
	}
	var removed []uint32
	for id := range s.channels {
		if !keep[id] {
			removed = append(removed, id)
			delete(s.channels, id)
		}
	}
	var moved []*user
	for _, u := range s.users {
		if !keep[u.channel] {
			u.channel = 0
			moved = append(moved, u)
		}
		for id := range u.listening {
			if !keep[id] {
				delete(u.listening, id)
			}
		}
	}
	users := s.userList()
	s.mu.Unlock()
	for _, c := range added {
		for _, u := range users {
			u.send(msgChannelState, s.channelState(c, u))
		}
	}
	for _, u := range moved {
		s.broadcast(msgUserState, pbBuf(nil).Uint(1, uint64(u.session)).Uint(5, 0))
	}
	for _, id := range removed {
		s.broadcast(msgChannelRemove, pbBuf(nil).Uint(1, uint64(id)))
	}
}

func (s *Server) userList() []*user {
	out := make([]*user, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

func (s *Server) Users() []UserInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []UserInfo
	for _, u := range s.users {
		ch := ""
		if c, ok := s.channels[u.channel]; ok {
			ch = c.Name
		}
		out = append(out, UserInfo{Session: u.session, Name: u.name, Channel: ch, Remote: u.nc.RemoteAddr().String(), Muted: u.mute || u.selfMute, Deafened: u.deaf || u.selfDeaf, Since: u.since})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) Kick(session uint32, reason string) bool {
	s.mu.Lock()
	u, ok := s.users[session]
	s.mu.Unlock()
	if ok {
		u.sendNow(msgUserRemove, pbBuf(nil).Uint(1, uint64(session)).Str(3, reason))
		u.close()
	}
	return ok
}

func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(nc)
		}()
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for _, l := range s.lns {
		l.Close()
	}
	users := s.userList()
	if s.udp != nil {
		s.udp.Close()
	}
	s.mu.Unlock()
	for _, u := range users {
		u.close()
	}
	s.wg.Wait()
}

func frame(typ uint16, payload []byte) []byte {
	out := make([]byte, 6, 6+len(payload))
	binary.BigEndian.PutUint16(out, typ)
	binary.BigEndian.PutUint32(out[2:], uint32(len(payload)))
	return append(out, payload...)
}

func (u *user) send(typ uint16, payload []byte) {
	select {
	case u.out <- frame(typ, payload):
	case <-u.done:
	default:
		if typ != msgUDPTunnel {
			u.close()
		}
	}
}

func (u *user) sendNow(typ uint16, payload []byte) {
	u.nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	u.nc.Write(frame(typ, payload))
}

func (u *user) close() {
	u.closeOnce.Do(func() {
		close(u.done)
		u.nc.Close()
	})
}

func (s *Server) broadcast(typ uint16, payload []byte) {
	s.mu.Lock()
	users := s.userList()
	s.mu.Unlock()
	for _, u := range users {
		u.send(typ, payload)
	}
}

func (s *Server) canEnter(u *user, c *Channel) bool {
	return c.Group == "" || u.admin || slices.Contains(u.groups, c.Group)
}

func (s *Server) perms(u *user, c *Channel) uint64 {
	if !s.canEnter(u, c) {
		return permTraverse
	}
	if u.admin {
		return adminPerms
	}
	return userPerms
}

func (s *Server) channelState(c *Channel, u *user) []byte {
	b := pbBuf(nil).Uint(1, uint64(c.ID))
	if c.ID != 0 {
		b = b.Uint(2, uint64(c.Parent))
	}
	b = b.Str(3, c.Name)
	if c.Description != "" {
		b = b.Str(5, c.Description)
	}
	b = b.Int(9, int64(c.Position))
	if c.Group != "" {
		b = b.Bool(12, true).Bool(13, s.canEnter(u, c))
	}
	return b
}

func (u *user) state(full bool) []byte {
	b := pbBuf(nil).Uint(1, uint64(u.session)).Str(3, u.name).Uint(5, uint64(u.channel))
	if full || u.selfMute {
		b = b.Bool(9, u.selfMute)
	}
	if full || u.selfDeaf {
		b = b.Bool(10, u.selfDeaf)
	}
	if u.mute {
		b = b.Bool(6, true)
	}
	if u.deaf {
		b = b.Bool(7, true)
	}
	if u.comment != "" {
		b = b.Str(14, u.comment)
	}
	for id := range u.listening {
		b = b.Uint(21, uint64(id))
	}
	return b
}

func (s *Server) serveConn(nc net.Conn) {
	defer nc.Close()
	if tc, ok := nc.(*tls.Conn); ok {
		tc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		tc.SetDeadline(time.Time{})
	}
	br := bufio.NewReaderSize(nc, 64<<10)
	u := &user{s: s, nc: nc, out: make(chan []byte, 1024), done: make(chan struct{}), listening: map[uint32]bool{}, targets: map[uint32]target{}, since: time.Now()}
	u.lastSeen.Store(time.Now().UnixNano())
	go u.writer()
	defer s.remove(u)
	u.send(msgVersion, pbBuf(nil).Uint(1, serverVersion).Uint(5, 1<<48|4<<32).Str(2, "GolangTAK").Str(3, "GolangTAK").Str(4, ""))
	authed := false
	for {
		nc.SetReadDeadline(time.Now().Add(45 * time.Second))
		var hdr [6]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		typ := binary.BigEndian.Uint16(hdr[:])
		n := binary.BigEndian.Uint32(hdr[2:])
		if n > maxMessage {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		u.lastSeen.Store(time.Now().UnixNano())
		if !authed {
			switch typ {
			case msgVersion, msgPing:
				if typ == msgPing {
					u.send(msgPing, pingReply(payload))
				}
				continue
			case msgAuthenticate:
				if !s.authenticate(u, payload) {
					return
				}
				authed = true
				continue
			default:
				return
			}
		}
		if err := s.handle(u, typ, payload); err != nil {
			return
		}
	}
}

func (u *user) writer() {
	bw := bufio.NewWriterSize(u.nc, 64<<10)
	for {
		select {
		case <-u.done:
			return
		case b := <-u.out:
			u.nc.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err := bw.Write(b); err != nil {
				u.close()
				return
			}
			if len(u.out) == 0 {
				if err := bw.Flush(); err != nil {
					u.close()
					return
				}
			}
		}
	}
}

func pingReply(payload []byte) []byte {
	m, _ := pbParse(payload)
	return pbBuf(nil).Uint(1, m.uint(1))
}

func (s *Server) reject(u *user, kind int, reason string) {
	u.sendNow(msgReject, pbBuf(nil).Uint(1, uint64(kind)).Str(2, reason))
}

func validName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) authenticate(u *user, payload []byte) bool {
	m, err := pbParse(payload)
	if err != nil {
		return false
	}
	name := strings.TrimSpace(m.str(1))
	if !validName(name) {
		s.reject(u, 2, "invalid user name")
		return false
	}
	u.opus = m.bool(5)
	id, err := s.Auth(name, m.str(2), u.nc.RemoteAddr().String())
	if err != nil {
		s.reject(u, 3, "wrong user name or password; use your TAK server account")
		s.Log.Warn("voice sign-in failed", "user", name, "remote", u.nc.RemoteAddr().String())
		return false
	}
	u.name, u.groups, u.admin = id.Name, id.Groups, id.Admin
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	var old *user
	for _, o := range s.users {
		if strings.EqualFold(o.name, u.name) {
			old = o
		}
	}
	if old == nil && s.MaxUsers > 0 && len(s.users) >= s.MaxUsers {
		s.mu.Unlock()
		s.reject(u, 6, "the voice server is full")
		return false
	}
	u.session = s.nextSession
	s.nextSession++
	u.crypt = newCryptState()
	s.users[u.session] = u
	chans := make([]*Channel, 0, len(s.channels))
	for _, c := range s.channels {
		chans = append(chans, c)
	}
	others := s.userList()
	s.mu.Unlock()
	if old != nil {
		old.sendNow(msgUserRemove, pbBuf(nil).Uint(1, uint64(old.session)).Str(3, "signed in from another device"))
		old.close()
	}
	sort.Slice(chans, func(i, j int) bool { return chans[i].ID < chans[j].ID })
	u.send(msgCryptSetup, pbBuf(nil).Bytes(1, u.crypt.key[:]).Bytes(2, u.crypt.decryptIV[:]).Bytes(3, u.crypt.encryptIV[:]))
	u.send(msgCodecVersion, pbBuf(nil).Int(1, -2147483637).Int(2, 0).Bool(3, true).Bool(4, true))
	for _, c := range chans {
		u.send(msgChannelState, s.channelState(c, u))
	}
	for _, o := range others {
		if o != u {
			u.send(msgUserState, o.state(true))
		}
	}
	mine := u.state(true)
	for _, o := range others {
		o.send(msgUserState, mine)
	}
	welcome := s.Welcome
	if welcome == "" {
		welcome = "Welcome to " + s.Name + " voice."
	}
	root := s.channels[0]
	u.send(msgServerSync, pbBuf(nil).Uint(1, uint64(u.session)).Uint(2, maxBandwidth).Str(3, welcome).Uint(4, s.perms(u, root)))
	u.send(msgServerConfig, pbBuf(nil).Uint(1, maxBandwidth).Str(2, welcome).Bool(3, true).Uint(4, maxText).Uint(5, maxImageText).Uint(6, uint64(s.MaxUsers)).Bool(7, false))
	s.Log.Info("voice user connected", "user", u.name, "remote", u.nc.RemoteAddr().String())
	return true
}

func (s *Server) remove(u *user) {
	u.close()
	s.mu.Lock()
	cur, ok := s.users[u.session]
	if ok && cur == u {
		delete(s.users, u.session)
	}
	s.mu.Unlock()
	if ok && cur == u {
		s.broadcast(msgUserRemove, pbBuf(nil).Uint(1, uint64(u.session)))
		s.Log.Info("voice user disconnected", "user", u.name)
	}
}

func (s *Server) handle(u *user, typ uint16, payload []byte) error {
	switch typ {
	case msgPing:
		m, _ := pbParse(payload)
		b := pbBuf(nil).Uint(1, m.uint(1))
		if u.crypt != nil {
			b = b.Uint(2, uint64(u.crypt.good.Load())).Uint(3, uint64(u.crypt.late.Load())).Uint(4, uint64(u.crypt.lost.Load())).Uint(5, 0)
		}
		u.send(msgPing, b)
	case msgUDPTunnel:
		s.voice(u, payload, false)
	case msgUserState:
		return s.userState(u, payload)
	case msgTextMessage:
		s.textMessage(u, payload)
	case msgVoiceTarget:
		m, err := pbParse(payload)
		if err != nil {
			return nil
		}
		id := uint32(m.uint(1))
		if id < 1 || id > 30 {
			return nil
		}
		var t target
		for _, raw := range m.all(2) {
			tm, err := pbParse(raw)
			if err != nil {
				continue
			}
			for _, sid := range tm.uints(1) {
				t.sessions = append(t.sessions, uint32(sid))
			}
			if tm.has(2) {
				t.channels = append(t.channels, uint32(tm.uint(2)))
				t.children = t.children || tm.bool(5)
			}
		}
		s.mu.Lock()
		if len(t.sessions)+len(t.channels) == 0 {
			delete(u.targets, id)
		} else if len(u.targets) < 30 {
			u.targets[id] = t
		}
		s.mu.Unlock()
	case msgPermissionQuery:
		m, _ := pbParse(payload)
		id := uint32(m.uint(1))
		s.mu.Lock()
		c, ok := s.channels[id]
		s.mu.Unlock()
		if ok {
			u.send(msgPermissionQuery, pbBuf(nil).Uint(1, uint64(id)).Uint(2, s.perms(u, c)))
		}
	case msgCryptSetup:
		m, _ := pbParse(payload)
		if civ := m.bytes(2); len(civ) == 16 {
			u.crypt.mu.Lock()
			copy(u.crypt.decryptIV[:], civ)
			u.crypt.mu.Unlock()
		} else {
			u.send(msgCryptSetup, pbBuf(nil).Bytes(3, u.crypt.encryptIV[:]))
		}
	case msgUserStats:
		m, _ := pbParse(payload)
		sid := uint32(m.uint(1))
		s.mu.Lock()
		o, ok := s.users[sid]
		s.mu.Unlock()
		if ok {
			b := pbBuf(nil).Uint(1, uint64(sid)).Uint(16, uint64(time.Since(o.since)/time.Second)).Uint(17, uint64(time.Since(time.Unix(0, o.lastSeen.Load()))/time.Second)).Bool(19, o.opus)
			u.send(msgUserStats, b)
		}
	case msgRequestBlob:
		m, _ := pbParse(payload)
		for _, sid := range m.uints(2) {
			s.mu.Lock()
			o, ok := s.users[uint32(sid)]
			var comment string
			if ok {
				comment = o.comment
			}
			s.mu.Unlock()
			if ok {
				u.send(msgUserState, pbBuf(nil).Uint(1, sid).Str(14, comment))
			}
		}
		for _, cid := range m.uints(3) {
			s.mu.Lock()
			c, ok := s.channels[uint32(cid)]
			s.mu.Unlock()
			if ok {
				u.send(msgChannelState, pbBuf(nil).Uint(1, cid).Str(5, c.Description))
			}
		}
	case msgACL, msgBanList, msgQueryUsers, msgUserList, msgChannelState, msgChannelRemove, msgContextAction, msgUserRemove:
		if typ == msgUserRemove && u.admin {
			m, _ := pbParse(payload)
			s.Kick(uint32(m.uint(1)), firstNonEmpty(m.str(3), "removed by "+u.name))
			return nil
		}
		u.send(msgPermissionDenied, pbBuf(nil).Uint(5, 1).Uint(1, permWrite).Uint(3, uint64(u.session)).Str(4, "managed by the TAK server"))
	}
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (s *Server) userState(u *user, payload []byte) error {
	m, err := pbParse(payload)
	if err != nil {
		return nil
	}
	sid := u.session
	if m.has(1) {
		sid = uint32(m.uint(1))
	}
	s.mu.Lock()
	t, ok := s.users[sid]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	self := t == u
	if !self && !u.admin {
		s.mu.Unlock()
		u.send(msgPermissionDenied, pbBuf(nil).Uint(5, 1).Uint(1, permMove).Uint(3, uint64(sid)))
		return nil
	}
	out := pbBuf(nil).Uint(1, uint64(sid)).Uint(2, uint64(u.session))
	changed := false
	if m.has(5) {
		cid := uint32(m.uint(5))
		c, ok := s.channels[cid]
		if !ok || !s.canEnter(t, c) {
			s.mu.Unlock()
			u.send(msgPermissionDenied, pbBuf(nil).Uint(5, 1).Uint(1, permEnter).Uint(2, uint64(cid)).Uint(3, uint64(sid)))
			return nil
		}
		t.channel = cid
		out = out.Uint(5, uint64(cid))
		changed = true
	}
	if self && m.has(9) {
		t.selfMute = m.bool(9)
		if !t.selfMute {
			t.selfDeaf = false
		}
		out = out.Bool(9, t.selfMute)
		changed = true
	}
	if self && m.has(10) {
		t.selfDeaf = m.bool(10)
		if t.selfDeaf {
			t.selfMute = true
			out = out.Bool(9, true)
		}
		out = out.Bool(10, t.selfDeaf)
		changed = true
	}
	if u.admin && !self && m.has(6) {
		t.mute = m.bool(6)
		out = out.Bool(6, t.mute)
		changed = true
	}
	if u.admin && !self && m.has(7) {
		t.deaf = m.bool(7)
		out = out.Bool(7, t.deaf)
		changed = true
	}
	if self && m.has(14) {
		c := m.str(14)
		if len(c) > maxComment {
			c = c[:maxComment]
		}
		t.comment = c
		out = out.Str(14, c)
		changed = true
	}
	if self {
		for _, id := range m.uints(21) {
			if c, ok := s.channels[uint32(id)]; ok && s.canEnter(t, c) && len(t.listening) < 32 {
				t.listening[uint32(id)] = true
				out = out.Uint(21, id)
				changed = true
			}
		}
		for _, id := range m.uints(22) {
			delete(t.listening, uint32(id))
			out = out.Uint(22, id)
			changed = true
		}
	}
	s.mu.Unlock()
	if changed {
		s.broadcast(msgUserState, out)
	}
	return nil
}

func (s *Server) channelTree(id uint32, out map[uint32]bool) {
	out[id] = true
	for _, c := range s.channels {
		if c.ID != 0 && c.Parent == id && !out[c.ID] {
			s.channelTree(c.ID, out)
		}
	}
}

func (s *Server) textMessage(u *user, payload []byte) {
	m, err := pbParse(payload)
	if err != nil {
		return
	}
	text := m.str(5)
	if text == "" {
		return
	}
	if len(text) > maxImageText || (len(text) > maxText && !strings.Contains(text, "<img")) {
		u.send(msgPermissionDenied, pbBuf(nil).Uint(5, 4))
		return
	}
	s.mu.Lock()
	recipients := map[*user]bool{}
	for _, sid := range m.uints(2) {
		if o, ok := s.users[uint32(sid)]; ok {
			recipients[o] = true
		}
	}
	chans := map[uint32]bool{}
	for _, cid := range m.uints(3) {
		chans[uint32(cid)] = true
	}
	for _, cid := range m.uints(4) {
		s.channelTree(uint32(cid), chans)
	}
	for cid := range chans {
		c, ok := s.channels[cid]
		if !ok || !s.canEnter(u, c) {
			continue
		}
		for _, o := range s.users {
			if o.channel == cid {
				recipients[o] = true
			}
		}
	}
	delete(recipients, u)
	s.mu.Unlock()
	msg := pbBuf(nil).Uint(1, uint64(u.session))
	for _, sid := range m.uints(2) {
		msg = msg.Uint(2, sid)
	}
	for _, cid := range m.uints(3) {
		msg = msg.Uint(3, cid)
	}
	for _, cid := range m.uints(4) {
		msg = msg.Uint(4, cid)
	}
	msg = msg.Str(5, text)
	for o := range recipients {
		o.send(msgTextMessage, msg)
	}
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 0x80:
		return append(b, byte(v))
	case v < 0x4000:
		return append(b, byte(v>>8)|0x80, byte(v))
	case v < 0x200000:
		return append(b, byte(v>>16)|0xc0, byte(v>>8), byte(v))
	case v < 0x10000000:
		return append(b, byte(v>>24)|0xe0, byte(v>>16), byte(v>>8), byte(v))
	case v < 0x100000000:
		return append(b, 0xf0, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, 0xf4, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (s *Server) voice(u *user, data []byte, viaUDP bool) {
	if len(data) < 2 {
		return
	}
	kind := data[0] >> 5
	tgt := data[0] & 0x1f
	if kind == 1 {
		u.sendVoice(data, viaUDP)
		return
	}
	s.mu.Lock()
	if u.mute || u.selfMute {
		s.mu.Unlock()
		return
	}
	type dest struct {
		u    *user
		flag byte
	}
	var dests []dest
	seen := map[*user]bool{u: true}
	add := func(o *user, flag byte) {
		if seen[o] || o.deaf || o.selfDeaf {
			return
		}
		seen[o] = true
		dests = append(dests, dest{o, flag})
	}
	switch {
	case tgt == 31:
		dests = append(dests, dest{u, 0})
	case tgt == 0:
		if c, ok := s.channels[u.channel]; ok && s.canEnter(u, c) {
			for _, o := range s.users {
				if o.channel == u.channel || o.listening[u.channel] {
					add(o, 0)
				}
			}
		}
	default:
		t, ok := u.targets[uint32(tgt)]
		if !ok {
			break
		}
		for _, sid := range t.sessions {
			if o, ok := s.users[sid]; ok {
				add(o, 2)
			}
		}
		chans := map[uint32]bool{}
		for _, cid := range t.channels {
			if c, ok := s.channels[cid]; ok && s.canEnter(u, c) {
				if t.children {
					s.channelTree(cid, chans)
				} else {
					chans[cid] = true
				}
			}
		}
		for _, o := range s.users {
			if chans[o.channel] {
				add(o, 1)
			}
		}
	}
	s.mu.Unlock()
	if len(dests) == 0 {
		return
	}
	s.VoicePackets.Add(1)
	for _, d := range dests {
		pkt := make([]byte, 0, len(data)+6)
		pkt = append(pkt, kind<<5|d.flag)
		pkt = appendVarint(pkt, uint64(u.session))
		pkt = append(pkt, data[1:]...)
		d.u.sendVoice(pkt, false)
	}
}

func (u *user) sendVoice(pkt []byte, preferUDP bool) {
	if addr := u.udpAddr.Load(); addr != nil && u.s.udp != nil {
		u.s.udp.WriteToUDP(u.crypt.encrypt(pkt), addr)
		return
	}
	u.send(msgUDPTunnel, pkt)
}

func randomBytes(b []byte) { rand.Read(b) }
