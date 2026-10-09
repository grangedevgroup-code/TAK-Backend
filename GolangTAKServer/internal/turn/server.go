package turn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultLifetime    = 10 * time.Minute
	maxLifetime        = time.Hour
	permissionLifetime = 5 * time.Minute
	channelLifetime    = 10 * time.Minute
	nonceLifetime      = time.Hour
)

type Config struct {
	Realm      string
	Secret     []byte
	RelayIP    net.IP
	PortMin    int
	PortMax    int
	MaxPerUser int
	Log        *slog.Logger
	AllowPeer  func(net.IP) bool
}

func Credentials(secret []byte, user string, ttl time.Duration) (string, string) {
	name := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10) + ":" + user
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(name))
	return name, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

type allocation struct {
	key      string
	user     string
	client   *net.UDPAddr
	relay    *net.UDPConn
	expires  time.Time
	mu       sync.Mutex
	perms    map[string]time.Time
	channels map[uint16]*net.UDPAddr
	byPeer   map[string]uint16
	chExpire map[uint16]time.Time
	authKey  []byte
}

type Server struct {
	cfg    Config
	conn   *net.UDPConn
	mu     sync.Mutex
	allocs map[string]*allocation
	nonceK []byte
	done   chan struct{}
	wg     sync.WaitGroup
}

func Listen(addr string, cfg Config) (*Server, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	if cfg.Realm == "" {
		cfg.Realm = "golangtakserver"
	}
	if cfg.PortMin <= 0 || cfg.PortMax < cfg.PortMin {
		cfg.PortMin, cfg.PortMax = 49160, 49200
	}
	if cfg.MaxPerUser <= 0 {
		cfg.MaxPerUser = 10
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	k := make([]byte, 32)
	rand.Read(k)
	s := &Server{cfg: cfg, conn: conn, allocs: map[string]*allocation{}, nonceK: k, done: make(chan struct{})}
	s.wg.Add(2)
	go s.serve()
	go s.janitor()
	return s, nil
}

func (s *Server) Addr() *net.UDPAddr { return s.conn.LocalAddr().(*net.UDPAddr) }

func (s *Server) Close() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	s.conn.Close()
	s.mu.Lock()
	for _, a := range s.allocs {
		a.relay.Close()
	}
	s.allocs = map[string]*allocation{}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) Allocations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.allocs)
}

func (s *Server) janitor() {
	defer s.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			for k, a := range s.allocs {
				if now.After(a.expires) {
					a.relay.Close()
					delete(s.allocs, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) serve() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		b := buf[:n]
		if n >= 4 && b[0]&0xc0 == 0x40 {
			s.channelData(from, b)
			continue
		}
		m, err := parse(b)
		if err != nil {
			continue
		}
		s.handle(from, m)
	}
}

func (s *Server) send(to *net.UDPAddr, b []byte) { s.conn.WriteToUDP(b, to) }

func (s *Server) nonce() string {
	ts := strconv.FormatInt(time.Now().Unix(), 16)
	h := sha256.Sum256(append(append([]byte(nil), s.nonceK...), ts...))
	return ts + hex.EncodeToString(h[:8])
}

func (s *Server) nonceOK(n string) bool {
	if len(n) < 17 {
		return false
	}
	ts := n[:len(n)-16]
	h := sha256.Sum256(append(append([]byte(nil), s.nonceK...), ts...))
	if hex.EncodeToString(h[:8]) != n[len(n)-16:] {
		return false
	}
	t, err := strconv.ParseInt(ts, 16, 64)
	return err == nil && time.Since(time.Unix(t, 0)) < nonceLifetime
}

func (s *Server) password(user string) (string, error) {
	exp, _, ok := strings.Cut(user, ":")
	if !ok {
		return "", errors.New("bad user name")
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > t {
		return "", errors.New("expired credentials")
	}
	mac := hmac.New(sha1.New, s.cfg.Secret)
	mac.Write([]byte(user))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) reply(to *net.UDPAddr, m *message, class uint16, key []byte, attrs ...attr) {
	b := newBuilder(m.method, class, m.txid)
	for _, a := range attrs {
		b.add(a.typ, a.value)
	}
	b.add(attrSoftware, []byte("GolangTAKServer"))
	if key != nil {
		b.integrity(key)
	}
	s.send(to, b.fingerprint())
}

func (s *Server) fail(to *net.UDPAddr, m *message, code int, reason string, key []byte) {
	attrs := []attr{{attrErrorCode, errorCode(code, reason)}}
	if code == 401 || code == 438 {
		attrs = append(attrs, attr{attrRealm, []byte(s.cfg.Realm)}, attr{attrNonce, []byte(s.nonce())})
	}
	s.reply(to, m, classError, key, attrs...)
}

func (s *Server) authenticate(from *net.UDPAddr, m *message) ([]byte, string, bool) {
	user, okU := m.get(attrUsername)
	nonce, okN := m.get(attrNonce)
	_, okI := m.get(attrMessageIntegrity)
	if !okU || !okN || !okI {
		s.fail(from, m, 401, "Unauthorized", nil)
		return nil, "", false
	}
	if !s.nonceOK(string(nonce)) {
		s.fail(from, m, 438, "Stale Nonce", nil)
		return nil, "", false
	}
	pass, err := s.password(string(user))
	if err != nil {
		s.fail(from, m, 401, "Unauthorized", nil)
		return nil, "", false
	}
	key := longTermKey(string(user), s.cfg.Realm, pass)
	if !m.checkIntegrity(key) {
		s.fail(from, m, 401, "Unauthorized", nil)
		return nil, "", false
	}
	_, name, _ := strings.Cut(string(user), ":")
	return key, name, true
}

func allocKey(a *net.UDPAddr) string { return a.String() }

func (s *Server) handle(from *net.UDPAddr, m *message) {
	if m.class == classIndication {
		if m.method == methodSend {
			s.sendIndication(from, m)
		}
		return
	}
	if m.class != classRequest {
		return
	}
	if m.method == methodBinding {
		s.reply(from, m, classSuccess, nil, attr{attrXorMappedAddress, xorAddr(from, m.txid)})
		return
	}
	key, user, ok := s.authenticate(from, m)
	if !ok {
		return
	}
	switch m.method {
	case methodAllocate:
		s.allocate(from, m, key, user)
	case methodRefresh:
		s.refresh(from, m, key)
	case methodCreatePermission:
		s.createPermission(from, m, key)
	case methodChannelBind:
		s.channelBind(from, m, key)
	default:
		s.fail(from, m, 400, "Bad Request", key)
	}
}

func lifetimeOf(m *message) time.Duration {
	if v, ok := m.get(attrLifetime); ok && len(v) == 4 {
		d := time.Duration(binary.BigEndian.Uint32(v)) * time.Second
		if d > maxLifetime {
			d = maxLifetime
		}
		return d
	}
	return defaultLifetime
}

func lifetimeAttr(d time.Duration) attr {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(d/time.Second))
	return attr{attrLifetime, v}
}

func (s *Server) allocation(from *net.UDPAddr) *allocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocs[allocKey(from)]
}

func (s *Server) listenRelay() (*net.UDPConn, error) {
	span := s.cfg.PortMax - s.cfg.PortMin + 1
	var b [2]byte
	rand.Read(b[:])
	start := int(binary.BigEndian.Uint16(b[:])) % span
	for i := 0; i < span; i++ {
		port := s.cfg.PortMin + (start+i)%span
		c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no free relay port between %d and %d", s.cfg.PortMin, s.cfg.PortMax)
}

func (s *Server) allocate(from *net.UDPAddr, m *message, key []byte, user string) {
	if a := s.allocation(from); a != nil {
		s.fail(from, m, 437, "Allocation Mismatch", key)
		return
	}
	tr, ok := m.get(attrRequestedTransport)
	if !ok || len(tr) < 1 || tr[0] != 17 {
		s.fail(from, m, 442, "Unsupported Transport Protocol", key)
		return
	}
	s.mu.Lock()
	count := 0
	for _, a := range s.allocs {
		if a.user == user {
			count++
		}
	}
	s.mu.Unlock()
	if count >= s.cfg.MaxPerUser {
		s.fail(from, m, 486, "Allocation Quota Reached", key)
		return
	}
	relay, err := s.listenRelay()
	if err != nil {
		s.fail(from, m, 508, "Insufficient Capacity", key)
		return
	}
	life := lifetimeOf(m)
	if life == 0 {
		life = defaultLifetime
	}
	a := &allocation{key: allocKey(from), user: user, client: from, relay: relay, expires: time.Now().Add(life),
		perms: map[string]time.Time{}, channels: map[uint16]*net.UDPAddr{}, byPeer: map[string]uint16{}, chExpire: map[uint16]time.Time{}, authKey: key}
	s.mu.Lock()
	s.allocs[a.key] = a
	s.mu.Unlock()
	s.wg.Add(1)
	go s.relayLoop(a)
	ip := s.cfg.RelayIP
	if ip == nil {
		ip = s.Addr().IP
	}
	relayed := &net.UDPAddr{IP: ip, Port: relay.LocalAddr().(*net.UDPAddr).Port}
	s.cfg.Log.Debug("turn allocation", "user", user, "client", from.String(), "relay", relayed.String())
	s.reply(from, m, classSuccess, key,
		attr{attrXorRelayedAddress, xorAddr(relayed, m.txid)},
		attr{attrXorMappedAddress, xorAddr(from, m.txid)},
		lifetimeAttr(life))
}

func (s *Server) refresh(from *net.UDPAddr, m *message, key []byte) {
	a := s.allocation(from)
	if a == nil {
		s.fail(from, m, 437, "Allocation Mismatch", key)
		return
	}
	life := lifetimeOf(m)
	if life == 0 {
		s.mu.Lock()
		delete(s.allocs, a.key)
		s.mu.Unlock()
		a.relay.Close()
	} else {
		a.mu.Lock()
		a.expires = time.Now().Add(life)
		a.mu.Unlock()
	}
	s.reply(from, m, classSuccess, key, lifetimeAttr(life))
}

func (s *Server) peerAllowed(ip net.IP) bool {
	if s.cfg.AllowPeer != nil {
		return s.cfg.AllowPeer(ip)
	}
	return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func (s *Server) createPermission(from *net.UDPAddr, m *message, key []byte) {
	a := s.allocation(from)
	if a == nil {
		s.fail(from, m, 437, "Allocation Mismatch", key)
		return
	}
	var peers []*net.UDPAddr
	for _, at := range m.attrs {
		if at.typ != attrXorPeerAddress {
			continue
		}
		p, err := parseXorAddr(at.value, m.txid)
		if err != nil {
			s.fail(from, m, 400, "Bad Request", key)
			return
		}
		if !s.peerAllowed(p.IP) {
			s.fail(from, m, 403, "Forbidden", key)
			return
		}
		peers = append(peers, p)
	}
	if len(peers) == 0 {
		s.fail(from, m, 400, "Bad Request", key)
		return
	}
	a.mu.Lock()
	for _, p := range peers {
		a.perms[p.IP.String()] = time.Now().Add(permissionLifetime)
	}
	a.mu.Unlock()
	s.reply(from, m, classSuccess, key)
}

func (s *Server) channelBind(from *net.UDPAddr, m *message, key []byte) {
	a := s.allocation(from)
	if a == nil {
		s.fail(from, m, 437, "Allocation Mismatch", key)
		return
	}
	cv, ok1 := m.get(attrChannelNumber)
	pv, ok2 := m.get(attrXorPeerAddress)
	if !ok1 || !ok2 || len(cv) < 2 {
		s.fail(from, m, 400, "Bad Request", key)
		return
	}
	ch := binary.BigEndian.Uint16(cv)
	peer, err := parseXorAddr(pv, m.txid)
	if err != nil || ch < 0x4000 || ch > 0x7FFF || !s.peerAllowed(peer.IP) {
		s.fail(from, m, 400, "Bad Request", key)
		return
	}
	a.mu.Lock()
	if old, ok := a.channels[ch]; ok && old.String() != peer.String() {
		a.mu.Unlock()
		s.fail(from, m, 400, "Bad Request", key)
		return
	}
	if old, ok := a.byPeer[peer.String()]; ok && old != ch {
		a.mu.Unlock()
		s.fail(from, m, 400, "Bad Request", key)
		return
	}
	a.channels[ch] = peer
	a.byPeer[peer.String()] = ch
	a.chExpire[ch] = time.Now().Add(channelLifetime)
	a.perms[peer.IP.String()] = time.Now().Add(permissionLifetime)
	a.mu.Unlock()
	s.reply(from, m, classSuccess, key)
}

func (a *allocation) permitted(ip net.IP) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.perms[ip.String()]
	return ok && time.Now().Before(exp)
}

func (s *Server) sendIndication(from *net.UDPAddr, m *message) {
	a := s.allocation(from)
	if a == nil {
		return
	}
	pv, ok1 := m.get(attrXorPeerAddress)
	data, ok2 := m.get(attrData)
	if !ok1 || !ok2 {
		return
	}
	peer, err := parseXorAddr(pv, m.txid)
	if err != nil || !a.permitted(peer.IP) {
		return
	}
	a.relay.WriteToUDP(data, peer)
}

func (s *Server) channelData(from *net.UDPAddr, b []byte) {
	a := s.allocation(from)
	if a == nil {
		return
	}
	ch := binary.BigEndian.Uint16(b[0:2])
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if 4+n > len(b) {
		return
	}
	a.mu.Lock()
	peer := a.channels[ch]
	exp := a.chExpire[ch]
	a.mu.Unlock()
	if peer == nil || time.Now().After(exp) || !a.permitted(peer.IP) {
		return
	}
	a.relay.WriteToUDP(b[4:4+n], peer)
}

func (s *Server) relayLoop(a *allocation) {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, peer, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !a.permitted(peer.IP) {
			continue
		}
		a.mu.Lock()
		ch, bound := a.byPeer[peer.String()]
		if bound && time.Now().After(a.chExpire[ch]) {
			bound = false
		}
		a.mu.Unlock()
		if bound {
			out := make([]byte, 4+n, 4+n+3)
			binary.BigEndian.PutUint16(out[0:2], ch)
			binary.BigEndian.PutUint16(out[2:4], uint16(n))
			copy(out[4:], buf[:n])
			s.send(a.client, out)
			continue
		}
		var txid [12]byte
		rand.Read(txid[:])
		bd := newBuilder(methodData, classIndication, txid)
		bd.add(attrXorPeerAddress, xorAddr(peer, txid))
		bd.add(attrData, buf[:n])
		s.send(a.client, bd.fingerprint())
	}
}
