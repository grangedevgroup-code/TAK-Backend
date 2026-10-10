package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

type PeerStatus struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Direction string    `json:"direction"`
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	Since     time.Time `json:"since"`
	Attempts  int       `json:"attempts"`
	Rx        uint64    `json:"rx"`
	Tx        uint64    `json:"tx"`
	Contacts  int       `json:"contacts"`
}

type peerLink struct {
	cfg      PeerConfig
	cancel   context.CancelFunc
	mu       sync.Mutex
	state    string
	err      string
	since    time.Time
	attempts int
	client   *Client
	done     chan struct{}
}

type PeerManager struct {
	s     *Server
	mu    sync.Mutex
	links map[string]*peerLink
}

func newPeerManager(s *Server) *PeerManager {
	return &PeerManager{s: s, links: map[string]*peerLink{}}
}

func peerKey(p PeerConfig) string {
	return p.Name + "\x00" + p.URL + "\x00" + p.Direction + "\x00" + strings.Join(p.Groups, ",") + "\x00" + p.Username + "\x00" + p.Password + "\x00" + p.CertFile + "\x00" + p.TrustFile + "\x00" + fmt.Sprint(p.Insecure) + "\x00" + p.Protocol
}

func (pm *PeerManager) Reload(cfgs []PeerConfig) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	want := map[string]PeerConfig{}
	for _, c := range cfgs {
		if c.Enabled && c.URL != "" {
			want[peerKey(c)] = c
		}
	}
	for k, l := range pm.links {
		if _, ok := want[k]; !ok {
			l.cancel()
			delete(pm.links, k)
		}
	}
	for k, c := range want {
		if _, ok := pm.links[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(pm.s.ctx)
		l := &peerLink{cfg: c, cancel: cancel, state: "starting", since: time.Now(), done: make(chan struct{})}
		pm.links[k] = l
		pm.s.wg.Add(1)
		go pm.run(ctx, l)
	}
}

func (pm *PeerManager) Stop() {
	pm.mu.Lock()
	for k, l := range pm.links {
		l.cancel()
		delete(pm.links, k)
	}
	pm.mu.Unlock()
}

func (pm *PeerManager) Status() []PeerStatus {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	out := []PeerStatus{}
	for _, l := range pm.links {
		l.mu.Lock()
		st := PeerStatus{Name: l.cfg.Name, URL: redactURL(l.cfg.URL), Direction: firstNonEmpty(l.cfg.Direction, "both"), State: l.state, Error: l.err, Since: l.since, Attempts: l.attempts}
		if c := l.client; c != nil {
			st.Rx, st.Tx = c.rx.Load(), c.tx.Load()
			c.mu.Lock()
			st.Contacts = len(c.remote)
			c.mu.Unlock()
		}
		l.mu.Unlock()
		out = append(out, st)
	}
	return out
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

func (l *peerLink) set(state, err string) {
	l.mu.Lock()
	if l.state != state || err != "" {
		l.since = time.Now()
	}
	l.state, l.err = state, err
	l.mu.Unlock()
}

func (pm *PeerManager) run(ctx context.Context, l *peerLink) {
	defer pm.s.wg.Done()
	defer close(l.done)
	backoff := time.Second
	for ctx.Err() == nil {
		l.mu.Lock()
		l.attempts++
		l.mu.Unlock()
		l.set("connecting", "")
		start := time.Now()
		err := pm.connect(ctx, l)
		if ctx.Err() != nil {
			return
		}
		msg := "connection closed"
		if err != nil {
			msg = err.Error()
		}
		l.set("waiting", msg)
		pm.s.log.Warn("peer link down", "peer", l.cfg.Name, "url", redactURL(l.cfg.URL), "err", msg)
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func loadCertFile(path, password string) (*tls.Certificate, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		certs, err := pki.ParseCertPEM(data)
		if err != nil {
			return nil, nil, err
		}
		key, err := pki.ParseKeyPEM(data, password)
		if err != nil {
			return nil, nil, errors.New("PEM file must contain the certificate and its private key")
		}
		c := &tls.Certificate{PrivateKey: key, Leaf: certs[0]}
		for _, x := range certs {
			c.Certificate = append(c.Certificate, x.Raw)
		}
		return c, certs[1:], nil
	}
	p, err := pki.DecodePKCS12(data, password)
	if err != nil {
		return nil, nil, err
	}
	if p.Key == nil || p.Cert == nil {
		return nil, p.Certs, nil
	}
	c := &tls.Certificate{PrivateKey: p.Key, Leaf: p.Cert, Certificate: [][]byte{p.Cert.Raw}}
	var chain []*x509.Certificate
	for _, x := range p.Certs {
		if x != p.Cert {
			c.Certificate = append(c.Certificate, x.Raw)
			chain = append(chain, x)
		}
	}
	return c, chain, nil
}

func loadTrust(path, password string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if bytes.Contains(data, []byte("-----BEGIN")) {
		certs, err := pki.ParseCertPEM(data)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			pool.AddCert(c)
		}
		return pool, nil
	}
	p, err := pki.DecodePKCS12(data, password)
	if err != nil {
		return nil, err
	}
	for _, c := range p.Certs {
		pool.AddCert(c)
	}
	return pool, nil
}

func (pm *PeerManager) tlsConfig(c PeerConfig, host string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if c.CertFile != "" {
		cert, chain, err := loadCertFile(c.CertFile, firstNonEmpty(c.CertPass, pm.s.Config().Certificates.Password))
		if err != nil {
			return nil, fmt.Errorf("client certificate %s: %w", c.CertFile, err)
		}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		if c.TrustFile == "" && len(chain) > 0 {
			pool := x509.NewCertPool()
			for _, x := range chain {
				pool.AddCert(x)
			}
			cfg.RootCAs = pool
		}
	}
	if c.TrustFile != "" {
		pool, err := loadTrust(c.TrustFile, firstNonEmpty(c.CertPass, pm.s.Config().Certificates.Password))
		if err != nil {
			return nil, fmt.Errorf("trust store %s: %w", c.TrustFile, err)
		}
		cfg.RootCAs = pool
	}
	if c.Insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

func (pm *PeerManager) newPeerClient(l *peerLink, remote string) *Client {
	s := pm.s
	c := s.relayClient(KindPeer, l.cfg.Name, remote, l.cfg.Groups)
	dir := strings.ToLower(firstNonEmpty(l.cfg.Direction, "both"))
	if dir == "in" {
		c.filter = func(*Message) bool { return false }
	}
	s.applyLinkArea(c, l.cfg.Area)
	return c
}

func (s *Server) peerPresence(name string) *cot.Event {
	cfg := s.Config()
	e := cot.New(s.UID(), "a-f-G-U-C", "h-g-i-g-o", 3*time.Minute)
	e.Point = cot.Point{Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("takv", "device", "server", "platform", "GolangTAKServer", "os", "GolangTAKServer", "version", s.Version)
	e.Detail.AddNew("contact", "callsign", cfg.Name, "endpoint", "*:-1:stcp")
	e.Detail.AddNew("__group", "name", "White", "role", "HQ")
	e.Detail.AddNew("uid", "Droid", cfg.Name)
	return e
}

func (s *Server) outbound(m *Message) []byte {
	e := m.Event.Clone()
	e.AddFlowTag(s.FlowKey(), time.Now())
	return e.XML()
}

func (pm *PeerManager) connect(ctx context.Context, l *peerLink) error {
	u, err := url.Parse(strings.TrimSpace(l.cfg.URL))
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "ws", "wss", "http", "https":
		return pm.connectWS(ctx, l, u)
	case "udp":
		return pm.connectUDP(ctx, l, u)
	case "fed", "federation":
		return pm.s.connectFederation(ctx, l, u)
	case "fed2", "fedv2", "federation2":
		return pm.s.connectFederationV2(ctx, l, u)
	case "tcp", "tls", "ssl", "stcp":
	default:
		return fmt.Errorf("unsupported peer URL scheme %q (use tcp, tls, ws, wss, udp, fed for federation v1 or fed2 for federation v2)", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if scheme == "tcp" || scheme == "stcp" {
			port = "8087"
		} else {
			port = "8089"
		}
	}
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	if scheme == "tls" || scheme == "ssl" {
		tcfg, err := pm.tlsConfig(l.cfg, host)
		if err != nil {
			return err
		}
		td := &tls.Dialer{NetDialer: d, Config: tcfg}
		conn, err = td.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return err
		}
	} else {
		conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return err
		}
	}
	defer conn.Close()
	c := pm.newPeerClient(l, conn.RemoteAddr().String())
	c.onClose = func() { conn.Close() }
	pm.s.hub.Add(c)
	l.mu.Lock()
	l.client = c
	l.mu.Unlock()
	defer func() {
		pm.s.hub.Remove(c)
		l.mu.Lock()
		l.client = nil
		l.mu.Unlock()
	}()
	l.set("connected", "")
	pm.s.log.Info("peer link connected", "peer", l.cfg.Name, "url", redactURL(l.cfg.URL))
	user, pass := l.cfg.Username, l.cfg.Password
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	bw := bufio.NewWriterSize(conn, 64<<10)
	var wmu sync.Mutex
	writeRaw := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := bw.Write(b); err != nil {
			return err
		}
		return bw.Flush()
	}
	if user != "" {
		auth := xmltree.New("auth")
		auth.AddNew("cot", "username", user, "password", pass, "uid", pm.s.UID())
		if err := writeRaw([]byte(auth.String())); err != nil {
			return err
		}
	}
	presence := !l.cfg.NoPresence
	if presence {
		if err := writeRaw(pm.s.peerPresence(l.cfg.Name).XML()); err != nil {
			return err
		}
	}
	errc := make(chan error, 2)
	go func() {
		ping := time.NewTicker(30 * time.Second)
		pres := time.NewTicker(60 * time.Second)
		defer ping.Stop()
		defer pres.Stop()
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case <-c.closed:
				errc <- errors.New("link closed")
				return
			case <-ping.C:
				if err := writeRaw(cot.Ping(pm.s.UID() + "-ping").XML()); err != nil {
					errc <- err
					return
				}
			case <-pres.C:
				if presence {
					if err := writeRaw(pm.s.peerPresence(l.cfg.Name).XML()); err != nil {
						errc <- err
						return
					}
				}
			case m := <-c.out:
				if m.ForceXML || m.SwitchProto {
					continue
				}
				if err := writeRaw(pm.s.outbound(m)); err != nil {
					errc <- err
					return
				}
				c.Sent()
			}
		}
	}()
	pm.s.hub.Replay(c, "sa", pm.s.Config().Limits.ReplayLimit)
	go func() {
		r := takproto.NewReader(conn, pm.s.Config().Limits.MaxMessageBytes)
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			f, err := r.Next()
			if err != nil {
				errc <- err
				return
			}
			pm.s.peerFrame(c, f)
		}
	}()
	err = <-errc
	c.Close()
	if err == io.EOF {
		return errors.New("remote closed the connection")
	}
	return err
}

func (s *Server) peerFrame(c *Client, f takproto.Frame) {
	var e *cot.Event
	var err error
	if f.Proto {
		e, err = takproto.UnmarshalEvent(f.Data)
	} else {
		var n *xmltree.Node
		n, err = xmltree.Parse(f.Data)
		if err == nil {
			if n.Name != "event" {
				return
			}
			e, err = cot.FromNode(n)
		}
	}
	if err != nil || e == nil {
		return
	}
	c.touch()
	if e.UID == s.UID() {
		return
	}
	s.ingestRelay(c, e, c.Remote)
}

func (pm *PeerManager) connectWS(ctx context.Context, l *peerLink, u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws" // nosemgrep -- u is parsed for this connection
	case "https":
		u.Scheme = "wss" // nosemgrep -- u is parsed for this connection
	}
	opts := &websocket.DialOptions{Header: http.Header{}}
	if u.Scheme == "wss" {
		tcfg, err := pm.tlsConfig(l.cfg, u.Hostname())
		if err != nil {
			return err
		}
		opts.TLS = tcfg
	}
	if l.cfg.Username != "" && u.User == nil {
		u.User = url.UserPassword(l.cfg.Username, l.cfg.Password) // nosemgrep -- u is parsed for this connection
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, _, err := websocket.Dial(dctx, u.String(), opts)
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.MaxMessage = int64(pm.s.Config().Limits.MaxMessageBytes)
	c := pm.newPeerClient(l, u.Host)
	c.onClose = func() { conn.CloseNow() }
	pm.s.hub.Add(c)
	l.mu.Lock()
	l.client = c
	l.mu.Unlock()
	defer func() {
		pm.s.hub.Remove(c)
		l.mu.Lock()
		l.client = nil
		l.mu.Unlock()
	}()
	l.set("connected", "")
	pm.s.log.Info("peer link connected", "peer", l.cfg.Name, "url", redactURL(l.cfg.URL))
	var wmu sync.Mutex
	write := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return conn.WriteBinary(b)
	}
	presence := !l.cfg.NoPresence
	if presence {
		if err := write(pm.s.peerPresence(l.cfg.Name).XML()); err != nil {
			return err
		}
	}
	errc := make(chan error, 2)
	go func() {
		ping := time.NewTicker(20 * time.Second)
		pres := time.NewTicker(60 * time.Second)
		defer ping.Stop()
		defer pres.Stop()
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case <-c.closed:
				errc <- errors.New("link closed")
				return
			case <-ping.C:
				wmu.Lock()
				err := conn.Ping(nil)
				wmu.Unlock()
				if err != nil {
					errc <- err
					return
				}
			case <-pres.C:
				if presence {
					if err := write(pm.s.peerPresence(l.cfg.Name).XML()); err != nil {
						errc <- err
						return
					}
				}
			case m := <-c.out:
				if m.ForceXML || m.SwitchProto {
					continue
				}
				if err := write(pm.s.outbound(m)); err != nil {
					errc <- err
					return
				}
				c.Sent()
			}
		}
	}()
	pm.s.hub.Replay(c, "sa", pm.s.Config().Limits.ReplayLimit)
	go func() {
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			_, data, err := conn.ReadMessage()
			if err != nil {
				errc <- err
				return
			}
			r := takproto.NewReader(bytes.NewReader(data), pm.s.Config().Limits.MaxMessageBytes)
			for {
				f, err := r.Next()
				if err != nil {
					break
				}
				pm.s.peerFrame(c, f)
			}
		}
	}()
	err = <-errc
	c.Close()
	return err
}

func (pm *PeerManager) connectUDP(ctx context.Context, l *peerLink, u *url.URL) error {
	addr, err := net.ResolveUDPAddr("udp", u.Host)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pm.newPeerClient(l, addr.String())
	pm.s.hub.Add(c)
	l.mu.Lock()
	l.client = c
	l.mu.Unlock()
	defer func() {
		pm.s.hub.Remove(c)
		l.mu.Lock()
		l.client = nil
		l.mu.Unlock()
	}()
	l.set("sending", "")
	proto := strings.EqualFold(l.cfg.Protocol, "protobuf")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m := <-c.out:
			if m.ForceXML || m.SwitchProto {
				continue
			}
			var b []byte
			if proto {
				b = takproto.MeshFrame(m.Proto())
			} else {
				b = pm.s.outbound(m)
			}
			if len(b) <= 65000 {
				conn.Write(b)
				c.Sent()
			}
		}
	}
}

func (s *Server) reloadPeers() {
	if s.peers != nil && s.ctx != nil {
		s.peers.Reload(s.Config().Peers)
	}
}

func (s *Server) peerStatus() []PeerStatus {
	if s.peers == nil {
		return []PeerStatus{}
	}
	return s.peers.Status()
}
