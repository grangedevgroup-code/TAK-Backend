package media

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrUnauthorized = errors.New("sign in required")
	ErrForbidden    = errors.New("forbidden")
)

type AuthFunc func(user, pass string, publish bool, path, remote string) (string, error)

type Server struct {
	Registry    *Registry
	Auth        AuthFunc
	Log         *slog.Logger
	IdleTimeout time.Duration
	MaxConns    int

	udpRTP  *net.UDPConn
	udpRTCP *net.UDPConn
	rtpPort int

	mu       sync.Mutex
	conns    map[*rtspConn]struct{}
	udpPubs  map[string]udpRoute
	closed   bool
	listener []net.Listener
	wg       sync.WaitGroup
	nconns   atomic.Int64
}

type udpRoute struct {
	sess  *session
	track int
	rtcp  bool
}

type sessTrack struct {
	tcp        bool
	channels   [2]int
	clientRTP  *net.UDPAddr
	clientRTCP *net.UDPAddr
}

type session struct {
	id      string
	conn    *rtspConn
	path    string
	publish bool
	desc    *Description
	tracks  map[int]*sessTrack
	stream  *Stream
	sub     *Subscriber
	user    string
	playing bool
}

type rtspConn struct {
	s        *Server
	nc       net.Conn
	br       *bufio.Reader
	wmu      sync.Mutex
	bw       *bufio.Writer
	user     string
	announce *Description
	annPath  string
	sessions map[string]*session
	channels map[int]udpRoute
}

func NewServer(reg *Registry, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{Registry: reg, Log: log, IdleTimeout: 2 * time.Minute, conns: map[*rtspConn]struct{}{}, udpPubs: map[string]udpRoute{}}
}

func (s *Server) ListenUDP(host string, rtpPort int) error {
	if rtpPort <= 0 {
		return nil
	}
	if rtpPort%2 != 0 {
		return fmt.Errorf("the RTP port must be even, not %d", rtpPort)
	}
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: rtpPort})
	if err != nil {
		return err
	}
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: rtpPort + 1})
	if err != nil {
		a.Close()
		return err
	}
	a.SetReadBuffer(4 << 20)
	s.udpRTP, s.udpRTCP, s.rtpPort = a, b, rtpPort
	s.wg.Add(2)
	go s.readUDP(a, false)
	go s.readUDP(b, true)
	return nil
}

func (s *Server) readUDP(c *net.UDPConn, rtcp bool) {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.mu.Lock()
		route, ok := s.udpPubs[from.String()]
		s.mu.Unlock()
		if !ok || route.sess.stream == nil {
			continue
		}
		route.sess.stream.Write(Packet{Track: route.track, RTCP: rtcp, Data: append([]byte(nil), buf[:n]...)})
	}
}

func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return net.ErrClosed
	}
	s.listener = append(s.listener, ln)
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
		if s.MaxConns > 0 && s.nconns.Load() >= int64(s.MaxConns) {
			nc.Close()
			continue
		}
		c := &rtspConn{s: s, nc: nc, br: bufio.NewReaderSize(nc, 64<<10), bw: bufio.NewWriterSize(nc, 64<<10), sessions: map[string]*session{}, channels: map[int]udpRoute{}}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.nconns.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			c.serve()
		}()
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	ls := s.listener
	conns := make([]*rtspConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, l := range ls {
		l.Close()
	}
	for _, c := range conns {
		c.nc.Close()
	}
	if s.udpRTP != nil {
		s.udpRTP.Close()
		s.udpRTCP.Close()
	}
	s.wg.Wait()
}

func (c *rtspConn) write(b []byte, flush bool) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.bw.Write(b); err != nil {
		return err
	}
	if flush {
		return c.bw.Flush()
	}
	return nil
}

func (c *rtspConn) respond(req *Request, status int, h map[string]string, body []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeResponse(c.bw, req.Get("cseq"), status, h, body); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *rtspConn) serve() {
	defer func() {
		for _, sess := range c.sessions {
			c.s.closeSession(sess)
		}
		c.nc.Close()
		c.s.mu.Lock()
		delete(c.s.conns, c)
		c.s.mu.Unlock()
		c.s.nconns.Add(-1)
	}()
	for {
		c.nc.SetReadDeadline(time.Now().Add(c.s.IdleTimeout))
		b, err := c.br.Peek(1)
		if err != nil {
			return
		}
		if b[0] == '$' {
			var hdr [4]byte
			if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
				return
			}
			n := int(hdr[2])<<8 | int(hdr[3])
			data := make([]byte, n)
			if _, err := io.ReadFull(c.br, data); err != nil {
				return
			}
			if route, ok := c.channels[int(hdr[1])]; ok && route.sess.stream != nil {
				route.sess.stream.Write(Packet{Track: route.track, RTCP: route.rtcp, Data: data})
			}
			continue
		}
		req, err := ReadRequest(c.br)
		if err != nil {
			return
		}
		if err := c.handle(req); err != nil {
			return
		}
	}
}

func (c *rtspConn) authorize(req *Request, publish bool, path string) (bool, error) {
	if c.s.Auth == nil {
		return true, nil
	}
	user, pass, _ := basicAuth(req.Get("authorization"))
	name, err := c.s.Auth(user, pass, publish, path, c.nc.RemoteAddr().String())
	if err == nil {
		if name != "" {
			c.user = name
		}
		return true, nil
	}
	if errors.Is(err, ErrUnauthorized) {
		return false, c.respond(req, 401, map[string]string{"WWW-Authenticate": `Basic realm="GolangTAKServer"`}, nil)
	}
	return false, c.respond(req, 403, nil, nil)
}

func (c *rtspConn) sessionFor(req *Request) *session {
	id, _, _ := strings.Cut(req.Get("session"), ";")
	return c.sessions[strings.TrimSpace(id)]
}

func (c *rtspConn) sessionHeader(sess *session) map[string]string {
	return map[string]string{"Session": sess.id + ";timeout=" + strconv.Itoa(int(c.s.IdleTimeout/time.Second/2))}
}

func (c *rtspConn) handle(req *Request) error {
	switch req.Method {
	case "OPTIONS":
		return c.respond(req, 200, map[string]string{"Public": "OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, GET_PARAMETER, SET_PARAMETER, TEARDOWN"}, nil)
	case "GET_PARAMETER", "SET_PARAMETER":
		h := map[string]string{}
		if sess := c.sessionFor(req); sess != nil {
			h = c.sessionHeader(sess)
		}
		return c.respond(req, 200, h, nil)
	case "DESCRIBE":
		return c.describe(req)
	case "ANNOUNCE":
		return c.announceReq(req)
	case "SETUP":
		return c.setup(req)
	case "PLAY":
		return c.play(req)
	case "RECORD":
		return c.record(req)
	case "PAUSE":
		sess := c.sessionFor(req)
		if sess == nil {
			return c.respond(req, 454, nil, nil)
		}
		if sess.sub != nil && sess.stream != nil {
			sess.stream.Unsubscribe(sess.sub)
			sess.sub = nil
			sess.playing = false
		}
		return c.respond(req, 200, c.sessionHeader(sess), nil)
	case "TEARDOWN":
		if sess := c.sessionFor(req); sess != nil {
			c.s.closeSession(sess)
			delete(c.sessions, sess.id)
		}
		return c.respond(req, 200, nil, nil)
	}
	return c.respond(req, 405, map[string]string{"Allow": "OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, GET_PARAMETER, SET_PARAMETER, TEARDOWN"}, nil)
}

func (c *rtspConn) describe(req *Request) error {
	p, err := urlPath(req.URL)
	if err != nil {
		return c.respond(req, 400, nil, nil)
	}
	p, _ = splitControl(p)
	if ok, err := c.authorize(req, false, p); !ok {
		return err
	}
	st, ok := c.s.Registry.Get(p)
	if !ok {
		return c.respond(req, 404, nil, nil)
	}
	base := strings.TrimRight(req.URL, "/") + "/"
	return c.respond(req, 200, map[string]string{"Content-Type": "application/sdp", "Content-Base": base}, st.Desc.Marshal(st.Name))
}

func (c *rtspConn) announceReq(req *Request) error {
	p, err := urlPath(req.URL)
	if err != nil {
		return c.respond(req, 400, nil, nil)
	}
	if p, err = CleanPath(p); err != nil {
		return c.respond(req, 400, nil, nil)
	}
	if ok, err := c.authorize(req, true, p); !ok {
		return err
	}
	desc, err := ParseSDP(req.Body)
	if err != nil {
		return c.respond(req, 400, nil, nil)
	}
	if _, busy := c.s.Registry.Get(p); busy {
		return c.respond(req, 453, nil, nil)
	}
	c.announce, c.annPath = desc, p
	return c.respond(req, 200, nil, nil)
}

func (c *rtspConn) trackFor(sess *session, control string, used map[int]*sessTrack, count int) int {
	if sess.publish {
		for i, t := range sess.desc.Tracks {
			if control != "" && (t.Control == control || strings.HasSuffix(t.Control, "/"+control)) {
				return i
			}
		}
	} else if strings.HasPrefix(control, "trackID=") {
		if n, err := strconv.Atoi(strings.TrimPrefix(control, "trackID=")); err == nil && n >= 0 && n < count {
			return n
		}
	}
	for i := 0; i < count; i++ {
		if _, ok := used[i]; !ok {
			return i
		}
	}
	return -1
}

func (c *rtspConn) setup(req *Request) error {
	full, err := urlPath(req.URL)
	if err != nil {
		return c.respond(req, 400, nil, nil)
	}
	tr, err := parseTransport(req.Get("transport"))
	if err != nil {
		return c.respond(req, 461, nil, nil)
	}
	if !tr.tcp && c.s.udpRTP == nil {
		return c.respond(req, 461, nil, nil)
	}
	sess := c.sessionFor(req)
	if sess == nil {
		if req.Get("session") != "" {
			return c.respond(req, 454, nil, nil)
		}
		sess = &session{id: newID(8), conn: c, tracks: map[int]*sessTrack{}}
		if c.announce != nil && (strings.HasPrefix(full, c.annPath+"/") || full == c.annPath) {
			sess.publish, sess.desc, sess.path = true, c.announce, c.annPath
		} else {
			p, _ := splitControl(full)
			if ok, err := c.authorize(req, false, p); !ok {
				return err
			}
			st, ok := c.s.Registry.Get(p)
			if !ok {
				return c.respond(req, 404, nil, nil)
			}
			sess.path, sess.desc, sess.stream = st.Name, st.Desc, st
		}
		sess.user = c.user
		c.sessions[sess.id] = sess
	}
	if sess.playing || (sess.publish && sess.stream != nil) {
		return c.respond(req, 455, nil, nil)
	}
	control := strings.TrimPrefix(strings.TrimPrefix(full, sess.path), "/")
	idx := c.trackFor(sess, control, sess.tracks, len(sess.desc.Tracks))
	if idx < 0 {
		return c.respond(req, 404, nil, nil)
	}
	st := &sessTrack{tcp: tr.tcp}
	var reply string
	if tr.tcp {
		ch := tr.channels
		if ch[0] < 0 || ch[0] > 254 {
			ch = [2]int{idx * 2, idx*2 + 1}
		}
		st.channels = ch
		reply = fmt.Sprintf("RTP/AVP/TCP;unicast;interleaved=%d-%d", ch[0], ch[1])
	} else {
		if tr.clientPort[0] <= 0 {
			return c.respond(req, 461, nil, nil)
		}
		ip := net.ParseIP(hostOnly(c.nc.RemoteAddr()))
		st.clientRTP = &net.UDPAddr{IP: ip, Port: tr.clientPort[0]}
		st.clientRTCP = &net.UDPAddr{IP: ip, Port: tr.clientPort[1]}
		reply = fmt.Sprintf("RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d", tr.clientPort[0], tr.clientPort[1], c.s.rtpPort, c.s.rtpPort+1)
	}
	sess.tracks[idx] = st
	h := c.sessionHeader(sess)
	h["Transport"] = reply
	return c.respond(req, 200, h, nil)
}

func (c *rtspConn) record(req *Request) error {
	sess := c.sessionFor(req)
	if sess == nil || !sess.publish {
		return c.respond(req, 454, nil, nil)
	}
	if len(sess.tracks) == 0 {
		return c.respond(req, 455, nil, nil)
	}
	st, err := c.s.Registry.Publish(sess.path, sess.desc, firstNonEmpty(sess.user, "anonymous"), "rtsp "+c.nc.RemoteAddr().String())
	if err != nil {
		return c.respond(req, 453, nil, nil)
	}
	sess.stream = st
	for idx, t := range sess.tracks {
		if t.tcp {
			c.channels[t.channels[0]] = udpRoute{sess: sess, track: idx}
			c.channels[t.channels[1]] = udpRoute{sess: sess, track: idx, rtcp: true}
		} else {
			c.s.mu.Lock()
			c.s.udpPubs[t.clientRTP.String()] = udpRoute{sess: sess, track: idx}
			c.s.udpPubs[t.clientRTCP.String()] = udpRoute{sess: sess, track: idx, rtcp: true}
			c.s.mu.Unlock()
		}
	}
	c.s.Log.Info("video stream started", "path", st.Name, "user", st.Publisher, "remote", c.nc.RemoteAddr().String())
	return c.respond(req, 200, c.sessionHeader(sess), nil)
}

func (c *rtspConn) play(req *Request) error {
	sess := c.sessionFor(req)
	if sess == nil || sess.publish {
		return c.respond(req, 454, nil, nil)
	}
	if len(sess.tracks) == 0 {
		return c.respond(req, 455, nil, nil)
	}
	if sess.playing {
		return c.respond(req, 200, c.sessionHeader(sess), nil)
	}
	sub, err := sess.stream.Subscribe(1024)
	if err != nil {
		return c.respond(req, 404, nil, nil)
	}
	sess.sub, sess.playing = sub, true
	h := c.sessionHeader(sess)
	h["Range"] = "npt=0.000-"
	if err := c.respond(req, 200, h, nil); err != nil {
		return err
	}
	go c.forward(sess, sub)
	return nil
}

func (c *rtspConn) forward(sess *session, sub *Subscriber) {
	for {
		select {
		case <-sub.Done:
			if sess.stream != nil {
				select {
				case <-sess.stream.Done():
					c.nc.Close()
				default:
				}
			}
			return
		case p := <-sub.C:
			t, ok := sess.tracks[p.Track]
			if !ok {
				continue
			}
			if t.tcp {
				ch := t.channels[0]
				if p.RTCP {
					ch = t.channels[1]
				}
				if err := c.write(interleavedFrame(byte(ch), p.Data), len(sub.C) == 0); err != nil {
					c.nc.Close()
					return
				}
				continue
			}
			if p.RTCP {
				c.s.udpRTCP.WriteToUDP(p.Data, t.clientRTCP)
			} else {
				c.s.udpRTP.WriteToUDP(p.Data, t.clientRTP)
			}
		}
	}
}

func (s *Server) closeSession(sess *session) {
	if sess.publish {
		s.mu.Lock()
		for k, r := range s.udpPubs {
			if r.sess == sess {
				delete(s.udpPubs, k)
			}
		}
		s.mu.Unlock()
		if sess.stream != nil {
			s.Log.Info("video stream stopped", "path", sess.stream.Name)
			s.Registry.Unpublish(sess.stream)
		}
		return
	}
	if sess.sub != nil && sess.stream != nil {
		sess.stream.Unsubscribe(sess.sub)
	}
}
