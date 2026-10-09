package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/grpcx"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

const figService = "/com.atakmap.FederatedChannel/"

type fig2Session struct {
	key      string
	name     string
	remote   string
	c        *Client
	allowed  []string
	refs     int
	since    time.Time
	groups   []string
	evCancel context.CancelFunc
	rolOut   chan takproto.ROL
	done     chan struct{}
	node     string
}

type fig2Server struct {
	s        *Server
	mu       sync.Mutex
	sessions map[string]*fig2Session
}

func (s *Server) figIdentity() takproto.Identity {
	cfg := s.Config()
	return takproto.Identity{Name: cfg.Name, UID: cfg.NodeID, Type: takproto.ConnFederationTakServer, ServerID: cfg.NodeID}
}

func (s *Server) figVersion() *takproto.ServerVersion {
	return &takproto.ServerVersion{Major: 5, Minor: 4, Patch: 0, Branch: "golangtakserver", Variant: s.Version}
}

func (s *Server) startFederationV2() error {
	cfg := s.Config()
	if !cfg.Federation.Enabled || cfg.Ports.FederationV2 <= 0 {
		return nil
	}
	ln, err := s.listenTCP(cfg.Ports.FederationV2)
	if err != nil {
		return err
	}
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"h2"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.pki.ServerCert(), nil
		},
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		c.ClientCAs = s.federationTrust()
		return c, nil
	}
	fs := &fig2Server{s: s, sessions: map[string]*fig2Session{}}
	s.fig2 = fs
	hs := &http.Server{
		Handler:           http.HandlerFunc(fs.serve),
		ReadHeaderTimeout: 20 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
	}
	s.lmu.Lock()
	s.https = append(s.https, hs)
	s.lmu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		hs.Serve(tls.NewListener(ln, base))
	}()
	s.log.Info("federation v2 listening", "port", cfg.Ports.FederationV2)
	return nil
}

func (f *fig2Server) acquire(r *http.Request) (*fig2Session, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, grpcx.Errorf(grpcx.Unauthenticated, "a client certificate is required")
	}
	cert := r.TLS.PeerCertificates[0]
	sum := sha256.Sum256(cert.Raw)
	key := hex.EncodeToString(sum[:])
	name := cert.Subject.CommonName
	if cert.Issuer.CommonName != "" {
		name += " (" + cert.Issuer.CommonName + ")"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if ss, ok := f.sessions[key]; ok {
		ss.refs++
		return ss, nil
	}
	allowed := f.s.Config().Federation.Groups
	c := f.s.relayClient(KindFederation, name, r.RemoteAddr, allowed)
	f.s.hub.Add(c)
	ss := &fig2Session{key: key, name: name, remote: r.RemoteAddr, c: c, allowed: allowed, refs: 1, since: time.Now(), rolOut: make(chan takproto.ROL, 256), done: make(chan struct{})}
	f.sessions[key] = ss
	f.s.fed.add(&fedConn{c: c, name: name, dir: "inbound", since: ss.since, version: "v2"})
	f.s.log.Info("federate connected", "federate", name, "direction", "inbound", "version", "v2", "remote", r.RemoteAddr)
	return ss, nil
}

func (f *fig2Server) release(ss *fig2Session) {
	f.mu.Lock()
	ss.refs--
	last := ss.refs <= 0
	if last {
		delete(f.sessions, ss.key)
	}
	f.mu.Unlock()
	if last {
		close(ss.done)
		f.s.fed.remove(ss.c)
		f.s.hub.Remove(ss.c)
		f.s.log.Info("federate disconnected", "federate", ss.name, "version", "v2")
	}
}

func (f *fig2Server) sessionsList() []*fig2Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*fig2Session, 0, len(f.sessions))
	for _, ss := range f.sessions {
		out = append(out, ss)
	}
	return out
}

func (f *fig2Server) serve(w http.ResponseWriter, r *http.Request) {
	if !grpcx.IsGRPC(r) || r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, figService) {
		http.Error(w, "this port only accepts TAK federation v2 (gRPC) connections", http.StatusUnsupportedMediaType)
		return
	}
	st := grpcx.NewServerStream(w, r, f.s.Config().Limits.MaxMessageBytes)
	method := strings.TrimPrefix(r.URL.Path, figService)
	switch method {
	case "getIdentity":
		st.Recv()
		err := st.Send(takproto.MarshalIdentity(f.s.figIdentity()))
		st.Finish(err)
		return
	case "Getx509Identity":
		st.Recv()
		cert := f.s.pki.ServerCert()
		var der []byte
		if cert != nil && len(cert.Certificate) > 0 {
			der = cert.Certificate[0]
		}
		st.Finish(st.Send(takproto.MarshalBlob(takproto.Blob{Type: takproto.BlobOther, Data: der})))
		return
	case "GetAuthTokenByX509":
		st.Finish(grpcx.Errorf(grpcx.Unimplemented, "token federation is not used by this server; connect with a client certificate"))
		return
	}
	ss, err := f.acquire(r)
	if err != nil {
		st.Finish(err)
		return
	}
	defer f.release(ss)
	switch method {
	case "HealthCheck":
		st.Recv()
		st.Finish(st.Send(takproto.MarshalHealth(takproto.HealthServing)))
	case "SendOneEvent":
		msg, err := st.Recv()
		if err != nil {
			st.Finish(grpcx.Errorf(grpcx.InvalidArgument, "%v", err))
			return
		}
		f.inbound(ss, msg)
		st.Finish(st.Send(nil))
	case "ServerEventStream":
		for {
			msg, err := st.Recv()
			if err != nil {
				if err == io.EOF {
					st.Send(takproto.MarshalSubscription(takproto.Subscription{Identity: f.s.figIdentity(), ServerVersion: f.s.figVersion()}))
					st.Finish(nil)
				} else {
					st.Finish(grpcx.Errorf(grpcx.Canceled, "%v", err))
				}
				return
			}
			f.inbound(ss, msg)
		}
	case "ClientEventStream":
		f.noteNode(ss, st)
		st.Finish(f.streamEvents(st, ss))
	case "ServerFederateGroupsStream":
		st.Recv()
		if err := st.Send(takproto.MarshalFederateGroups(takproto.FederateGroups{Groups: ss.allowed})); err != nil {
			st.Finish(err)
			return
		}
		<-st.Context().Done()
		st.Finish(nil)
	case "ClientFederateGroupsStream":
		for {
			msg, err := st.Recv()
			if err != nil {
				if err == io.EOF {
					st.Send(takproto.MarshalSubscription(takproto.Subscription{Identity: f.s.figIdentity()}))
				}
				st.Finish(nil)
				return
			}
			if g, err := takproto.UnmarshalFederateGroups(msg); err == nil && len(g.Groups) > 0 {
				f.mu.Lock()
				ss.groups = g.Groups
				f.mu.Unlock()
			}
		}
	case "ClientROLStream":
		f.noteNode(ss, st)
		go f.s.rolSnapshot(st.Context(), f.target(ss))
		for {
			select {
			case <-st.Context().Done():
				st.Finish(nil)
				return
			case rol := <-ss.rolOut:
				if err := st.Send(takproto.MarshalROL(rol)); err != nil {
					st.Finish(err)
					return
				}
			}
		}
	case "ServerROLStream":
		for {
			msg, err := st.Recv()
			if err != nil {
				if err == io.EOF {
					st.Send(takproto.MarshalSubscription(takproto.Subscription{Identity: f.s.figIdentity()}))
				}
				st.Finish(nil)
				return
			}
			if rol, err := takproto.UnmarshalROL(msg); err == nil {
				f.s.handleROL(ss.c, rol, ss.allowed, f.nodeOf(ss))
			}
		}
	case "BinaryMessageStream":
		for {
			if _, err := st.Recv(); err != nil {
				if err == io.EOF {
					st.Send(nil)
				}
				st.Finish(nil)
				return
			}
		}
	case "SendOneBlob":
		st.Recv()
		st.Finish(st.Send(nil))
	default:
		st.Finish(grpcx.Errorf(grpcx.Unimplemented, "unknown method %s", method))
	}
}

func (f *fig2Server) noteNode(ss *fig2Session, st *grpcx.ServerStream) {
	msg, err := st.Recv()
	if err != nil {
		return
	}
	if sub, err := takproto.UnmarshalSubscription(msg); err == nil && sub.Identity.ServerID != "" {
		f.mu.Lock()
		ss.node = sub.Identity.ServerID
		f.mu.Unlock()
	}
}

func (f *fig2Server) nodeOf(ss *fig2Session) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ss.node
}

func (f *fig2Server) target(ss *fig2Session) rolTarget {
	return rolTarget{c: ss.c, allowed: ss.allowed, out: ss.rolOut, done: ss.done, node: f.nodeOf(ss)}
}

func (f *fig2Server) inbound(ss *fig2Session, msg []byte) {
	ev, err := takproto.UnmarshalFed(msg)
	if err != nil {
		f.s.log.Debug("bad federated message", "federate", ss.name, "err", err)
		return
	}
	ss.c.touch()
	f.s.federatedIn(ss.c, ev, ss.allowed)
}

func (f *fig2Server) streamEvents(st *grpcx.ServerStream, ss *fig2Session) error {
	ctx, cancel := context.WithCancel(st.Context())
	defer cancel()
	f.mu.Lock()
	if ss.evCancel != nil {
		ss.evCancel()
	}
	ss.evCancel = cancel
	f.mu.Unlock()
	send := func(ev takproto.FedEvent) error { return st.Send(takproto.MarshalFed(ev)) }
	if err := f.s.fedInitial(ss.c, ss.allowed, send); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ss.c.closed:
			return grpcx.Errorf(grpcx.Unavailable, "federate closed")
		case m := <-ss.c.out:
			ev, ok := f.s.fedOutEvent(m, ss.allowed)
			if !ok {
				continue
			}
			if err := send(ev); err != nil {
				return err
			}
			ss.c.Sent()
		}
	}
}

type fig2Link struct {
	c       *Client
	allowed []string
	inOnly  bool
	rolOut  chan takproto.ROL
	done    chan struct{}
	node    string
}

func (s *Server) connectFederationV2(ctx context.Context, l *peerLink, u *url.URL) error {
	host := u.Hostname()
	port := firstNonEmpty(u.Port(), "9001")
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: s.federationTrust(), NextProtos: []string{"h2"}}
	if l.cfg.CertFile != "" {
		cert, _, err := loadCertFile(l.cfg.CertFile, firstNonEmpty(l.cfg.CertPass, s.Config().Certificates.Password))
		if err != nil {
			return err
		}
		if cert != nil {
			tcfg.Certificates = []tls.Certificate{*cert}
		}
	} else {
		tcfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return s.pki.ServerCert(), nil }
	}
	if l.cfg.TrustFile != "" {
		pool, err := loadTrust(l.cfg.TrustFile, firstNonEmpty(l.cfg.CertPass, s.Config().Certificates.Password))
		if err != nil {
			return err
		}
		tcfg.RootCAs = pool
	}
	if l.cfg.Insecure {
		tcfg.InsecureSkipVerify = true
	}
	tr := &http.Transport{
		TLSClientConfig:     tcfg,
		ForceAttemptHTTP2:   true,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 20 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}
	base := "https://" + net.JoinHostPort(host, port)
	max := s.Config().Limits.MaxMessageBytes

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hctx, hcancel := context.WithTimeout(ctx, 20*time.Second)
	healthMsg, err := grpcx.Unary(hctx, hc, base, figService+"HealthCheck", nil, takproto.MarshalHealth(takproto.HealthServing), max)
	hcancel()
	if err != nil {
		return fmt.Errorf("federation v2 handshake failed: %w", err)
	}
	if st, _ := takproto.UnmarshalHealth(healthMsg); st != takproto.HealthServing {
		return fmt.Errorf("the federation server reports it is not serving (status %d)", st)
	}

	remoteNode := ""
	ictx, icancel := context.WithTimeout(ctx, 20*time.Second)
	if msg, err := grpcx.Unary(ictx, hc, base, figService+"getIdentity", nil, nil, max); err == nil {
		if id, err := takproto.UnmarshalIdentity(msg); err == nil {
			remoteNode = id.ServerID
		}
	}
	icancel()

	cfg := s.Config()
	allowed := cfg.Federation.Groups
	if len(l.cfg.Groups) > 0 {
		allowed = l.cfg.Groups
	}
	c := s.relayClient(KindFederation, l.cfg.Name, net.JoinHostPort(host, port), allowed)
	if strings.EqualFold(l.cfg.Direction, "in") {
		c.filter = func(*Message) bool { return false }
	}
	s.applyLinkArea(c, l.cfg.Area)
	s.hub.Add(c)
	link := &fig2Link{c: c, allowed: allowed, inOnly: strings.EqualFold(l.cfg.Direction, "in"), rolOut: make(chan takproto.ROL, 256), done: make(chan struct{}), node: remoteNode}
	s.fig2Out.Store(l, link)
	s.fed.add(&fedConn{c: c, name: l.cfg.Name, dir: "outbound", since: time.Now(), version: "v2"})
	l.mu.Lock()
	l.client = c
	l.mu.Unlock()
	defer func() {
		close(link.done)
		s.fig2Out.Delete(l)
		s.fed.remove(c)
		s.hub.Remove(c)
		l.mu.Lock()
		l.client = nil
		l.mu.Unlock()
	}()
	l.set("connected", "")
	s.log.Info("federation link connected", "federate", l.cfg.Name, "version", "v2", "remote", base)

	sub := takproto.MarshalSubscription(takproto.Subscription{Identity: takproto.Identity{Name: cfg.Name, UID: cfg.NodeID, Type: takproto.ConnFederationTakClient, ServerID: cfg.NodeID}, ServerVersion: s.figVersion()})
	errc := make(chan error, 8)
	fail := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}
	open := func(method string) (*grpcx.ClientStream, error) {
		return grpcx.Open(ctx, hc, base, figService+method, nil, max)
	}
	serverStream := func(method string, handle func([]byte)) error {
		cs, err := open(method)
		if err != nil {
			return err
		}
		if err := cs.Send(sub); err != nil {
			cs.Close()
			return err
		}
		cs.CloseSend()
		go func() {
			defer cs.Close()
			for {
				msg, err := cs.Recv()
				if err != nil {
					if err == io.EOF {
						err = fmt.Errorf("%s ended", method)
					}
					fail(err)
					return
				}
				handle(msg)
			}
		}()
		return nil
	}

	if err := serverStream("ServerFederateGroupsStream", func([]byte) {}); err != nil {
		return err
	}
	groupsOut, err := open("ClientFederateGroupsStream")
	if err != nil {
		return err
	}
	defer groupsOut.Close()
	if err := groupsOut.Send(takproto.MarshalFederateGroups(takproto.FederateGroups{Groups: allowed})); err != nil {
		return err
	}
	if err := serverStream("ClientEventStream", func(msg []byte) {
		ev, err := takproto.UnmarshalFed(msg)
		if err != nil {
			return
		}
		c.touch()
		s.federatedIn(c, ev, allowed)
	}); err != nil {
		return err
	}
	if err := serverStream("ClientROLStream", func(msg []byte) {
		if rol, err := takproto.UnmarshalROL(msg); err == nil {
			s.handleROL(c, rol, allowed, remoteNode)
		}
	}); err != nil {
		return err
	}
	events, err := open("ServerEventStream")
	if err != nil {
		return err
	}
	defer events.Close()
	rolStream, err := open("ServerROLStream")
	if err != nil {
		return err
	}
	defer rolStream.Close()

	if !link.inOnly {
		go s.rolSnapshot(ctx, rolTarget{c: c, allowed: allowed, out: link.rolOut, done: link.done, node: remoteNode})
	}
	go func() {
		send := func(ev takproto.FedEvent) error { return events.Send(takproto.MarshalFed(ev)) }
		if err := s.fedInitial(c, allowed, send); err != nil {
			fail(err)
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.closed:
				fail(errors.New("federation link closed"))
				return
			case m := <-c.out:
				ev, ok := s.fedOutEvent(m, allowed)
				if !ok {
					continue
				}
				if err := send(ev); err != nil {
					fail(err)
					return
				}
				c.Sent()
			case rol := <-link.rolOut:
				if err := rolStream.Send(takproto.MarshalROL(rol)); err != nil {
					fail(err)
					return
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				hctx, hcancel := context.WithTimeout(ctx, 20*time.Second)
				_, err := grpcx.Unary(hctx, hc, base, figService+"HealthCheck", nil, takproto.MarshalHealth(takproto.HealthServing), max)
				hcancel()
				if err != nil {
					fail(fmt.Errorf("health check failed: %w", err))
					return
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}
