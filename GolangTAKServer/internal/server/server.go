package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/flock"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/mumble"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

var ErrRunning = errors.New("GolangTAKServer is already running with this data directory")

type Options struct {
	Console io.Writer
	Version string
}

type Server struct {
	DataDir   string
	Version   string
	Started   time.Time
	cfgMu     sync.RWMutex
	cfg       Config
	level     *slog.LevelVar
	logs      *LogBuffer
	log       *slog.Logger
	dir       *Directory
	pki       *PKI
	hub       *Hub
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	lmu       sync.Mutex
	closers   []io.Closer
	https     []*http.Server
	stopOnce  sync.Once
	stoppers  []func()
	tokenKey  []byte
	devices   *Devices
	res       *Resources
	history   *History
	missions  *Missions
	videos    *Videos
	profiles  *Profiles
	chats     *Chats
	repeated  *Repeated
	linkMu    sync.Mutex
	links     map[string]*downloadLink
	apiMu     sync.Mutex
	apiSrc    *Client
	peers     *PeerManager
	fed       *Federation
	reports   *Reports
	feeds     *feedState
	mesh      *meshBridge
	telegram  *telegramBridge
	jobs      jobRegistry
	feedKick  map[string]chan struct{}
	perf      *perfSampler
	plugins   *pluginManager
	fig2      *fig2Server
	fig2Out   sync.Map
	dfeeds    *dataFeeds
	uasSeen   sync.Map
	upd       updateState
	props     *store.Collection[uidProps]
	seq       sequences
	calls     *callHub
	live      *liveVideo
	voice     *mumble.Server
	injectors *Injectors
	acct      *accountSecurity
	acme      *acmeState
	mapLayers *MapLayers
	fedFeeds  *store.Collection[dataFeedView]
	control   string
	lock      *flock.Lock
	localMux  http.Handler
	localMu   sync.Mutex
	restart   chan struct{}
	histStop  chan struct{}
}

func New(dataDir string, opts Options) (*Server, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create data directory %s: %w", dataDir, err)
	}
	lock, err := flock.Acquire(LockPath(dataDir))
	if errors.Is(err, flock.ErrLocked) {
		return nil, fmt.Errorf("%w (%s)", ErrRunning, dataDir)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot lock data directory %s: %w", dataDir, err)
	}
	s, err := newServer(dataDir, opts)
	if err != nil {
		lock.Release()
		return nil, err
	}
	s.lock = lock
	return s, nil
}

func LockPath(dataDir string) string { return filepath.Join(dataDir, "golangtakserver.lock") }

func newServer(dataDir string, opts Options) (*Server, error) {
	cfg, err := LoadConfig(dataDir)
	if err != nil {
		return nil, err
	}
	_, statErr := os.Stat(ConfigPath(dataDir))
	if cfg.Address == "" {
		cfg.Address = PrimaryIP()
	}
	if statErr != nil || cfg.Address == "" {
		if err := SaveConfig(dataDir, cfg); err != nil {
			return nil, err
		}
	}
	if raw, err := os.ReadFile(ConfigPath(dataDir)); err == nil && !strings.Contains(string(raw), cfg.NodeID) {
		SaveConfig(dataDir, cfg)
	}
	s := &Server{DataDir: dataDir, Version: opts.Version, cfg: cfg, level: new(slog.LevelVar), dfeeds: newDataFeeds()}
	if s.Version == "" {
		s.Version = "dev"
	}
	s.level.Set(ParseLevel(cfg.LogLevel))
	s.logs = NewLogBuffer(filepath.Join(dataDir, "logs", "golangtakserver.log"), opts.Console)
	s.log = NewLogger(s.logs, s.level)
	if s.dir, err = OpenDirectory(filepath.Join(dataDir, "db"), cfg.AnonymousGroup); err != nil {
		s.logs.Close()
		return nil, err
	}
	if s.pki, err = OpenPKI(dataDir, cfg); err != nil {
		s.dir.Close()
		s.logs.Close()
		return nil, err
	}
	s.hub = NewHub(s, s.log, cfg.Limits.QueueLength, cfg.Limits.MaxClients, cfg.Limits.CacheLimit)
	s.hub.SetRateLimits(cfg.RateLimits)
	s.hub.vbm.Store(&cfg.VBM)
	s.perf = &perfSampler{}
	s.dir.OnChange = s.refreshUser
	s.dir.External = s.ldapAuth
	if err := s.initSubsystems(); err != nil {
		s.closeSubsystems()
		s.dir.Close()
		s.logs.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) Config() Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Server) UpdateConfig(fn func(c *Config) error) (Config, error) {
	s.cfgMu.Lock()
	next := s.cfg
	next.Ports = s.cfg.Ports
	next.ExtraNames = append([]string(nil), s.cfg.ExtraNames...)
	next.Peers = append([]PeerConfig(nil), s.cfg.Peers...)
	next.Mesh.Groups = append([]string(nil), s.cfg.Mesh.Groups...)
	next.Federation.Groups = append([]string(nil), s.cfg.Federation.Groups...)
	next.Federation.TrustPEM = append([]string(nil), s.cfg.Federation.TrustPEM...)
	if err := fn(&next); err != nil {
		s.cfgMu.Unlock()
		return s.cfg, err
	}
	next.fill()
	if err := SaveConfig(s.DataDir, next); err != nil {
		s.cfgMu.Unlock()
		return s.cfg, err
	}
	s.cfg = next
	s.cfgMu.Unlock()
	s.hub.SetRateLimits(next.RateLimits)
	s.hub.vbm.Store(&next.VBM)
	s.level.Set(ParseLevel(next.LogLevel))
	return next, nil
}

func (s *Server) Log() *slog.Logger { return s.log }

func (s *Server) Logs() *LogBuffer { return s.logs }

func (s *Server) Directory() *Directory { return s.dir }

func (s *Server) PKI() *PKI { return s.pki }

func (s *Server) Hub() *Hub { return s.hub }

func (s *Server) UID() string { return "GolangTAKServer-" + s.Config().NodeID }

func (s *Server) refreshUser(name string) {
	for _, c := range s.hub.Clients() {
		id := c.Identity()
		if id == nil || id.Name != name || id.Anon {
			continue
		}
		next, err := s.dir.Identity(name, id.Via)
		if err != nil {
			c.Close()
			continue
		}
		next.Cert = id.Cert
		c.SetIdentity(next)
	}
}

func portError(network, addr string, err error) error {
	msg := strings.ToLower(err.Error())
	if errors.Is(err, errAddrInUse) || strings.Contains(msg, "in use") || strings.Contains(msg, "only one usage") {
		return fmt.Errorf("port %s/%s is already in use by another program; stop that program or change the port in config.json", strings.TrimPrefix(addr, ":"), network)
	}
	if strings.Contains(msg, "permission") || strings.Contains(msg, "access") {
		return fmt.Errorf("not allowed to listen on %s/%s: %w", addr, network, err)
	}
	return fmt.Errorf("cannot listen on %s/%s: %w", addr, network, err)
}

func (s *Server) addr(port int) string {
	return net.JoinHostPort(s.Config().Bind, strconv.Itoa(port))
}

func (s *Server) track(c io.Closer) {
	s.lmu.Lock()
	s.closers = append(s.closers, c)
	s.lmu.Unlock()
}

func (s *Server) listenTCP(port int) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	addr := s.addr(port)
	ln, err := lc.Listen(s.ctx, "tcp", addr)
	if err != nil {
		return nil, portError("tcp", addr, err)
	}
	s.track(ln)
	return ln, nil
}

func (s *Server) startStream(port int, kind string, tlsCfg *tls.Config) error {
	if port <= 0 {
		return nil
	}
	ln, err := s.listenTCP(port)
	if err != nil {
		return err
	}
	s.wg.Add(1)
	go s.acceptLoop(ln, kind, tlsCfg)
	return nil
}

func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.Started = time.Now()
	cfg := s.Config()
	type starter struct {
		name string
		fn   func() error
	}
	starters := []starter{
		{"tcp", func() error { return s.startStream(cfg.Ports.TCP, KindTCP, nil) }},
		{"tcp", func() error {
			if cfg.Ports.TCPAlt == cfg.Ports.TCP {
				return nil
			}
			return s.startStream(cfg.Ports.TCPAlt, KindTCP, nil)
		}},
		{"tls", func() error { return s.startStream(cfg.Ports.TLS, KindTLS, s.streamTLSConfig(false)) }},
	}
	for _, st := range starters {
		if err := st.fn(); err != nil {
			s.Stop()
			return err
		}
	}
	if err := s.startSubsystems(); err != nil {
		s.Stop()
		return err
	}
	s.writeControlToken()
	if _, err := s.pki.SelfTestCert(); err != nil {
		s.log.Warn("could not create the self-test certificate", "err", err)
	}
	s.wg.Add(2)
	go s.maintenance()
	go s.perfLoop()
	s.startPlugins()
	s.log.Info("GolangTAKServer started", "version", s.Version, "address", cfg.Address, "data", s.DataDir,
		"tcp", cfg.Ports.TCP, "tls", cfg.Ports.TLS, "http", cfg.Ports.HTTP, "https", cfg.Ports.HTTPS, "enroll", cfg.Ports.Enroll)
	return nil
}

func (s *Server) maintenance() {
	defer s.wg.Done()
	repeat := time.NewTicker(time.Duration(s.Config().Repeater.IntervalSec) * time.Second)
	minute := time.NewTicker(time.Minute)
	hourly := time.NewTicker(time.Hour)
	defer repeat.Stop()
	defer minute.Stop()
	defer hourly.Stop()
	lastIPs := strings.Join(LocalIPs(), ",")
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-repeat.C:
			s.runJob("emergencies")
		case <-minute.C:
			s.hub.Prune()
			s.runJob("sync")
			s.runJob("repeated")
			if ips := strings.Join(LocalIPs(), ","); ips != lastIPs {
				lastIPs = ips
				if err := s.pki.EnsureServer(s.Config()); err != nil {
					s.log.Error("server certificate renewal failed", "err", err)
				} else {
					s.log.Info("network addresses changed; server certificate updated")
				}
			}
		case <-hourly.C:
			s.runJobFn("certificate", false, func() error {
				err := s.pki.EnsureServer(s.Config())
				if err != nil {
					s.log.Error("server certificate renewal failed", "err", err)
				}
				return err
			})
			s.runJob("cleanup")
			s.runJob("updates")
		}
	}
}

func (s *Server) Publish(e *cot.Event) {
	m := NewMessage(e, nil, nil)
	m.Everyone = true
	s.hub.Publish(m)
}

func (s *Server) PublishTo(e *cot.Event, groups []string) {
	m := NewMessage(e, nil, s.dir.Mask(groups))
	s.hub.Publish(m)
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.lmu.Lock()
		for _, c := range s.closers {
			c.Close()
		}
		s.closers = nil
		hs := s.https
		s.https = nil
		s.lmu.Unlock()
		for _, h := range hs {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			h.Shutdown(ctx)
			cancel()
		}
		for _, c := range s.hub.Clients() {
			c.Close()
		}
		for _, fn := range s.stoppers {
			fn()
		}
		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			s.log.Warn("some background tasks did not stop in time")
		}
		s.closeSubsystems()
		s.removeControlToken()
		s.dir.Close()
		if s.cancel != nil {
			s.log.Info("GolangTAKServer stopped")
		}
		s.logs.Close()
		s.lock.Release()
	})
}
