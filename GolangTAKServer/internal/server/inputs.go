package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type InputConfig struct {
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	Port         int      `json:"port"`
	Group        string   `json:"group,omitempty"`
	Iface        string   `json:"iface,omitempty"`
	Auth         string   `json:"auth,omitempty"`
	FilterGroups []string `json:"filterGroups,omitempty"`
	Area         string   `json:"area,omitempty"`
	NoArchive    bool     `json:"noArchive,omitempty"`
	ArchiveOnly  bool     `json:"archiveOnly,omitempty"`
	CoreVersion  int      `json:"coreVersion,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
}

func (in InputConfig) proto() string { return strings.ToLower(firstNonEmpty(in.Protocol, "tls")) }

func (in InputConfig) auth() string {
	a := strings.ToLower(in.Auth)
	if a == "" {
		if in.proto() == "tls" || in.proto() == "ssl" {
			return "x509"
		}
		return "anonymous"
	}
	return a
}

type inputStats struct {
	clients  atomic.Int64
	reads    atomic.Int64
	messages atomic.Int64
	bytes    atomic.Int64
}

type inputRun struct {
	cancel context.CancelFunc
	sig    string
	stats  *inputStats
}

func inputSig(in InputConfig) string {
	b, _ := json.Marshal(in)
	return string(b)
}

func validateInput(in InputConfig) error {
	if in.Name == "" {
		return errors.New("an input needs a name")
	}
	switch in.proto() {
	case "tcp", "stcp", "tls", "ssl", "udp", "mcast", "multicast":
	default:
		return fmt.Errorf("input %s: protocol %q is not supported; use tcp, stcp, tls, udp or mcast", in.Name, in.Protocol)
	}
	if in.Port <= 0 || in.Port > 65535 {
		return fmt.Errorf("input %s: port %d is out of range", in.Name, in.Port)
	}
	switch in.auth() {
	case "anonymous", "file", "ldap", "x509", "oauth":
	default:
		return fmt.Errorf("input %s: auth %q is not supported; use anonymous, file, ldap or x509", in.Name, in.Auth)
	}
	if _, err := parseArea(in.Area); err != nil {
		return fmt.Errorf("input %s: %w", in.Name, err)
	}
	return nil
}

func (s *Server) inputIdentity(in *InputConfig) *Identity {
	id := s.dir.Anonymous()
	if len(in.FilterGroups) > 0 {
		for _, g := range in.FilterGroups {
			s.dir.EnsureGroup(g, "Input "+in.Name, false)
		}
		m := s.dir.Mask(in.FilterGroups)
		if !m.Empty() {
			id = &Identity{Via: "input", In: m, Out: m, Anon: true}
		}
	}
	return id
}

func (s *Server) syncInputs() {
	if s.ctx == nil {
		return
	}
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if s.inputRuns == nil {
		s.inputRuns = map[string]*inputRun{}
	}
	want := map[string]InputConfig{}
	var order []string
	for _, in := range s.Config().Inputs {
		if !in.Disabled {
			want[in.Name] = in
			order = append(order, in.Name)
		}
	}
	stopped := false
	for name, run := range s.inputRuns {
		if in, ok := want[name]; !ok || inputSig(in) != run.sig {
			run.cancel()
			delete(s.inputRuns, name)
			stopped = true
		}
	}
	for _, name := range order {
		if _, ok := s.inputRuns[name]; ok {
			continue
		}
		in := want[name]
		ctx, cancel := context.WithCancel(s.ctx)
		run := &inputRun{cancel: cancel, sig: inputSig(in), stats: &inputStats{}}
		var err error
		for i := 0; i < 20; i++ {
			if err = s.startInput(ctx, &in, run.stats); err == nil || !stopped || !strings.Contains(err.Error(), "in use") {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			cancel()
			s.log.Error("input could not start", "input", in.Name, "err", err)
			continue
		}
		s.inputRuns[name] = run
		s.log.Info("input listening", "input", in.Name, "protocol", in.proto(), "port", in.Port, "auth", in.auth())
	}
}

func (s *Server) startInput(ctx context.Context, in *InputConfig, st *inputStats) error {
	switch in.proto() {
	case "tcp", "stcp", "tls", "ssl":
		ln, err := s.listenTCP(in.Port)
		if err != nil {
			return err
		}
		context.AfterFunc(ctx, func() { ln.Close() })
		var tlsCfg *tls.Config
		kind := KindTCP
		if in.proto() == "tls" || in.proto() == "ssl" {
			tlsCfg = s.streamTLSConfig(in.auth() == "x509")
			kind = KindTLS
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
					continue
				}
				if tlsCfg != nil {
					conn = tls.Server(conn, tlsCfg)
				}
				go func() {
					stop := context.AfterFunc(ctx, func() { conn.Close() })
					defer stop()
					st.clients.Add(1)
					defer st.clients.Add(-1)
					s.serveStreamInput(conn, kind, in, st)
				}()
			}
		}()
		return nil
	case "udp", "mcast", "multicast":
		var pc net.PacketConn
		addr := s.addr(in.Port)
		if in.proto() == "udp" {
			p, err := net.ListenPacket("udp", addr)
			if err != nil {
				return portError("udp", addr, err)
			}
			pc = p
		} else {
			ga, err := net.ResolveUDPAddr("udp", net.JoinHostPort(in.Group, strconv.Itoa(in.Port)))
			if err != nil || ga.IP == nil || !ga.IP.IsMulticast() {
				return fmt.Errorf("multicast inputs need a multicast group address, not %q", in.Group)
			}
			var ifi *net.Interface
			if in.Iface != "" {
				if ifi, err = net.InterfaceByName(in.Iface); err != nil {
					return err
				}
			}
			uc, err := net.ListenMulticastUDP("udp", ifi, ga)
			if err != nil {
				return err
			}
			pc = uc
		}
		context.AfterFunc(ctx, func() { pc.Close() })
		c := s.hub.NewClient(KindUDP, addr, s.inputIdentity(in))
		c.Name = in.Name
		c.authed.Store(true)
		c.input = in
		c.filter = func(*Message) bool { return false }
		s.applyLinkArea(c, in.Area)
		s.hub.Add(c)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.hub.Remove(c)
			buf := make([]byte, 65536)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
						return
					}
					continue
				}
				st.reads.Add(1)
				st.bytes.Add(int64(n))
				for _, e := range decodeDatagram(append([]byte(nil), buf[:n]...)) {
					st.messages.Add(1)
					c.touch()
					if in.ArchiveOnly {
						s.archiveOnly(c, NewMessage(e, c, c.InMask()))
						continue
					}
					s.ingestRelay(c, e, from.String())
				}
			}
		}()
		return nil
	}
	return fmt.Errorf("protocol %q is not supported", in.Protocol)
}

func (s *Server) archiveOnly(c *Client, m *Message) {
	if s.history != nil && !c.input.NoArchive {
		s.history.Record(m)
	}
}

type countingConn struct {
	net.Conn
	st *inputStats
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.st.reads.Add(1)
		c.st.bytes.Add(int64(n))
	}
	return n, err
}

func (s *Server) inputMetrics(excludeFeeds bool) []map[string]any {
	cfg := s.Config()
	var out []map[string]any
	counts := map[string][2]int64{}
	for _, c := range s.hub.Clients() {
		if c.input != nil {
			continue
		}
		v := counts[c.Kind]
		v[0]++
		v[1] += int64(c.rx.Load())
		counts[c.Kind] = v
	}
	core := func(name, proto string, port int, kind, auth string) {
		if port <= 0 {
			return
		}
		v := counts[kind]
		out = append(out, map[string]any{"id": name, "input": map[string]any{"name": name, "protocol": proto, "port": port, "auth": strings.ToUpper(auth), "archive": cfg.Retention.HistoryDays != 0,
			"anongroup": cfg.AllowAnonymous, "coreVersion": 2, "filtergroup": []string{}, "builtIn": true}, "numClients": v[0], "messagesReceived": v[1], "readsReceived": v[1], "bytesRecieved": 0})
	}
	anonAuth := "anonymous"
	if !cfg.AllowAnonymous {
		anonAuth = "file"
	}
	core("stdtcp", "tcp", cfg.Ports.TCP, KindTCP, anonAuth)
	if cfg.Ports.TCPAlt != cfg.Ports.TCP {
		core("streamtcp", "stcp", cfg.Ports.TCPAlt, KindTCP, anonAuth)
	}
	core("stdssl", "tls", cfg.Ports.TLS, KindTLS, "x509")
	core("stdudp", "udp", cfg.Ports.UDP, KindUDP, "anonymous")
	core("websocket", "websocket", cfg.Ports.WebSocket, KindWebSocket, anonAuth)
	s.inputMu.Lock()
	for _, in := range cfg.Inputs {
		var st *inputStats
		if run := s.inputRuns[in.Name]; run != nil {
			st = run.stats
		}
		m := map[string]any{"id": in.Name, "input": s.inputJSON(in), "numClients": 0, "messagesReceived": 0, "readsReceived": 0, "bytesRecieved": 0, "running": st != nil}
		if st != nil {
			m["numClients"], m["messagesReceived"], m["readsReceived"], m["bytesRecieved"] = st.clients.Load(), st.messages.Load(), st.reads.Load(), st.bytes.Load()
		}
		out = append(out, m)
	}
	s.inputMu.Unlock()
	if !excludeFeeds {
		for _, f := range s.allDataFeeds() {
			out = append(out, map[string]any{"id": f.UUID, "input": f, "numClients": 0, "messagesReceived": f.Messages, "readsReceived": f.Messages, "bytesRecieved": 0})
		}
	}
	return out
}

func (s *Server) inputJSON(in InputConfig) map[string]any {
	groups := in.FilterGroups
	if groups == nil {
		groups = []string{}
	}
	return map[string]any{"name": in.Name, "protocol": in.proto(), "port": in.Port, "group": in.Group, "iface": in.Iface, "auth": strings.ToUpper(in.auth()),
		"archive": !in.NoArchive, "archiveOnly": in.ArchiveOnly, "anongroup": len(groups) == 0 && in.auth() == "anonymous", "coreVersion": firstNonZero(in.CoreVersion, 2),
		"filtergroup": groups, "area": in.Area, "enabled": !in.Disabled}
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

type takInputBody struct {
	Name        string   `json:"name"`
	AltName     string   `json:"_name"`
	Protocol    string   `json:"protocol"`
	Port        int      `json:"port"`
	Group       string   `json:"group"`
	Iface       string   `json:"iface"`
	Auth        string   `json:"auth"`
	FilterGroup []string `json:"filtergroup"`
	Groups      []string `json:"filterGroups"`
	Area        string   `json:"area"`
	Archive     *bool    `json:"archive"`
	ArchiveOnly *bool    `json:"archiveOnly"`
	CoreVersion int      `json:"coreVersion"`
	Enabled     *bool    `json:"enabled"`
}

func (b takInputBody) apply(in *InputConfig) {
	if n := firstNonEmpty(b.Name, b.AltName); n != "" {
		in.Name = n
	}
	if b.Protocol != "" {
		in.Protocol = strings.ToLower(b.Protocol)
	}
	if b.Port != 0 {
		in.Port = b.Port
	}
	if b.Group != "" {
		in.Group = b.Group
	}
	if b.Iface != "" {
		in.Iface = b.Iface
	}
	if b.Auth != "" {
		in.Auth = strings.ToLower(b.Auth)
	}
	if g := append(b.FilterGroup, b.Groups...); len(g) > 0 || b.FilterGroup != nil || b.Groups != nil {
		in.FilterGroups = g
	}
	if b.Area != "" {
		in.Area = b.Area
	}
	if b.Archive != nil {
		in.NoArchive = !*b.Archive
	}
	if b.ArchiveOnly != nil {
		in.ArchiveOnly = *b.ArchiveOnly
	}
	if b.CoreVersion != 0 {
		in.CoreVersion = b.CoreVersion
	}
	if b.Enabled != nil {
		in.Disabled = !*b.Enabled
	}
}

func (s *Server) martiInputs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.InputMetric", s.inputMetrics(boolParam(r, "excludeDataFeeds"))))
}

func (s *Server) martiInput(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, m := range s.inputMetrics(false) {
		if m["id"] == name {
			writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.InputMetric", m))
			return
		}
		if in, ok := m["input"].(map[string]any); ok && in["name"] == name {
			writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.InputMetric", m))
			return
		}
	}
	writeJSON(w, http.StatusNotFound, s.envelope("error", "no such input"))
}

func (s *Server) martiInputSave(w http.ResponseWriter, r *http.Request) {
	var b takInputBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected an input"))
		return
	}
	key := r.PathValue("name")
	var saved InputConfig
	_, err := s.UpdateConfig(func(c *Config) error {
		i := -1
		for j, in := range c.Inputs {
			if key != "" && in.Name == key {
				i = j
			}
		}
		if key != "" && i < 0 {
			return errNoInput
		}
		if key == "" {
			n := firstNonEmpty(b.Name, b.AltName)
			for _, in := range c.Inputs {
				if in.Name == n {
					return errors.New("an input with that name already exists")
				}
			}
			c.Inputs = append(c.Inputs, InputConfig{})
			i = len(c.Inputs) - 1
		}
		b.apply(&c.Inputs[i])
		saved = c.Inputs[i]
		if err := validateInput(saved); err != nil {
			return err
		}
		return validateConfig(c)
	})
	if errors.Is(err, errNoInput) {
		writeJSON(w, http.StatusNotFound, s.envelope("error", err.Error()))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	s.syncInputs()
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Input", s.inputJSON(saved)))
}

var errNoInput = errors.New("no such input")

func (s *Server) martiInputDelete(w http.ResponseWriter, r *http.Request) {
	_, err := s.UpdateConfig(func(c *Config) error {
		for i, in := range c.Inputs {
			if in.Name == r.PathValue("name") {
				c.Inputs = append(c.Inputs[:i], c.Inputs[i+1:]...)
				return nil
			}
		}
		return errNoInput
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, s.envelope("error", err.Error()))
		return
	}
	s.syncInputs()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiInputsConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var b struct {
			LatestSA *bool `json:"latestSA"`
			Archive  *bool `json:"archive"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected messaging settings"))
			return
		}
		_, err := s.UpdateConfig(func(c *Config) error {
			if b.LatestSA != nil {
				if *b.LatestSA && c.Replay == "none" {
					c.Replay = "all"
				} else if !*b.LatestSA {
					c.Replay = "none"
				}
			}
			if b.Archive != nil {
				if *b.Archive && c.Retention.HistoryDays == 0 {
					c.Retention.HistoryDays = DefaultConfig().Retention.HistoryDays
				} else if !*b.Archive {
					c.Retention.HistoryDays = 0
				}
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
	}
	cfg := s.Config()
	writeJSON(w, http.StatusOK, map[string]any{"latestSA": cfg.Replay != "none", "archive": cfg.Retention.HistoryDays != 0, "numDbConnections": 0,
		"numAutoDbConnections": 0, "connectionPoolAutoSize": true, "dbUsername": "", "dbPassword": "", "dbUrl": "embedded", "sslEnabled": false})
}

func (s *Server) inputNames() []string {
	var out []string
	for _, in := range s.Config().Inputs {
		out = append(out, in.Name)
	}
	sort.Strings(out)
	return out
}
