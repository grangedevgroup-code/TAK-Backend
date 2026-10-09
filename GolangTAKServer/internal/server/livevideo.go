package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/media"
)

type VideoServerConfig struct {
	Enabled          bool          `json:"enabled"`
	RTSPPort         int           `json:"rtspPort"`
	RTSPSPort        int           `json:"rtspsPort"`
	RTMPPort         int           `json:"rtmpPort"`
	RTPPort          int           `json:"rtpPort"`
	AnonymousRead    bool          `json:"anonymousRead"`
	AnonymousPublish bool          `json:"anonymousPublish"`
	MaxStreams       int           `json:"maxStreams"`
	Sources          []VideoSource `json:"sources"`
	Record           bool          `json:"record"`
	RecordPaths      []string      `json:"recordPaths"`
	RecordMinutes    int           `json:"recordMinutes"`
	RecordDays       int           `json:"recordDays"`
}

type VideoSource struct {
	Name     string   `json:"name"`
	URL      string   `json:"url"`
	Path     string   `json:"path"`
	Groups   []string `json:"groups"`
	Enabled  bool     `json:"enabled"`
	Insecure bool     `json:"insecure,omitempty"`
}

type sourceState struct {
	mu    sync.Mutex
	err   string
	since time.Time
}

type liveVideo struct {
	reg       *media.Registry
	srv       *media.Server
	sources   sync.Map
	recorders sync.Map
}

func (s *Server) startLiveVideo() error {
	cfg := s.Config()
	vc := cfg.Video
	if !vc.Enabled {
		return nil
	}
	reg := media.NewRegistry()
	reg.MaxStreams = vc.MaxStreams
	reg.OnPublish = s.onStreamPublish
	reg.OnUnpublish = s.onStreamUnpublish
	srv := media.NewServer(reg, s.log)
	srv.Auth = s.rtspAuth
	srv.MaxConns = cfg.Limits.MaxClients
	lv := &liveVideo{reg: reg, srv: srv}
	if vc.RTPPort > 0 {
		host := ""
		if cfg.Bind != "" {
			host = cfg.Bind
		}
		if err := srv.ListenUDP(host, vc.RTPPort); err != nil {
			s.log.Warn("video server UDP transport unavailable, TCP still works", "port", vc.RTPPort, "err", err)
		}
	}
	if vc.RTSPPort > 0 {
		ln, err := s.listenTCP(vc.RTSPPort)
		if err != nil {
			s.log.Error("video server could not start; change the RTSP port under Settings", "port", vc.RTSPPort, "err", err)
			srv.Close()
			return nil
		}
		go srv.Serve(ln)
		s.log.Info("video server listening", "rtsp", vc.RTSPPort, "rtp", vc.RTPPort)
	}
	if vc.RTSPSPort > 0 {
		if ln, err := s.listenTCP(vc.RTSPSPort); err != nil {
			s.log.Error("secure video server could not start", "port", vc.RTSPSPort, "err", err)
		} else {
			tcfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.pki.ServerCert(), nil }}
			go srv.Serve(tls.NewListener(ln, tcfg))
			s.log.Info("video server listening", "rtsps", vc.RTSPSPort)
		}
	}
	var rtmp *media.RTMPServer
	if vc.RTMPPort > 0 {
		if ln, err := s.listenTCP(vc.RTMPPort); err != nil {
			s.log.Error("RTMP ingest could not start", "port", vc.RTMPPort, "err", err)
		} else {
			rtmp = media.NewRTMPServer(reg)
			rtmp.Auth = s.rtspAuth
			rtmp.Log = s.log
			go rtmp.Serve(ln)
			s.log.Info("video server listening", "rtmp", vc.RTMPPort)
		}
	}
	s.live = lv
	s.track(closerFunc(func() error {
		if rtmp != nil {
			rtmp.Close()
		}
		srv.Close()
		reg.CloseAll()
		return nil
	}))
	for _, src := range vc.Sources {
		if src.Enabled {
			s.startVideoSource(src)
		}
	}
	return nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func (s *Server) rtspAuth(user, pass string, publish bool, path, remote string) (string, error) {
	vc := s.Config().Video
	if user == "" {
		if (publish && vc.AnonymousPublish) || (!publish && vc.AnonymousRead) {
			return "", nil
		}
		return "", media.ErrUnauthorized
	}
	id, err := s.dir.CheckPassword(remoteIP(remote), user, pass)
	if err != nil {
		return "", media.ErrForbidden
	}
	if !publish && s.live != nil {
		if st, ok := s.live.reg.Get(path); ok && !s.streamVisible(id, st) {
			return "", media.ErrForbidden
		}
	}
	return id.Name, nil
}

func (s *Server) streamGroups(st *media.Stream) []string {
	if v, ok := st.Meta("groups"); ok {
		return v.([]string)
	}
	return nil
}

func (s *Server) streamVisible(id *Identity, st *media.Stream) bool {
	groups := s.streamGroups(st)
	if id.Admin || len(groups) == 0 {
		return true
	}
	mine := s.identityGroups(id)
	return slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(mine, g) })
}

func streamFeedUID(name string) string {
	return "golangtakserver-live-" + strings.ReplaceAll(name, "/", "-")
}

func (s *Server) onStreamPublish(st *media.Stream) {
	var groups []string
	if strings.HasPrefix(st.Source, "pull ") {
		for _, src := range s.Config().Video.Sources {
			if p, _ := media.CleanPath(firstNonEmpty(src.Path, src.Name)); p == st.Name {
				groups = src.Groups
			}
		}
	} else if u, ok := s.dir.User(st.Publisher); ok {
		groups = u.In
	}
	st.SetMeta("groups", groups)
	cfg := s.Config()
	f := VideoFeed{UID: streamFeedUID(st.Name), Alias: st.Name, Protocol: "rtsp", Address: cfg.Address, Port: cfg.Video.RTSPPort, Path: "/" + st.Name, RTSPReliable: "1", Buffer: "-1", Timeout: "5000", Groups: groups, Creator: st.Publisher, Updated: time.Now().UTC(), Active: true}
	s.videos.Put(f)
	s.log.Info("live video stream available", "path", st.Name, "by", st.Publisher, "source", st.Source)
	if s.shouldRecord(st.Name) {
		go s.startRecording(st)
	}
}

func (s *Server) onStreamUnpublish(st *media.Stream) {
	s.videos.Delete(streamFeedUID(st.Name))
}

func (s *Server) startVideoSource(src VideoSource) {
	path, err := media.CleanPath(firstNonEmpty(src.Path, src.Name))
	if err != nil {
		s.log.Warn("video source has a bad path", "source", src.Name, "err", err)
		return
	}
	state := &sourceState{}
	s.live.sources.Store(src.Name, state)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		delay := time.Second
		for s.ctx.Err() == nil {
			started := time.Now()
			err := media.Pull(s.ctx, src.URL, &tls.Config{InsecureSkipVerify: src.Insecure}, s.live.reg, path, firstNonEmpty(src.Name, "source"))
			if s.ctx.Err() != nil {
				return
			}
			state.mu.Lock()
			if err != nil {
				state.err = scrubPassword(err.Error(), src.URL)
			}
			state.since = time.Now()
			state.mu.Unlock()
			if time.Since(started) > time.Minute {
				delay = time.Second
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, time.Minute)
		}
	}()
}

func scrubPassword(msg, raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		if p, ok := u.User.Password(); ok && p != "" {
			msg = strings.ReplaceAll(msg, p, "***")
		}
	}
	return msg
}

type streamView struct {
	Path      string    `json:"path"`
	Publisher string    `json:"publisher"`
	Source    string    `json:"source"`
	Started   time.Time `json:"started"`
	Readers   int       `json:"readers"`
	Bytes     int64     `json:"bytes"`
	Codecs    []string  `json:"codecs"`
	RTSP      string    `json:"rtsp"`
	HLS       string    `json:"hls"`
	Browser   bool      `json:"browser"`
	Groups    []string  `json:"groups,omitempty"`
	LastData  time.Time `json:"lastData"`
	Recording bool      `json:"recording"`
}

func (s *Server) rtspURL(r *http.Request, path string) string {
	cfg := s.Config()
	host := cfg.Address
	if r != nil {
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		} else if r.Host != "" {
			host = r.Host
		}
	}
	return "rtsp://" + net.JoinHostPort(host, strconv.Itoa(cfg.Video.RTSPPort)) + "/" + path
}

func (s *Server) rtmpURL(r *http.Request) string {
	cfg := s.Config()
	if cfg.Video.RTMPPort <= 0 {
		return ""
	}
	u := s.rtspURL(r, "live/NAME")
	host := strings.TrimPrefix(u, "rtsp://")
	host = host[:strings.Index(host, "/")]
	h, _, _ := net.SplitHostPort(host)
	return "rtmp://" + net.JoinHostPort(h, strconv.Itoa(cfg.Video.RTMPPort)) + "/live/NAME?user=USER&pass=PASSWORD"
}

func (s *Server) apiStreams(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []streamView{}
	if s.live != nil {
		for _, st := range s.live.reg.List() {
			if !s.streamVisible(id, st) {
				continue
			}
			v := streamView{Path: st.Name, Publisher: st.Publisher, Source: st.Source, Started: st.Started, Readers: st.Readers(), Bytes: st.BytesIn.Load(), RTSP: s.rtspURL(r, st.Name), HLS: "/api/video/live/" + st.Name + "/index.m3u8", Groups: s.streamGroups(st), LastData: st.LastPacket(), Recording: s.isRecording(st.Name)}
			for _, t := range st.Desc.Tracks {
				v.Codecs = append(v.Codecs, firstNonEmpty(t.Codec, t.Media))
				if t.Media == "video" && t.Codec == "H264" {
					v.Browser = true
				}
			}
			out = append(out, v)
		}
	}
	sources := []map[string]any{}
	for _, src := range s.Config().Video.Sources {
		m := map[string]any{"name": src.Name, "path": firstNonEmpty(src.Path, src.Name), "enabled": src.Enabled}
		if v, ok := s.live.sourceState(src.Name); ok {
			v.mu.Lock()
			m["error"] = v.err
			v.mu.Unlock()
		}
		if p, err := media.CleanPath(firstNonEmpty(src.Path, src.Name)); err == nil && s.live != nil {
			_, m["live"] = s.live.reg.Get(p)
		}
		sources = append(sources, m)
	}
	vc := s.Config().Video
	writeJSON(w, http.StatusOK, map[string]any{"enabled": vc.Enabled && s.live != nil, "rtspPort": vc.RTSPPort, "rtspsPort": vc.RTSPSPort, "rtmpPort": vc.RTMPPort, "rtmpURL": s.rtmpURL(r), "rtpPort": vc.RTPPort, "streams": out, "sources": sources, "publishURL": s.rtspURL(r, "live/NAME")})
}

func (lv *liveVideo) sourceState(name string) (*sourceState, bool) {
	if lv == nil {
		return nil, false
	}
	v, ok := lv.sources.Load(name)
	if !ok {
		return nil, false
	}
	return v.(*sourceState), true
}

func (s *Server) apiLiveStream(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the video server is off"})
		return
	}
	rest := r.PathValue("rest")
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	name, file := rest[:i], rest[i+1:]
	st, ok := s.live.reg.Get(name)
	if !ok || !s.streamVisible(identityOf(r), st) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no live stream at that path"})
		return
	}
	l, err := media.LiveFor(st)
	if err != nil {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": err.Error()})
		return
	}
	if err := l.Wait(8 * time.Second); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch {
	case file == "live.mp4":
		s.serveLiveMP4(w, r, l)
	case file == "index.m3u8":
		pl, ok := l.Playlist()
		deadline := time.Now().Add(6 * time.Second)
		for !ok && time.Now().Before(deadline) {
			time.Sleep(200 * time.Millisecond)
			pl, ok = l.Playlist()
		}
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the first segment is not ready yet"})
			return
		}
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Write([]byte(pl))
	case file == "init.mp4":
		w.Header().Set("Content-Type", "video/mp4")
		w.Write(l.Init())
	case strings.HasPrefix(file, "seg") && strings.HasSuffix(file, ".m4s"):
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(file, "seg"), ".m4s"))
		seg, ok := l.Segment(n)
		if err != nil || !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "segment expired"})
			return
		}
		w.Header().Set("Content-Type", "video/iso.segment")
		w.Write(seg)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) serveLiveMP4(w http.ResponseWriter, r *http.Request, l *media.Live) {
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", fmt.Sprintf(`video/mp4; codecs="%s"`, l.Codec()))
	w.Header().Set("X-Codec", l.Codec())
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(l.Init()); err != nil {
		return
	}
	rc.Flush()
	v := l.Watch()
	defer l.Unwatch(v)
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-v.Done:
			return
		case frag := <-v.C:
			rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err := w.Write(frag); err != nil {
				return
			}
			if len(v.C) == 0 {
				rc.Flush()
			}
		}
	}
}

func (s *Server) apiStreamStop(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the video server is off"})
		return
	}
	st, ok := s.live.reg.Get(r.PathValue("rest"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no live stream at that path"})
		return
	}
	s.live.reg.Unpublish(st)
	w.WriteHeader(http.StatusNoContent)
}
