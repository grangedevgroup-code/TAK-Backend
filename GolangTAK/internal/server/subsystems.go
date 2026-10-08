package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/store"
)

func (s *Server) initSubsystems() error {
	var err error
	if s.tokenKey, err = loadTokenKey(s.DataDir); err != nil {
		return err
	}
	if s.devices, err = OpenDevices(filepath.Join(s.DataDir, "db")); err != nil {
		return err
	}
	if s.res, err = OpenResources(s.DataDir); err != nil {
		return err
	}
	if s.history, err = OpenHistory(filepath.Join(s.DataDir, "history")); err != nil {
		return err
	}
	s.history.names = s.dir.Names
	if s.missions, err = OpenMissions(s.DataDir); err != nil {
		return err
	}
	if s.videos, err = OpenVideos(s.DataDir); err != nil {
		return err
	}
	if s.profiles, err = OpenProfiles(s.DataDir); err != nil {
		return err
	}
	if s.chats, err = OpenChats(s.DataDir); err != nil {
		return err
	}
	if s.repeated, err = OpenRepeated(s.DataDir); err != nil {
		return err
	}
	if s.mapLayers, err = OpenMapLayers(s.DataDir); err != nil {
		return err
	}
	if s.fedFeeds, err = store.Open[dataFeedView](filepath.Join(s.DataDir, "db", "federated-feeds.jsonl"), true); err != nil {
		return err
	}
	if s.reports, err = OpenReports(s.DataDir); err != nil {
		return err
	}
	s.links = map[string]*downloadLink{}
	s.feeds = &feedState{status: map[string]*FeedStatus{}}
	s.restart = make(chan struct{}, 1)
	s.peers = newPeerManager(s)
	s.fed = newFederation(s)
	s.ensureExCheckTemplates()
	s.hub.OnIdentify = func(c *Client) {
		s.devices.Seen(c, "Connected")
		s.deliverStored(c)
		s.announceLocalContact(c)
		info := c.Info()
		s.log.Info("device identified", "callsign", info.Callsign, "uid", info.UID, "platform", info.Platform, "version", info.Version, "user", c.User(), "remote", c.Remote)
	}
	s.hub.OnRemove = func(c *Client) {
		if !c.Relay && c.UID() != "" {
			s.devices.Seen(c, "Disconnected")
		}
	}
	s.hub.OnCoT = func(m *Message) {
		if !m.NoHistory {
			s.history.Record(m)
		}
		if m.Feed != "" {
			s.onFeedMessage(m)
		}
		if src := m.Source; src != nil && !src.Relay && m.Event.IsSA() && m.Event.UID == src.UID() {
			s.devices.Seen(src, "Connected")
		}
	}
	s.hub.OnMissions = s.onMissionCoT
	s.hub.OnOffline = s.storeOffline
	return nil
}

func (s *Server) startSubsystems() error {
	if err := s.startUDP(); err != nil {
		return err
	}
	if err := s.startMesh(); err != nil {
		s.log.Warn("mesh bridge unavailable", "err", err)
	}
	if err := s.startHTTP(); err != nil {
		return err
	}
	if err := s.startFederation(); err != nil {
		return err
	}
	if err := s.startFederationV2(); err != nil {
		return err
	}
	s.rebuildFeedIndex()
	s.startDataFeeds()
	if err := s.startLiveVideo(); err != nil {
		return err
	}
	s.startVoice()
	s.startFeeds()
	s.startMeshtastic()
	s.histStop = make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.history.Run(s.histStop)
	}()
	s.peers.Reload(s.Config().Peers)
	s.stoppers = append(s.stoppers, func() {
		s.peers.Stop()
		close(s.histStop)
	})
	return nil
}

func (s *Server) closeSubsystems() {
	if s.devices != nil {
		s.devices.Close()
	}
	if s.res != nil {
		s.res.Close()
	}
	if s.missions != nil {
		s.missions.Close()
	}
	if s.videos != nil {
		s.videos.Close()
	}
	if s.profiles != nil {
		s.profiles.Close()
	}
	if s.chats != nil {
		s.chats.Close()
	}
	if s.repeated != nil {
		s.repeated.Close()
	}
	if s.mapLayers != nil {
		s.mapLayers.Close()
	}
	if s.fedFeeds != nil {
		s.fedFeeds.Close()
	}
	if s.reports != nil {
		s.reports.Close()
	}
}

func (s *Server) minuteTasks() {
	s.refreshVoiceChannels()
	s.devices.Flush()
	s.missions.cots.Sync()
}

func (s *Server) housekeeping() {
	cfg := s.Config()
	s.expireResources()
	s.expireMissions()
	s.expireChats()
	if n := s.history.Cleanup(cfg.Retention.HistoryDays); n > 0 {
		s.log.Info("old history removed", "days", n)
	}
	s.devices.Prune(180 * 24 * time.Hour)
	s.devices.Flush()
}

func (s *Server) RestartRequested() <-chan struct{} { return s.restart }

func (s *Server) apiRestart(w http.ResponseWriter, r *http.Request) {
	s.log.Info("restart requested", "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		select {
		case s.restart <- struct{}{}:
		default:
		}
	}()
}

func jsonUnmarshalStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) martiFileDeleteByUID(w http.ResponseWriter, r *http.Request) {
	r.SetPathValue("hash", r.PathValue("uid"))
	s.martiFileDelete(w, r)
}

func (s *Server) apiFileDownload(w http.ResponseWriter, r *http.Request) {
	s.serveResource(w, r, r.PathValue("uid"))
}
