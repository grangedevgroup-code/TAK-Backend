package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/update"
)

type UpdatesConfig struct {
	Auto bool `json:"auto"`
	Hour int  `json:"hour"`
}

type updateState struct {
	mu        sync.Mutex
	latest    update.Release
	checked   time.Time
	err       string
	installed time.Time
	busy      bool
	exit      chan struct{}
	exitOnce  sync.Once
}

func (s *Server) UpdateExit() <-chan struct{} { return s.upd.exit }

func (s *Server) updateBlocked() string {
	switch {
	case !update.Valid(s.Version):
		return "this is a development build, so it does not update itself"
	case update.InContainer():
		return "running in a container: pull the new image and recreate the container instead"
	}
	return ""
}

func (s *Server) checkForUpdate(ctx context.Context) (update.Release, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rel, err := update.Latest(ctx, &http.Client{Timeout: 30 * time.Second})
	s.upd.mu.Lock()
	defer s.upd.mu.Unlock()
	s.upd.checked = time.Now().UTC()
	if err != nil {
		s.upd.err = err.Error()
		return rel, err
	}
	s.upd.err = ""
	s.upd.latest = rel
	return rel, nil
}

func (s *Server) installUpdate(by string) error {
	if why := s.updateBlocked(); why != "" {
		return errors.New(why)
	}
	s.upd.mu.Lock()
	if s.upd.busy {
		s.upd.mu.Unlock()
		return errors.New("an update is already being installed")
	}
	s.upd.busy = true
	s.upd.mu.Unlock()
	defer func() {
		s.upd.mu.Lock()
		s.upd.busy = false
		s.upd.mu.Unlock()
	}()
	rel, err := s.checkForUpdate(s.ctx)
	if err != nil {
		return err
	}
	if !update.Newer(rel.Version, s.Version) {
		return errors.New("already up to date")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	defer cancel()
	s.log.Info("installing update", "from", s.Version, "to", rel.Version, "by", by)
	if err := rel.Install(ctx, &http.Client{Timeout: 10 * time.Minute}, exe); err != nil {
		s.log.Error("update failed", "to", rel.Version, "err", err)
		s.upd.mu.Lock()
		s.upd.err = err.Error()
		s.upd.mu.Unlock()
		return err
	}
	s.upd.mu.Lock()
	s.upd.installed = time.Now().UTC()
	s.upd.mu.Unlock()
	s.log.Info("update installed; restarting into the new version", "version", rel.Version)
	go func() {
		time.Sleep(time.Second)
		s.upd.exitOnce.Do(func() { close(s.upd.exit) })
	}()
	return nil
}

func (s *Server) updateJob() error {
	cfg := s.Config().Updates
	rel, err := s.checkForUpdate(s.ctx)
	if err != nil {
		return err
	}
	if !cfg.Auto || !update.Newer(rel.Version, s.Version) || s.updateBlocked() != "" {
		return nil
	}
	if time.Now().Hour() != cfg.Hour {
		return nil
	}
	return s.installUpdate("automatic update")
}

func (s *Server) apiUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.checkForUpdate(r.Context())
	}
	s.upd.mu.Lock()
	rel, checked, errText := s.upd.latest, s.upd.checked, s.upd.err
	s.upd.mu.Unlock()
	out := map[string]any{
		"current": s.Version, "latest": rel.Version, "url": rel.URL, "checked": checked, "error": errText,
		"available": update.Newer(rel.Version, s.Version), "blocked": s.updateBlocked(), "settings": s.Config().Updates,
	}
	if !rel.Published.IsZero() {
		out["published"] = rel.Published
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiUpdateInstall(w http.ResponseWriter, r *http.Request) {
	if err := s.installUpdate(identityOf(r).Name); err != nil {
		apiError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
