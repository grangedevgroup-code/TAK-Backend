package server

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type job struct {
	id, name string
	every    string
	fn       func() error
	last     time.Time
	dur      time.Duration
	err      string
	paused   bool
	running  bool
	runs     int64
}

type jobRegistry struct {
	mu    sync.Mutex
	jobs  map[string]*job
	order []string
}

type JobView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Every    string    `json:"every"`
	LastRun  time.Time `json:"lastRun,omitempty"`
	Duration float64   `json:"durationMs"`
	Error    string    `json:"error,omitempty"`
	Paused   bool      `json:"paused"`
	Running  bool      `json:"running"`
	Runs     int64     `json:"runs"`
}

func (s *Server) registerJob(id, name, every string, fn func() error) {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	if s.jobs.jobs == nil {
		s.jobs.jobs = map[string]*job{}
	}
	if _, ok := s.jobs.jobs[id]; !ok {
		s.jobs.order = append(s.jobs.order, id)
	}
	s.jobs.jobs[id] = &job{id: id, name: name, every: every, fn: fn}
}

func (s *Server) jobPaused(id string) bool {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	j := s.jobs.jobs[id]
	return j != nil && j.paused
}

func (s *Server) jobStart(id string, force bool) (*job, bool) {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	j := s.jobs.jobs[id]
	if j == nil || j.running || (j.paused && !force) {
		return j, false
	}
	j.running = true
	return j, true
}

func (s *Server) jobDone(j *job, start time.Time, err error) {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	j.running = false
	j.last, j.dur = start, time.Since(start)
	j.runs++
	j.err = ""
	if err != nil {
		j.err = err.Error()
	}
}

func (s *Server) runJob(id string) {
	s.runJobFn(id, false, nil)
}

func (s *Server) runJobFn(id string, force bool, fn func() error) {
	j, ok := s.jobStart(id, force)
	if !ok {
		return
	}
	if fn == nil {
		fn = j.fn
	}
	start := time.Now()
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
				s.log.Error("background job failed", "job", id, "err", err)
			}
		}()
		err = fn()
	}()
	s.jobDone(j, start, err)
}

func (s *Server) jobViews() []JobView {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	out := make([]JobView, 0, len(s.jobs.order))
	for _, id := range s.jobs.order {
		j := s.jobs.jobs[id]
		out = append(out, JobView{ID: j.id, Name: j.name, Every: j.every, LastRun: j.last, Duration: float64(j.dur.Microseconds()) / 1000, Error: j.err, Paused: j.paused, Running: j.running, Runs: j.runs})
	}
	return out
}

func (s *Server) registerJobs() {
	s.registerJob("cleanup", "Delete old data", "every hour", func() error { s.housekeeping(); return nil })
	s.registerJob("certificate", "Renew the server certificate", "every hour", func() error { return s.pki.EnsureServer(s.Config()) })
	s.registerJob("emergencies", "Repeat active emergencies", "every repeater interval", func() error {
		if s.Config().Repeater.Enabled {
			s.hub.RepeatEmergencies()
		}
		return nil
	})
	s.registerJob("repeated", "Send repeated objects", "every minute", func() error { s.repeatAll(); return nil })
	s.registerJob("sync", "Save devices and missions, refresh voice channels", "every minute", func() error { s.minuteTasks(); return nil })
	s.registerJob("adsb", "ADS-B aircraft", "every feed interval", nil)
	s.registerJob("ais", "AIS ships", "every feed interval", nil)
	s.registerJob("updates", "Check for and install updates", "every hour", s.updateJob)
	s.registerJob("letsencrypt", "Let's Encrypt renewal", "every 12 hours", func() error {
		if !s.Config().ACME.Enabled || s.acme == nil {
			return errors.New("the Let's Encrypt setting is off")
		}
		return s.renewACME(false)
	})
}

func (s *Server) apiJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.jobViews())
}

func (s *Server) apiJobAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	s.jobs.mu.Lock()
	j := s.jobs.jobs[id]
	if j == nil {
		s.jobs.mu.Unlock()
		apiError(w, http.StatusNotFound, errors.New("no such job"))
		return
	}
	switch action {
	case "pause":
		j.paused = true
	case "resume":
		j.paused = false
	case "run":
	default:
		s.jobs.mu.Unlock()
		apiError(w, http.StatusBadRequest, errors.New("action must be run, pause or resume"))
		return
	}
	s.jobs.mu.Unlock()
	s.log.Info("background job "+action, "job", id, "by", identityOf(r).Name)
	if action == "run" {
		go s.runJobFn(id, true, s.jobRunner(id))
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) jobRunner(id string) func() error {
	switch id {
	case "letsencrypt":
		return func() error {
			if !s.Config().ACME.Enabled || s.acme == nil {
				return errors.New("the Let's Encrypt setting is off")
			}
			return s.renewACME(true)
		}
	case "adsb", "ais":
		return func() error {
			if s.feedKick == nil {
				return errors.New("feeds are not running")
			}
			select {
			case s.feedKick[id] <- struct{}{}:
			default:
			}
			return nil
		}
	}
	return nil
}
