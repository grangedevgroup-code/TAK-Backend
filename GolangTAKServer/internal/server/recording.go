package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/media"
)

type recorder struct {
	stop  chan struct{}
	once  sync.Once
	since time.Time
}

func (r *recorder) halt() { r.once.Do(func() { close(r.stop) }) }

type recordingMeta struct {
	Path      string    `json:"path"`
	File      string    `json:"file"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Duration  float64   `json:"duration"`
	Size      int64     `json:"size"`
	Publisher string    `json:"publisher"`
	Groups    []string  `json:"groups"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
}

func (s *Server) recordingsDir() string { return filepath.Join(s.DataDir, "recordings") }

func (s *Server) shouldRecord(name string) bool {
	vc := s.Config().Video
	if vc.Record {
		return true
	}
	for _, p := range vc.RecordPaths {
		p = strings.Trim(p, "/ ")
		if p != "" && (name == p || strings.HasPrefix(name, p+"/")) {
			return true
		}
	}
	return false
}

func (s *Server) startRecording(st *media.Stream) bool {
	if s.live == nil {
		return false
	}
	rec := &recorder{stop: make(chan struct{}), since: time.Now()}
	if _, loaded := s.live.recorders.LoadOrStore(st.Name, rec); loaded {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.live.recorders.CompareAndDelete(st.Name, rec)
		s.recordStream(st, rec)
	}()
	return true
}

func (s *Server) stopRecording(name string) bool {
	if s.live == nil {
		return false
	}
	v, ok := s.live.recorders.Load(name)
	if ok {
		v.(*recorder).halt()
	}
	return ok
}

func (s *Server) isRecording(name string) bool {
	if s.live == nil {
		return false
	}
	_, ok := s.live.recorders.Load(name)
	return ok
}

func (s *Server) recordStream(st *media.Stream, rec *recorder) {
	l, err := media.LiveFor(st)
	if err != nil {
		s.log.Warn("stream cannot be recorded", "path", st.Name, "err", err)
		return
	}
	if err := l.Wait(20 * time.Second); err != nil {
		s.log.Warn("stream cannot be recorded", "path", st.Name, "err", err)
		return
	}
	s.log.Info("recording started", "path", st.Name)
	defer s.log.Info("recording stopped", "path", st.Name)
	for {
		minutes := s.Config().Video.RecordMinutes
		if minutes <= 0 {
			minutes = 30
		}
		done := s.recordSegment(st, l, rec, time.Duration(minutes)*time.Minute)
		if done {
			return
		}
	}
}

func (s *Server) recordSegment(st *media.Stream, l *media.Live, rec *recorder, length time.Duration) bool {
	sps, pps, info, ok := l.Params()
	if !ok {
		return true
	}
	start := time.Now().UTC()
	dir := filepath.Join(s.recordingsDir(), filepath.FromSlash(st.Name))
	file := filepath.Join(dir, start.Format("20060102-150405")+".mp4")
	w, err := media.NewMP4Writer(file, sps, pps, info)
	if err != nil {
		s.log.Error("recording failed", "path", st.Name, "err", err)
		return true
	}
	v := l.Watch()
	timer := time.NewTimer(length)
	defer timer.Stop()
	stopped := false
loop:
	for {
		select {
		case <-rec.stop:
			stopped = true
			break loop
		case <-s.ctx.Done():
			stopped = true
			break loop
		case <-st.Done():
			stopped = true
			break loop
		case <-v.Done:
			break loop
		case <-timer.C:
			break loop
		case frag := <-v.C:
			if err := w.WriteFragment(frag); err != nil {
				s.log.Warn("recording fragment skipped", "path", st.Name, "err", err)
			}
		}
	}
	l.Unwatch(v)
	dur := w.Duration()
	if err := w.Close(); err != nil {
		os.Remove(file)
		return stopped
	}
	fi, _ := os.Stat(file)
	meta := recordingMeta{Path: st.Name, File: filepath.Base(file), Start: start, End: time.Now().UTC(), Duration: dur, Publisher: st.Publisher, Groups: s.streamGroups(st), Width: info.Width, Height: info.Height}
	if fi != nil {
		meta.Size = fi.Size()
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	writeFileAtomic(file+".json", b, 0o600)
	return stopped
}

func (s *Server) recordings() []recordingMeta {
	var out []recordingMeta
	root := s.recordingsDir()
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".mp4.json") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var m recordingMeta
		if json.Unmarshal(b, &m) == nil {
			out = append(out, m)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out
}

func (s *Server) recordingVisible(id *Identity, m recordingMeta) bool {
	if id.Admin || len(m.Groups) == 0 {
		return true
	}
	mine := s.identityGroups(id)
	return slices.ContainsFunc(m.Groups, func(g string) bool { return slices.Contains(mine, g) })
}

func (s *Server) findRecording(rest string) (recordingMeta, string, bool) {
	rest = strings.Trim(rest, "/")
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		return recordingMeta{}, "", false
	}
	path, file := rest[:i], rest[i+1:]
	if _, err := media.CleanPath(path); err != nil || !strings.HasSuffix(file, ".mp4") || strings.ContainsAny(file, `/\`) || strings.HasPrefix(file, ".") {
		return recordingMeta{}, "", false
	}
	full := filepath.Join(s.recordingsDir(), filepath.FromSlash(path), file)
	b, err := os.ReadFile(full + ".json")
	if err != nil {
		return recordingMeta{}, "", false
	}
	var m recordingMeta
	if json.Unmarshal(b, &m) != nil {
		return recordingMeta{}, "", false
	}
	return m, full, true
}

func (s *Server) apiRecordings(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []recordingMeta{}
	for _, m := range s.recordings() {
		if s.recordingVisible(id, m) {
			out = append(out, m)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiRecordingFile(w http.ResponseWriter, r *http.Request) {
	m, full, ok := s.findRecording(r.PathValue("rest"))
	if !ok || !s.recordingVisible(identityOf(r), m) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recording not found"})
		return
	}
	if r.Method == http.MethodDelete {
		if !identityOf(r).Admin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrators only"})
			return
		}
		os.Remove(full)
		os.Remove(full + ".json")
		s.log.Info("recording deleted", "path", m.Path, "file", m.File, "by", identityOf(r).Name)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	f, err := os.Open(full)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recording not found"})
		return
	}
	defer f.Close()
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(strings.ReplaceAll(m.Path, "/", "-")+"-"+m.File)+`"`)
	}
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, m.File, m.End, f)
}

func (s *Server) apiRecordControl(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the video server is off"})
		return
	}
	name := r.PathValue("rest")
	if r.Method == http.MethodDelete {
		if !s.stopRecording(name) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "that stream is not being recorded"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	st, ok := s.live.reg.Get(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no live stream at that path"})
		return
	}
	if !s.startRecording(st) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "that stream is already being recorded"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) expireRecordings() {
	days := s.Config().Video.RecordDays
	if days <= 0 {
		return
	}
	cut := time.Now().AddDate(0, 0, -days)
	n := 0
	for _, m := range s.recordings() {
		if m.End.Before(cut) {
			full := filepath.Join(s.recordingsDir(), filepath.FromSlash(m.Path), m.File)
			os.Remove(full)
			os.Remove(full + ".json")
			n++
		}
	}
	if n > 0 {
		s.log.Info("old recordings removed", "count", n, "days", days)
	}
}
