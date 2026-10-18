package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type cronField struct {
	any  bool
	vals map[int]bool
}

type cronSpec struct {
	min, hour, dom, mon, dow cronField
}

var cronNames = map[string]int{
	"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
	"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}

func parseCronField(f string, lo, hi int) (cronField, error) {
	if f == "*" || f == "?" {
		return cronField{any: true}, nil
	}
	out := cronField{vals: map[int]bool{}}
	num := func(v string) (int, error) {
		if n, ok := cronNames[strings.ToUpper(v)]; ok {
			return n, nil
		}
		return strconv.Atoi(v)
	}
	for _, part := range strings.Split(f, ",") {
		step := 1
		if a, b, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(b)
			if err != nil || n <= 0 {
				return out, fmt.Errorf("bad step in %q", part)
			}
			part, step = a, n
		}
		start, end := lo, hi
		switch {
		case part == "*" || part == "?":
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			var err1, err2 error
			start, err1 = num(a)
			end, err2 = num(b)
			if err1 != nil || err2 != nil {
				return out, fmt.Errorf("bad range %q", part)
			}
		default:
			n, err := num(part)
			if err != nil {
				return out, fmt.Errorf("bad value %q", part)
			}
			start, end = n, n
			if step > 1 {
				end = hi
			}
		}
		if start < lo || end > hi || start > end {
			if !(hi == 6 && end == 7) {
				return out, fmt.Errorf("%q is out of range %d-%d", part, lo, hi)
			}
		}
		for v := start; v <= end; v += step {
			out.vals[v%(hi+1)] = true
			if hi == 6 && v == 7 {
				out.vals[0] = true
			}
		}
	}
	return out, nil
}

func parseCron(expr string) (*cronSpec, error) {
	f := strings.Fields(expr)
	if len(f) == 6 {
		f = f[1:]
	}
	if len(f) != 5 {
		return nil, errors.New("a schedule has 5 fields (minute hour day month weekday) or 6 with seconds first")
	}
	var c cronSpec
	var err error
	if c.min, err = parseCronField(f[0], 0, 59); err != nil {
		return nil, err
	}
	if c.hour, err = parseCronField(f[1], 0, 23); err != nil {
		return nil, err
	}
	if c.dom, err = parseCronField(f[2], 1, 31); err != nil {
		return nil, err
	}
	if c.mon, err = parseCronField(f[3], 1, 12); err != nil {
		return nil, err
	}
	if c.dow, err = parseCronField(f[4], 0, 6); err != nil {
		return nil, err
	}
	return &c, nil
}

func (f cronField) has(v int) bool { return f.any || f.vals[v] }

func (c *cronSpec) matches(t time.Time) bool {
	if !c.min.has(t.Minute()) || !c.hour.has(t.Hour()) || !c.mon.has(int(t.Month())) {
		return false
	}
	if c.dom.any || c.dow.any {
		return c.dom.has(t.Day()) && c.dow.has(int(t.Weekday()))
	}
	return c.dom.has(t.Day()) || c.dow.has(int(t.Weekday()))
}

func scheduleDue(expr string, t time.Time) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "-" {
		return false
	}
	c, err := parseCron(expr)
	return err == nil && c.matches(t)
}

func validSchedule(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "-" {
		return nil
	}
	_, err := parseCron(expr)
	return err
}

type ArchivedMission struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	GUID       string            `json:"guid"`
	Created    time.Time         `json:"createTime"`
	ArchivedAt time.Time         `json:"archiveTime"`
	Mission    json.RawMessage   `json:"mission"`
	CoT        map[string]string `json:"cot,omitempty"`
}

type missionArchive struct {
	db *store.Collection[ArchivedMission]
	mu sync.Mutex
}

func openMissionArchive(dataDir string) (*missionArchive, error) {
	db, err := store.Open[ArchivedMission](filepath.Join(dataDir, "db", "mission-archive.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &missionArchive{db: db}, nil
}

func (s *Server) missionLastActivity(m Mission, cfg MissionArchiveConfig) time.Time {
	last := m.Created
	contentOnly := cfg.ByNoContentActivity && !cfg.ByNoSubscriptionActivity
	subsOnly := cfg.ByNoSubscriptionActivity && !cfg.ByNoContentActivity
	if !subsOnly {
		if n := len(m.Changes); n > 0 && m.Changes[n-1].Time.After(last) {
			last = m.Changes[n-1].Time
		}
	}
	if !contentOnly {
		for _, sub := range m.Subs {
			if sub.Created.After(last) {
				last = sub.Created
			}
		}
	}
	return last
}

func (s *Server) archiveMission(m Mission) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	cots := map[string]string{}
	prefix := m.Name + "\x00"
	for _, k := range s.missions.cots.Keys() {
		if strings.HasPrefix(k, prefix) {
			if v, ok := s.missions.cots.Get(k); ok {
				cots[strings.TrimPrefix(k, prefix)] = v
			}
		}
	}
	s.archive.mu.Lock()
	defer s.archive.mu.Unlock()
	a := ArchivedMission{ID: nextID(s.archive.db), Name: m.Name, GUID: m.GUID, Created: m.Created, ArchivedAt: time.Now().UTC(), Mission: raw, CoT: cots}
	if err := s.archive.db.Put(strconv.FormatInt(a.ID, 10), a); err != nil {
		return err
	}
	s.missions.db.Delete(s.missions.key(m.Name))
	s.missions.DeleteAllCoT(m.Name)
	s.log.Info("mission archived", "name", m.Name, "id", a.ID)
	return nil
}

func (s *Server) restoreMission(id int64) (Mission, error) {
	s.archive.mu.Lock()
	defer s.archive.mu.Unlock()
	a, ok := s.archive.db.Get(strconv.FormatInt(id, 10))
	if !ok {
		return Mission{}, errors.New("no archived mission with that id")
	}
	var m Mission
	if err := json.Unmarshal(a.Mission, &m); err != nil {
		return m, err
	}
	if _, exists := s.missions.Get(m.Name); exists {
		return m, fmt.Errorf("a mission named %s already exists", m.Name)
	}
	m.addChange(MissionChange{Type: "CHANGE", CreatorUID: s.UID()})
	if err := s.missions.db.Put(m.Name, m); err != nil {
		return m, err
	}
	for uid, xml := range a.CoT {
		s.missions.SetCoT(m.Name, uid, []byte(xml))
	}
	s.archive.db.Delete(strconv.FormatInt(id, 10))
	s.log.Info("mission restored from archive", "name", m.Name, "id", id)
	return m, nil
}

func (s *Server) runMissionArchive() error {
	cfg := s.Config().Retention.Archive
	if s.archive == nil {
		return nil
	}
	if cfg.AfterNoActivityDays > 0 {
		cut := time.Now().Add(-time.Duration(cfg.AfterNoActivityDays * float64(24*time.Hour)))
		for _, m := range s.missions.All() {
			if strings.EqualFold(m.Tool, "citrap") || m.Name == "exchecktemplates" {
				continue
			}
			if s.missionLastActivity(m, cfg).Before(cut) {
				if err := s.archiveMission(m); err != nil {
					s.log.Warn("mission archive failed", "name", m.Name, "err", err)
				}
			}
		}
	}
	if cfg.RemoveAfterDays > 0 {
		cut := time.Now().Add(-time.Duration(cfg.RemoveAfterDays * float64(24*time.Hour)))
		for _, a := range s.archive.db.All() {
			if a.ArchivedAt.Before(cut) {
				s.archive.db.Delete(strconv.FormatInt(a.ID, 10))
				s.log.Info("archived mission removed", "name", a.Name, "id", a.ID)
			}
		}
	}
	return nil
}

func (s *Server) archivedHashes() map[string]bool {
	out := map[string]bool{}
	if s.archive == nil {
		return out
	}
	for _, a := range s.archive.db.All() {
		var m Mission
		if json.Unmarshal(a.Mission, &m) == nil {
			for _, c := range m.Contents {
				out[c.Hash] = true
			}
		}
	}
	return out
}

func (s *Server) purgeGeoChat(days int) int {
	if days <= 0 || s.history == nil {
		return 0
	}
	cut := time.Now().UTC().AddDate(0, 0, -days)
	today := time.Now().UTC().Format("2006-01-02")
	removed := 0
	entries, _ := os.ReadDir(s.history.dir)
	for _, de := range entries {
		name := de.Name()
		day := strings.TrimSuffix(name, ".jsonl")
		d, err := time.Parse("2006-01-02", day)
		if err != nil || day == today || !d.Before(cut) {
			continue
		}
		s.chatPurgeMu.Lock()
		done := s.chatPurged[name]
		s.chatPurgeMu.Unlock()
		if done {
			continue
		}
		path := filepath.Join(s.history.dir, name)
		n, err := rewriteWithout(path, func(line []byte) bool {
			var hl historyLine
			return json.Unmarshal(line, &hl) == nil && strings.HasPrefix(hl.Y, "b-t-f")
		})
		if err != nil {
			s.log.Warn("chat retention could not rewrite history", "file", name, "err", err)
			continue
		}
		removed += n
		s.chatPurgeMu.Lock()
		if s.chatPurged == nil {
			s.chatPurged = map[string]bool{}
		}
		s.chatPurged[name] = true
		s.chatPurgeMu.Unlock()
	}
	return removed
}

func rewriteWithout(path string, drop func([]byte) bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var buf bytes.Buffer
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	n := 0
	for sc.Scan() {
		if drop(sc.Bytes()) {
			n++
			continue
		}
		buf.Write(sc.Bytes())
		buf.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return 0, err
	}
	f.Close()
	return n, os.Rename(tmp, path)
}

func resourceExempt(res Resource, exempt []string) bool {
	for _, k := range exempt {
		if slices.ContainsFunc(res.Keywords, func(x string) bool { return strings.EqualFold(x, k) }) {
			return true
		}
	}
	return false
}

func hoursPtr(days int) any {
	if days <= 0 {
		return nil
	}
	return days * 24
}

func daysFromHours(v any) (int, bool) {
	switch x := v.(type) {
	case nil:
		return 0, true
	case float64:
		if x <= 0 {
			return 0, true
		}
		return int(math.Ceil(x / 24)), true
	case string:
		if x == "" || x == "null" {
			return 0, true
		}
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, false
		}
		return daysFromHours(f)
	}
	return 0, false
}

func (s *Server) retentionPolicyJSON() map[string]any {
	r := s.Config().Retention
	return map[string]any{"cot": hoursPtr(r.HistoryDays), "files": hoursPtr(r.FileDays), "missionpackages": hoursPtr(r.PackageDays),
		"missions": hoursPtr(r.MissionDays), "geochat": hoursPtr(r.GeoChatDays)}
}

func (s *Server) retentionPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var body map[string]any
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a map of retention hours"))
			return
		}
		_, err := s.UpdateConfig(func(c *Config) error {
			for k, v := range body {
				d, ok := daysFromHours(v)
				if !ok {
					return fmt.Errorf("%s must be a number of hours or null", k)
				}
				switch k {
				case "cot":
					c.Retention.HistoryDays = d
				case "files":
					c.Retention.FileDays = d
				case "missionpackages":
					c.Retention.PackageDays = d
				case "missions":
					c.Retention.MissionDays = d
				case "geochat":
					c.Retention.GeoChatDays = d
				default:
					return fmt.Errorf("unknown retention category %s", k)
				}
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
			return
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("RetentionPolicies", s.retentionPolicyJSON()))
}

func (s *Server) retentionSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		expr := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(body)), `"`))
		if err := validSchedule(expr); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
			return
		}
		if _, err := s.UpdateConfig(func(c *Config) error { c.Retention.Schedule = expr; return nil }); err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
	}
	expr := s.Config().Retention.Schedule
	if expr == "" {
		expr = "0 0 * * * *"
	}
	writeJSON(w, http.StatusOK, s.envelope("RetentionServiceSchedule", expr))
}

func (s *Server) retentionMissionExpiry(w http.ResponseWriter, r *http.Request) {
	t, err := strconv.ParseInt(r.PathValue("time"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "time must be seconds since 1970 or -1"))
		return
	}
	if _, err := s.missions.Update(r.PathValue("name"), func(x *Mission) error { x.Expiration = t; return nil }); err != nil {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "empty mission name or mission not found"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) retentionResourceExpiry(w http.ResponseWriter, r *http.Request) {
	t, err := strconv.ParseInt(r.PathValue("time"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "time must be seconds since 1970 or -1"))
		return
	}
	key := r.PathValue("name")
	n := 0
	for _, res := range s.res.All() {
		if res.Hash == key || res.UID == key || res.Name == key {
			s.res.Update(res.UID, func(x *Resource) { x.Expiration = t })
			n++
		}
	}
	if n == 0 {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such file"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) retentionArchiveList(w http.ResponseWriter, r *http.Request) {
	list := s.archive.db.All()
	slices.SortFunc(list, func(a, b ArchivedMission) int { return b.ArchivedAt.Compare(a.ArchivedAt) })
	out := []map[string]any{}
	for _, a := range list {
		out = append(out, map[string]any{"id": a.ID, "name": a.Name, "guid": a.GUID, "createTime": isoTime(a.Created), "archiveTime": isoTime(a.ArchivedAt), "items": len(a.CoT)})
	}
	b, _ := json.Marshal(out)
	writeJSON(w, http.StatusOK, s.envelope("MissionArchive", string(b)))
}

func (s *Server) retentionRestore(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	id, err := strconv.ParseInt(strings.TrimSpace(strings.Trim(strings.TrimSpace(string(body)), `"`)), 10, 64)
	if err != nil {
		if v := r.URL.Query().Get("id"); v != "" {
			id, err = strconv.ParseInt(v, 10, 64)
		}
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "send the archive id"))
		return
	}
	m, err := s.restoreMission(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("MissionArchiveRestore", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionArchiveRestore", "restored "+m.Name))
}

func (s *Server) missionArchiveConfigJSON() map[string]any {
	a := s.Config().Retention.Archive
	return map[string]any{"cronExpression": firstNonEmpty(a.Schedule, "-"), "archiveMissionByNoContentActivity": a.ByNoContentActivity,
		"archiveMissionByNoSubscriptionActivity": a.ByNoSubscriptionActivity, "timeToArchiveAfterNoActivityDays": a.AfterNoActivityDays, "removeFromArchiveAfterDays": a.RemoveAfterDays}
}

func (s *Server) retentionArchiveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var b struct {
			Cron      *string  `json:"cronExpression"`
			Content   *bool    `json:"archiveMissionByNoContentActivity"`
			Subs      *bool    `json:"archiveMissionByNoSubscriptionActivity"`
			AfterDays *float64 `json:"timeToArchiveAfterNoActivityDays"`
			Remove    *float64 `json:"removeFromArchiveAfterDays"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a mission archive configuration"))
			return
		}
		if b.Cron != nil {
			if err := validSchedule(*b.Cron); err != nil {
				writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
				return
			}
		}
		_, err := s.UpdateConfig(func(c *Config) error {
			a := &c.Retention.Archive
			if b.Cron != nil {
				a.Schedule = strings.TrimSpace(*b.Cron)
			}
			if b.Content != nil {
				a.ByNoContentActivity = *b.Content
			}
			if b.Subs != nil {
				a.ByNoSubscriptionActivity = *b.Subs
			}
			if b.AfterDays != nil {
				a.AfterNoActivityDays = *b.AfterDays
			}
			if b.Remove != nil {
				a.RemoveAfterDays = *b.Remove
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.MissionArchiveConfig", s.missionArchiveConfigJSON()))
}

func (s *Server) retentionRoutes(a func(string, http.HandlerFunc)) {
	a("GET /Marti/api/retention/policy", s.retentionPolicy)
	a("PUT /Marti/api/retention/policy", s.retentionPolicy)
	a("GET /Marti/api/retention/service/schedule", s.retentionSchedule)
	a("PUT /Marti/api/retention/service/schedule", s.retentionSchedule)
	a("PUT /Marti/api/retention/mission/{name}/expiry/{time}", s.retentionMissionExpiry)
	a("PUT /Marti/api/retention/resource/{name}/expiry/{time}", s.retentionResourceExpiry)
	a("GET /Marti/api/retention/missionarchive", s.retentionArchiveList)
	a("POST /Marti/api/retention/restoremission", s.retentionRestore)
	a("GET /Marti/api/retention/missionarchiveconfig", s.retentionArchiveConfig)
	a("PUT /Marti/api/retention/missionarchiveconfig", s.retentionArchiveConfig)
}
