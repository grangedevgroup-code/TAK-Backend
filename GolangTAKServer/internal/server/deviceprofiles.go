package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

const (
	profileTypeConnection = "Connection"
	profileTypeEnrollment = "Enrollment"
	profileTypeTool       = "Tool"
)

type DeviceProfile struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Active            bool      `json:"active"`
	ApplyOnEnrollment bool      `json:"applyOnEnrollment"`
	ApplyOnConnect    bool      `json:"applyOnConnect"`
	Type              string    `json:"type"`
	Updated           time.Time `json:"updated"`
	Tool              string    `json:"tool,omitempty"`
	Groups            []string  `json:"groupNames"`
	Directories       []string  `json:"directories,omitempty"`
}

type DeviceProfileFile struct {
	ID        int64     `json:"id"`
	ProfileID int64     `json:"profileId"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	Updated   time.Time `json:"updated"`
}

type deviceProfileStore struct {
	profiles *store.Collection[DeviceProfile]
	files    *store.Collection[DeviceProfileFile]
}

func openDeviceProfiles(dataDir string) (*deviceProfileStore, error) {
	p, err := store.Open[DeviceProfile](filepath.Join(dataDir, "db", "device-profiles.jsonl"), true)
	if err != nil {
		return nil, err
	}
	f, err := store.Open[DeviceProfileFile](filepath.Join(dataDir, "db", "device-profile-files.jsonl"), true)
	if err != nil {
		p.Close()
		return nil, err
	}
	return &deviceProfileStore{profiles: p, files: f}, nil
}

func (d *deviceProfileStore) Close() {
	d.profiles.Close()
	d.files.Close()
}

func nextID[T any](c *store.Collection[T]) int64 {
	var max int64
	for _, k := range c.Keys() {
		if n, err := strconv.ParseInt(k, 10, 64); err == nil && n > max {
			max = n
		}
	}
	return max + 1
}

func (d *deviceProfileStore) byName(name string) (DeviceProfile, bool) {
	for _, p := range d.profiles.All() {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return DeviceProfile{}, false
}

func (d *deviceProfileStore) filesOf(id int64) []DeviceProfileFile {
	var out []DeviceProfileFile
	for _, f := range d.files.All() {
		if f.ProfileID == id {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) profileDirRoot() string { return filepath.Join(s.DataDir, "profiles") }

func (s *Server) validProfileDirectories() []string {
	root := s.profileDirRoot()
	os.MkdirAll(root, 0o700)
	var out []string
	filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil || !de.IsDir() || p == root {
			return nil
		}
		if rel, err := filepath.Rel(root, p); err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func cleanRelPath(p string) (string, bool) {
	p = path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." || strings.HasPrefix(p, "..") {
		return "", false
	}
	return p, true
}

type profileDirFile struct {
	rel     string
	full    string
	modTime time.Time
}

func (s *Server) profileDirectoryFiles(dirs []string) []profileDirFile {
	root := s.profileDirRoot()
	var out []profileDirFile
	for _, d := range dirs {
		rel, ok := cleanRelPath(d)
		if !ok {
			continue
		}
		base := filepath.Join(root, filepath.FromSlash(rel))
		filepath.WalkDir(base, func(p string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			info, err := de.Info()
			if err != nil {
				return nil
			}
			r, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			out = append(out, profileDirFile{rel: filepath.ToSlash(r), full: p, modTime: info.ModTime()})
			return nil
		})
	}
	return out
}

func (s *Server) profileApplies(p DeviceProfile, groups []string) bool {
	if !p.Active {
		return false
	}
	if len(p.Groups) == 0 {
		return true
	}
	for _, g := range p.Groups {
		if containsFold(groups, g) {
			return true
		}
	}
	return false
}

func (s *Server) namedProfileFiles(enrollment bool, tool string, groups []string, cut time.Time) []zipEntry {
	if s.devProfiles == nil {
		return nil
	}
	var out []zipEntry
	for _, p := range s.devProfiles.profiles.All() {
		if !s.profileApplies(p, groups) {
			continue
		}
		switch {
		case tool != "":
			if p.Type != profileTypeTool || !strings.EqualFold(p.Tool, tool) {
				continue
			}
		case p.Type == profileTypeTool:
			continue
		case enrollment && !p.ApplyOnEnrollment:
			continue
		case !enrollment && !p.ApplyOnConnect:
			continue
		}
		for _, f := range s.devProfiles.filesOf(p.ID) {
			if !cut.IsZero() && f.Updated.Before(cut) && p.Updated.Before(cut) {
				continue
			}
			if data, err := s.res.blobs.Read(f.Hash); err == nil {
				out = append(out, zipEntry{safeFileName(f.Name), data})
			}
		}
		for _, df := range s.profileDirectoryFiles(p.Directories) {
			if !cut.IsZero() && df.modTime.Before(cut) {
				continue
			}
			if data, err := os.ReadFile(df.full); err == nil {
				out = append(out, zipEntry{df.rel, data})
			}
		}
	}
	return out
}

func (s *Server) profileJSON(p DeviceProfile) map[string]any {
	groups := p.Groups
	if groups == nil {
		groups = []string{}
	}
	return map[string]any{
		"id": p.ID, "name": p.Name, "active": p.Active, "applyOnEnrollment": p.ApplyOnEnrollment, "applyOnConnect": p.ApplyOnConnect,
		"type": p.Type, "updated": isoTime(p.Updated), "tool": p.Tool, "groupNames": groups, "groupVector": s.groupVector(groups),
	}
}

func (s *Server) groupVector(groups []string) string {
	mask := s.dir.Mask(groups)
	var b strings.Builder
	for i := 0; i < len(mask)*64; i++ {
		if mask.Has(i) {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return strings.TrimRight(b.String(), "0")
}

func (s *Server) profileFileJSON(f DeviceProfileFile) map[string]any {
	return map[string]any{"id": f.ID, "profileId": f.ProfileID, "name": f.Name, "size": f.Size}
}

func (s *Server) loadDeviceProfile(w http.ResponseWriter, r *http.Request) (DeviceProfile, bool) {
	p, ok := s.devProfiles.byName(r.PathValue("name"))
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no profile named "+r.PathValue("name")))
	}
	return p, ok
}

func (s *Server) saveDeviceProfile(p DeviceProfile) error {
	p.Updated = time.Now().UTC()
	return s.devProfiles.profiles.Put(strconv.FormatInt(p.ID, 10), p)
}

func (s *Server) devProfileList(w http.ResponseWriter, r *http.Request) {
	list := s.devProfiles.profiles.All()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	out := []map[string]any{}
	for _, p := range list {
		out = append(out, s.profileJSON(p))
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.device.profile.model.Profile", out))
}

func (s *Server) devProfileGet(w http.ResponseWriter, r *http.Request) {
	if p, ok := s.loadDeviceProfile(w, r); ok {
		writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.device.profile.model.Profile", s.profileJSON(p)))
	}
}

func (s *Server) devProfileCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || len(name) > 128 {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "invalid profile name"))
		return
	}
	if _, exists := s.devProfiles.byName(name); exists {
		writeJSON(w, http.StatusConflict, s.envelope("error", "a profile with that name already exists"))
		return
	}
	q := r.URL.Query()
	var groups []string
	for _, g := range q["group"] {
		groups = append(groups, splitList(g)...)
	}
	p := DeviceProfile{ID: nextID(s.devProfiles.profiles), Name: name, Active: true, Type: firstNonEmpty(q.Get("type"), profileTypeConnection), Groups: groups, Tool: q.Get("tool")}
	if p.Type == profileTypeEnrollment {
		p.ApplyOnEnrollment = true
	} else if p.Type == profileTypeConnection {
		p.ApplyOnConnect = true
	}
	if err := s.saveDeviceProfile(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	p, _ = s.devProfiles.byName(name)
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.device.profile.model.Profile", s.profileJSON(p)))
}

func (s *Server) devProfileUpdate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		Name              *string   `json:"name"`
		Active            *bool     `json:"active"`
		ApplyOnEnrollment *bool     `json:"applyOnEnrollment"`
		ApplyOnConnect    *bool     `json:"applyOnConnect"`
		Type              *string   `json:"type"`
		Tool              *string   `json:"tool"`
		Groups            *[]string `json:"groupNames"`
		GroupsAlt         *[]string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a JSON profile"))
		return
	}
	if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
		if other, exists := s.devProfiles.byName(*body.Name); exists && other.ID != p.ID {
			writeJSON(w, http.StatusConflict, s.envelope("error", "a profile with that name already exists"))
			return
		}
		p.Name = strings.TrimSpace(*body.Name)
	}
	if body.Active != nil {
		p.Active = *body.Active
	}
	if body.ApplyOnEnrollment != nil {
		p.ApplyOnEnrollment = *body.ApplyOnEnrollment
	}
	if body.ApplyOnConnect != nil {
		p.ApplyOnConnect = *body.ApplyOnConnect
	}
	if body.Type != nil && *body.Type != "" {
		p.Type = *body.Type
	}
	if body.Tool != nil {
		p.Tool = *body.Tool
	}
	if body.Groups != nil {
		p.Groups = *body.Groups
	} else if body.GroupsAlt != nil {
		p.Groups = *body.GroupsAlt
	}
	if err := s.saveDeviceProfile(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.device.profile.model.Profile", s.profileJSON(p)))
}

func (s *Server) devProfileDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("name")
	p, ok := s.devProfiles.profiles.Get(key)
	if !ok {
		if p, ok = s.devProfiles.byName(key); !ok {
			writeJSON(w, http.StatusNotFound, s.envelope("error", "no such profile"))
			return
		}
	}
	for _, f := range s.devProfiles.filesOf(p.ID) {
		s.devProfiles.files.Delete(strconv.FormatInt(f.ID, 10))
	}
	s.devProfiles.profiles.Delete(strconv.FormatInt(p.ID, 10))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) devProfileFiles(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return
	}
	out := []map[string]any{}
	for _, f := range s.devProfiles.filesOf(p.ID) {
		out = append(out, s.profileFileJSON(f))
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.device.profile.model.ProfileFile", out))
}

func (s *Server) devProfileAddFile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return
	}
	name := safeFileName(r.URL.Query().Get("filename"))
	if r.URL.Query().Get("filename") == "" {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "filename is required"))
		return
	}
	hash, size, err := s.res.blobs.Put(r.Body, s.uploadLimit())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	f := DeviceProfileFile{ID: nextID(s.devProfiles.files), ProfileID: p.ID, Name: name, Hash: hash, Size: size, Updated: time.Now().UTC()}
	for _, old := range s.devProfiles.filesOf(p.ID) {
		if old.Name == name {
			f.ID = old.ID
		}
	}
	if err := s.devProfiles.files.Put(strconv.FormatInt(f.ID, 10), f); err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	s.saveDeviceProfile(p)
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.device.profile.model.ProfileFile", s.profileFileJSON(f)))
}

func (s *Server) loadProfileFile(w http.ResponseWriter, r *http.Request) (DeviceProfile, DeviceProfileFile, bool) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return p, DeviceProfileFile{}, false
	}
	f, ok := s.devProfiles.files.Get(r.PathValue("id"))
	if !ok || f.ProfileID != p.ID {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such file in this profile"))
		return p, f, false
	}
	return p, f, true
}

func (s *Server) devProfileGetFile(w http.ResponseWriter, r *http.Request) {
	_, f, ok := s.loadProfileFile(w, r)
	if !ok {
		return
	}
	fh, err := s.res.blobs.Open(f.Hash)
	if err != nil {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "file data missing"))
		return
	}
	defer fh.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFileName(f.Name)+`"`)
	http.ServeContent(w, r, f.Name, f.Updated, fh)
}

func (s *Server) devProfileDeleteFile(w http.ResponseWriter, r *http.Request) {
	p, f, ok := s.loadProfileFile(w, r)
	if !ok {
		return
	}
	s.devProfiles.files.Delete(strconv.FormatInt(f.ID, 10))
	s.saveDeviceProfile(p)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) devProfileValidDirectories(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", s.validProfileDirectories()))
}

func (s *Server) devProfileDirectories(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodDelete:
		p.Directories = nil
		s.saveDeviceProfile(p)
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPut:
		valid := s.validProfileDirectories()
		var dirs []string
		for _, d := range splitList(r.PathValue("dirs")) {
			rel, ok := cleanRelPath(d)
			if !ok || !slices.Contains(valid, rel) {
				writeJSON(w, http.StatusBadRequest, s.envelope("error", "not a profile directory: "+d))
				return
			}
			dirs = append(dirs, rel)
		}
		p.Directories = dirs
		s.saveDeviceProfile(p)
	}
	dirs := p.Directories
	if dirs == nil {
		dirs = []string{}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", dirs))
}

func (s *Server) profilePackage(p DeviceProfile) ([]byte, error) {
	files := s.devProfiles.filesOf(p.ID)
	var entries []zipEntry
	for _, f := range files {
		if data, err := s.res.blobs.Read(f.Hash); err == nil {
			entries = append(entries, zipEntry{safeFileName(f.Name), data})
		}
	}
	for _, df := range s.profileDirectoryFiles(p.Directories) {
		if data, err := os.ReadFile(df.full); err == nil {
			entries = append(entries, zipEntry{df.rel, data})
		}
	}
	if len(entries) == 0 {
		return nil, errors.New("the profile has no files")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return buildZip(append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifestXML(cot.NewUID(), p.Name, true, names))}}, entries...))
}

func (s *Server) devProfileMissionPackage(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return
	}
	data, err := s.profilePackage(p)
	if err != nil {
		writeJSON(w, http.StatusNotFound, s.envelope("error", err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFileName(p.Name)+`.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		return
	}
	w.Write(data)
}

func (s *Server) devProfileSend(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadDeviceProfile(w, r)
	if !ok {
		return
	}
	var to []string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&to); err != nil || len(to) == 0 {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a JSON list of client UIDs"))
		return
	}
	data, err := s.profilePackage(p)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	if _, err := s.pushPackage(r, safeFileName(p.Name)+".zip", p.Name, data, p.Groups, to); err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) pushPackage(r *http.Request, fileName, label string, data []byte, groups, to []string) (Resource, error) {
	hash, size, err := s.res.blobs.Put(bytes.NewReader(data), s.uploadLimit())
	if err != nil {
		return Resource{}, err
	}
	id := identityOf(r)
	submitter := s.Config().Name
	if id != nil && id.Name != "" {
		submitter = id.Name
	}
	res := Resource{UID: hash, Hash: hash, Name: fileName, MIMEType: "application/zip", Size: size, Keywords: []string{"missionpackage"}, Tool: "public",
		CreatorUID: s.UID(), Submitter: submitter, Submitted: time.Now().UTC(), Groups: groups, Expiration: -1, Package: true}
	if old, ok := s.res.db.Get(hash); ok {
		res.Key = old.Key
	}
	if err := s.res.Put(res); err != nil {
		return res, err
	}
	url := s.contentURL(r, hash)
	e := cot.New(cot.NewUID(), "b-f-t-r", "h-e", 10*time.Minute)
	e.Point.Hae = 0
	e.Detail.AddNew("fileshare", "filename", fileName, "senderUrl", url, "sizeInBytes", itoa(int(size)), "sha256", hash,
		"senderUid", s.UID(), "senderCallsign", s.Config().Name, "name", label)
	e.Detail.AddNew("ackrequest", "uid", cot.NewUID(), "ackrequested", "true", "tag", fileName)
	dests := make([]cot.Dest, 0, len(to))
	for _, t := range to {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if s.hub.ByUID(t) == nil && s.hub.ByCallsign(t) != nil {
			dests = append(dests, cot.Dest{Callsign: t})
		} else {
			dests = append(dests, cot.Dest{UID: t})
		}
	}
	e.SetDests(dests)
	msg := NewMessage(e, nil, nil)
	msg.Everyone = true
	msg.NoReplay = true
	s.hub.Publish(msg)
	return res, nil
}

func (s *Server) martiToolProfileFile(w http.ResponseWriter, r *http.Request) {
	tool := strings.TrimSpace(r.PathValue("tool"))
	q := r.URL.Query()
	var cut time.Time
	if n, err := parseInt64(q.Get("syncSecago")); err == nil && n > 0 {
		cut = time.Now().Add(-time.Duration(n) * time.Second)
	}
	groups := s.clientGroups(r, q.Get("clientUid"))
	want := map[string]bool{}
	for _, v := range q["relativePath"] {
		for _, p := range splitList(v) {
			if rel, ok := cleanRelPath(p); ok {
				want[rel] = true
			}
		}
	}
	var entries []zipEntry
	if s.devProfiles != nil {
		for _, p := range s.devProfiles.profiles.All() {
			if p.Type != profileTypeTool || !strings.EqualFold(p.Tool, tool) || !s.profileApplies(p, groups) {
				continue
			}
			for _, df := range s.profileDirectoryFiles(p.Directories) {
				if (len(want) > 0 && !want[df.rel]) || (!cut.IsZero() && df.modTime.Before(cut)) {
					continue
				}
				if data, err := os.ReadFile(df.full); err == nil {
					entries = append(entries, zipEntry{df.rel, data})
				}
			}
			for _, f := range s.devProfiles.filesOf(p.ID) {
				if (len(want) > 0 && !want[f.Name]) || (!cut.IsZero() && f.Updated.Before(cut)) {
					continue
				}
				if data, err := s.res.blobs.Read(f.Hash); err == nil {
					entries = append(entries, zipEntry{safeFileName(f.Name), data})
				}
			}
		}
	}
	if len(entries) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	data, err := buildZip(append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifestXML(cot.NewUID(), s.Config().Name+" "+tool+" files", true, names))}}, entries...))
	if err != nil {
		writeText(w, http.StatusInternalServerError, "could not build the package")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="profile.zip"`)
	w.Write(data)
}

func (s *Server) clientGroups(r *http.Request, clientUID string) []string {
	if c := s.hub.ByUID(clientUID); c != nil {
		return s.dir.Names(c.OutMask())
	}
	if id := identityOf(r); id != nil {
		return s.identityGroups(id)
	}
	return nil
}

func (s *Server) deviceProfileRoutes(m, a func(string, http.HandlerFunc)) {
	a("GET /Marti/api/device/profile", s.devProfileList)
	a("GET /Marti/api/device/profile/directories", s.devProfileValidDirectories)
	a("GET /Marti/api/device/profile/{name}", s.devProfileGet)
	a("POST /Marti/api/device/profile/{name}", s.devProfileCreate)
	a("PUT /Marti/api/device/profile/{name}", s.devProfileUpdate)
	a("DELETE /Marti/api/device/profile/{name}", s.devProfileDelete)
	a("GET /Marti/api/device/profile/{name}/files", s.devProfileFiles)
	a("PUT /Marti/api/device/profile/{name}/file", s.devProfileAddFile)
	a("GET /Marti/api/device/profile/{name}/file/{id}", s.devProfileGetFile)
	a("DELETE /Marti/api/device/profile/{name}/file/{id}", s.devProfileDeleteFile)
	a("GET /Marti/api/device/profile/{name}/directories", s.devProfileDirectories)
	a("DELETE /Marti/api/device/profile/{name}/directories", s.devProfileDirectories)
	a("PUT /Marti/api/device/profile/{name}/directories/{dirs}", s.devProfileDirectories)
	a("POST /Marti/api/device/profile/{name}/send", s.devProfileSend)
	m("GET /Marti/api/device/profile/{name}/missionpackage", s.devProfileMissionPackage)
	m("HEAD /Marti/api/device/profile/{name}/missionpackage", s.devProfileMissionPackage)
	m("GET /Marti/api/device/profile/tool/{tool}/file", s.martiToolProfileFile)
	m("GET /Marti/api/tls/profile/tool/{tool}/file", s.martiToolProfileFile)
}
