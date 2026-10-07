package server

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/store"
)

type ProfileItem struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Key        string    `json:"key,omitempty"`
	Class      string    `json:"class,omitempty"`
	Value      string    `json:"value,omitempty"`
	Name       string    `json:"name,omitempty"`
	Hash       string    `json:"hash,omitempty"`
	Enrollment bool      `json:"enrollment"`
	Connection bool      `json:"connection"`
	ClientUID  string    `json:"clientUid,omitempty"`
	Group      string    `json:"group,omitempty"`
	Updated    time.Time `json:"updated"`
}

type Plugin struct {
	ID          string    `json:"id"`
	Platform    string    `json:"platform"`
	Type        string    `json:"type"`
	Package     string    `json:"package"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Revision    string    `json:"revision"`
	File        string    `json:"file"`
	Hash        string    `json:"hash"`
	Size        int64     `json:"size"`
	Icon        string    `json:"icon,omitempty"`
	IconHash    string    `json:"iconHash,omitempty"`
	Description string    `json:"description"`
	OSRequired  string    `json:"osRequired"`
	TAKPrereq   string    `json:"takPrereq"`
	ATAKVersion string    `json:"atakVersion,omitempty"`
	Enrollment  bool      `json:"enrollment"`
	Connection  bool      `json:"connection"`
	Updated     time.Time `json:"updated"`
}

type Profiles struct {
	items   *store.Collection[ProfileItem]
	plugins *store.Collection[Plugin]
}

func OpenProfiles(dataDir string) (*Profiles, error) {
	items, err := store.Open[ProfileItem](filepath.Join(dataDir, "db", "profiles.jsonl"), true)
	if err != nil {
		return nil, err
	}
	plugins, err := store.Open[Plugin](filepath.Join(dataDir, "db", "plugins.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &Profiles{items: items, plugins: plugins}, nil
}

func (p *Profiles) Close() {
	p.items.Close()
	p.plugins.Close()
}

func (p *Profiles) Items() []ProfileItem { return p.items.All() }

func (p *Profiles) PutItem(it ProfileItem) (ProfileItem, error) {
	if it.ID == "" {
		it.ID = cot.NewUID()
	}
	if it.Kind == "" {
		it.Kind = "pref"
	}
	if it.Class == "" && it.Kind == "pref" {
		it.Class = "String"
	}
	it.Updated = time.Now().UTC()
	return it, p.items.Put(it.ID, it)
}

func (p *Profiles) DeleteItem(id string) error { return p.items.Delete(id) }

func (p *Profiles) Plugins() []Plugin {
	list := p.plugins.All()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func (p *Profiles) PutPlugin(pl Plugin) (Plugin, error) {
	if pl.ID == "" {
		pl.ID = cot.NewUID()
	}
	pl.Updated = time.Now().UTC()
	return pl, p.plugins.Put(pl.ID, pl)
}

func (p *Profiles) DeletePlugin(id string) error { return p.plugins.Delete(id) }

type profileBundle struct {
	prefs []prefEntry
	files []zipEntry
}

func javaClass(c string) string {
	switch strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(c, "class "), "java.lang.")) {
	case "boolean":
		return "class java.lang.Boolean"
	case "integer", "int":
		return "class java.lang.Integer"
	case "long":
		return "class java.lang.Long"
	case "float", "double":
		return "class java.lang.Float"
	}
	return "class java.lang.String"
}

func (s *Server) profileEntries(enrollment bool, clientUID string, secago int64) profileBundle {
	var b profileBundle
	if s.profiles == nil {
		return b
	}
	cut := time.Time{}
	if secago > 0 {
		cut = time.Now().Add(-time.Duration(secago) * time.Second)
	}
	var groups []string
	if clientUID != "" {
		if c := s.hub.ByUID(clientUID); c != nil {
			groups = s.dir.Names(c.OutMask())
		}
	}
	for _, it := range s.profiles.Items() {
		if (enrollment && !it.Enrollment) || (!enrollment && !it.Connection) {
			continue
		}
		if it.ClientUID != "" && it.ClientUID != clientUID {
			continue
		}
		if it.Group != "" && !containsFold(groups, it.Group) {
			continue
		}
		if !cut.IsZero() && it.Updated.Before(cut) {
			continue
		}
		switch it.Kind {
		case "file":
			if data, err := s.res.blobs.Read(it.Hash); err == nil {
				b.files = append(b.files, zipEntry{safeFileName(it.Name), data})
			}
		default:
			b.prefs = append(b.prefs, prefEntry{Key: it.Key, Class: javaClass(it.Class), Value: it.Value})
		}
	}
	for _, pl := range s.profiles.Plugins() {
		if (enrollment && !pl.Enrollment) || (!enrollment && !pl.Connection) {
			continue
		}
		if !cut.IsZero() && pl.Updated.Before(cut) {
			continue
		}
		if data, err := s.res.blobs.Read(pl.Hash); err == nil {
			b.files = append(b.files, zipEntry{safeFileName(pl.File), data})
		}
	}
	for _, res := range s.res.All() {
		if (enrollment && res.Enrollment) || (!enrollment && res.Connection) {
			if !cut.IsZero() && res.Submitted.Before(cut) {
				continue
			}
			if data, err := s.res.blobs.Read(res.Hash); err == nil {
				b.files = append(b.files, zipEntry{safeFileName(res.Name), data})
			}
		}
	}
	return b
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func (s *Server) productInf(atakVersion string) ([]byte, []Plugin) {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	var used []Plugin
	for _, pl := range s.profiles.Plugins() {
		if atakVersion != "" && pl.ATAKVersion != "" && pl.ATAKVersion != atakVersion {
			continue
		}
		icon := pl.Icon
		cw.Write([]string{
			firstNonEmpty(pl.Platform, "Android"), firstNonEmpty(pl.Type, "plugin"), pl.Package, pl.Name, pl.Version,
			firstNonEmpty(pl.Revision, "1"), pl.File, icon, pl.Description, pl.Hash, pl.OSRequired, pl.TAKPrereq,
			strconv.FormatInt(pl.Size, 10),
		})
		used = append(used, pl)
	}
	cw.Flush()
	return buf.Bytes(), used
}

func (s *Server) packagesProductInfz(w http.ResponseWriter, r *http.Request) {
	inf, used := s.productInf(r.PathValue("atak"))
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, _ := zw.Create("product.inf")
	fw.Write(inf)
	for _, pl := range used {
		if pl.Icon == "" || pl.IconHash == "" {
			continue
		}
		if data, err := s.res.blobs.Read(pl.IconHash); err == nil {
			iw, err := zw.Create(safeFileName(pl.Icon))
			if err == nil {
				iw.Write(data)
			}
		}
	}
	zw.Close()
	w.Header().Set("Content-Type", "application/zip")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
		return
	}
	w.Write(buf.Bytes())
}

func (s *Server) packagesProductInf(w http.ResponseWriter, r *http.Request) {
	inf, _ := s.productInf(r.PathValue("atak"))
	w.Header().Set("Content-Type", "text/plain")
	w.Write(inf)
}

func (s *Server) packagesRepositories(w http.ResponseWriter, r *http.Request) {
	seen := map[string]bool{}
	var out []string
	for _, pl := range s.profiles.Plugins() {
		if pl.ATAKVersion != "" && !seen[pl.ATAKVersion] {
			seen[pl.ATAKVersion] = true
			out = append(out, pl.ATAKVersion)
		}
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeText(w, http.StatusOK, strings.Join(out, "\n")+"\n")
}

func (s *Server) packagesFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	for _, pl := range s.profiles.Plugins() {
		if pl.File == name || pl.Icon == name {
			hash := pl.Hash
			ct := "application/vnd.android.package-archive"
			if pl.Icon == name {
				hash, ct = pl.IconHash, "image/png"
			}
			f, err := s.res.blobs.Open(hash)
			if err != nil {
				break
			}
			defer f.Close()
			st, _ := f.Stat()
			w.Header().Set("Content-Type", ct)
			http.ServeContent(w, r, name, st.ModTime(), f)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) packagesList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.profiles.Plugins())
}
