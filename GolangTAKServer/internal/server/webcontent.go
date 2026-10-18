package server

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

type ContentAccessRule struct {
	Folder string   `json:"folder"`
	Groups []string `json:"groups,omitempty"`
}

func (s *Server) webContentDir() string {
	d := firstNonEmpty(s.Config().Web.ContentDir, "webcontent")
	if filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(s.DataDir, d)
}

func contentRule(rules []ContentAccessRule, p string) (ContentAccessRule, bool) {
	best, found := ContentAccessRule{}, false
	for _, r := range rules {
		f := "/" + strings.Trim(strings.TrimSpace(r.Folder), "/")
		if f == "/" {
			continue
		}
		if (p == f || strings.HasPrefix(p, f+"/")) && len(f) > len("/"+strings.Trim(best.Folder, "/")) {
			best, found = r, true
		}
	}
	return best, found
}

func (s *Server) webContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if strings.ContainsAny(r.URL.Path, "\\\x00") {
		http.NotFound(w, r)
		return
	}
	p := path.Clean("/" + r.URL.Path)
	if rule, ok := contentRule(s.Config().Web.ContentAccess, p); ok {
		id, _, err := s.resolveIdentity(r)
		if err != nil || id == nil || id.Anon {
			deny(w, r, "sign in to open this page")
			return
		}
		if len(rule.Groups) > 0 && !id.Admin && !slices.ContainsFunc(s.identityGroups(id), func(g string) bool { return slices.Contains(rule.Groups, g) }) {
			writeText(w, http.StatusForbidden, "your groups do not include this page")
			return
		}
	}
	dir := s.webContentDir()
	full := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(p, "/")))
	if rel, err := filepath.Rel(dir, full); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if st.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, path.Base(p)+"/", http.StatusMovedPermanently)
			return
		}
		full = filepath.Join(full, "index.html")
		if st, err = os.Stat(full); err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
	}
	f, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}
