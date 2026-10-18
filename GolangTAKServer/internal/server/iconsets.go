package server

import (
	"archive/zip"
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

type IconRecord struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Hash  string `json:"hash"`
	Mime  string `json:"mime"`
}

type Iconset struct {
	UID             string       `json:"uid"`
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	DefaultFriendly string       `json:"defaultFriendly,omitempty"`
	DefaultHostile  string       `json:"defaultHostile,omitempty"`
	DefaultNeutral  string       `json:"defaultNeutral,omitempty"`
	DefaultUnknown  string       `json:"defaultUnknown,omitempty"`
	SelectedGroup   string       `json:"selectedGroup,omitempty"`
	SkipResize      bool         `json:"skipResize,omitempty"`
	Icons           []IconRecord `json:"icons"`
	Uploaded        time.Time    `json:"uploaded"`
}

type iconStore struct {
	sets  *store.Collection[Iconset]
	blobs *store.Blobs
	mu    sync.Mutex
	cache map[string][]byte
}

func openIconsets(dataDir string) (*iconStore, error) {
	sets, err := store.Open[Iconset](filepath.Join(dataDir, "db", "iconsets.jsonl"), true)
	if err != nil {
		return nil, err
	}
	blobs, err := store.OpenBlobs(filepath.Join(dataDir, "iconsets"))
	if err != nil {
		sets.Close()
		return nil, err
	}
	return &iconStore{sets: sets, blobs: blobs, cache: map[string][]byte{}}, nil
}

func parseIconsetZip(data []byte, blobs *store.Blobs) (Iconset, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Iconset{}, errors.New("the iconset is not a zip file")
	}
	var set Iconset
	var meta *xmltree.Node
	for _, f := range zr.File {
		if strings.EqualFold(path.Base(f.Name), "iconset.xml") {
			rc, err := f.Open()
			if err != nil {
				return set, err
			}
			b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
			rc.Close()
			if meta, err = xmltree.Parse(b); err != nil {
				return set, errors.New("iconset.xml could not be read")
			}
		}
	}
	if meta == nil || meta.Attr("uid") == "" {
		return set, errors.New("the zip has no iconset.xml with a uid")
	}
	set = Iconset{UID: meta.Attr("uid"), Name: firstNonEmpty(meta.Attr("name"), meta.Attr("uid")), Version: meta.Attr("version"),
		DefaultFriendly: meta.Attr("default_friendly"), DefaultHostile: meta.Attr("default_hostile"), DefaultNeutral: meta.Attr("default_neutral"),
		DefaultUnknown: meta.Attr("default_unknown"), SelectedGroup: meta.Attr("selected_group"), SkipResize: strings.EqualFold(meta.Attr("skipResize"), "true"),
		Uploaded: time.Now().UTC(), Icons: []IconRecord{}}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > 4<<20 {
			continue
		}
		ext := strings.ToLower(path.Ext(f.Name))
		if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".gif" && ext != ".svg" && ext != ".bmp" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if err != nil {
			continue
		}
		hash, err := blobs.PutBytes(b)
		if err != nil {
			return set, err
		}
		dir := path.Dir(strings.ReplaceAll(f.Name, "\\", "/"))
		group := path.Base(dir)
		if dir == "." {
			group = ""
		}
		set.Icons = append(set.Icons, IconRecord{Group: group, Name: path.Base(f.Name), Hash: hash, Mime: firstNonEmpty(mime.TypeByExtension(ext), "image/png")})
	}
	sort.Slice(set.Icons, func(i, j int) bool {
		return set.Icons[i].Group+"/"+set.Icons[i].Name < set.Icons[j].Group+"/"+set.Icons[j].Name
	})
	return set, nil
}

func (s *Server) iconsetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	var data []byte
	if f, _, err := r.FormFile("file"); err == nil {
		data, _ = io.ReadAll(f)
		f.Close()
	} else {
		data, _ = io.ReadAll(r.Body)
	}
	if len(data) == 0 {
		writeText(w, http.StatusBadRequest, "You failed to upload because the file was empty.")
		return
	}
	set, err := parseIconsetZip(data, s.icons.blobs)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.icons.sets.Put(set.UID, set); err != nil {
		writeText(w, http.StatusInternalServerError, "Error saving file")
		return
	}
	s.log.Info("iconset uploaded", "uid", set.UID, "name", set.Name, "icons", len(set.Icons))
	writeText(w, http.StatusOK, "You successfully uploaded "+set.Name)
}

func (s *Server) iconsetUIDs(w http.ResponseWriter, r *http.Request) {
	uids := s.icons.sets.Keys()
	sort.Strings(uids)
	if uids == nil {
		uids = []string{}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", uids))
}

func (s *Server) iconURLBase(r *http.Request) string {
	return s.baseURL(r) + "/Marti/api/icon/"
}

func (s *Server) iconsetURLs(w http.ResponseWriter, r *http.Request) {
	set, ok := s.icons.sets.Get(r.PathValue("uid"))
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "Invalid request: uid: "+r.PathValue("uid")))
		return
	}
	out := []string{}
	for _, ic := range set.Icons {
		out = append(out, s.iconURLBase(r)+url.PathEscape(set.UID)+"/"+url.PathEscape(firstNonEmpty(ic.Group, "_"))+"/"+url.PathEscape(ic.Name))
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", out))
}

func (s *Server) findIcon(uid, group, name string) (IconRecord, bool) {
	set, ok := s.icons.sets.Get(uid)
	if !ok {
		return IconRecord{}, false
	}
	if group == "_" {
		group = ""
	}
	for _, ic := range set.Icons {
		if strings.EqualFold(ic.Name, name) && (group == "" || strings.EqualFold(ic.Group, group)) {
			return ic, true
		}
	}
	return IconRecord{}, false
}

func (s *Server) serveIcon(w http.ResponseWriter, ic IconRecord) {
	data, err := s.icons.blobs.Read(ic.Hash)
	if err != nil {
		writeText(w, http.StatusNotFound, "icon missing")
		return
	}
	w.Header().Set("Content-Type", ic.Mime)
	w.Header().Set("Cache-Control", "max-age=86400")
	w.Write(data)
}

func (s *Server) iconGet(w http.ResponseWriter, r *http.Request) {
	ic, ok := s.findIcon(r.PathValue("uid"), r.PathValue("group"), r.PathValue("name"))
	if !ok {
		writeText(w, http.StatusNotFound, "no such icon")
		return
	}
	s.serveIcon(w, ic)
}

func splitIconsetPath(p string) (uid, group, name string, ok bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch len(parts) {
	case 2:
		return parts[0], "", parts[1], true
	case 3:
		return parts[0], parts[1], parts[2], true
	}
	return "", "", "", false
}

func iconQueryKey(q url.Values) string {
	keys := []string{"cotType", "medevac", "groupName", "role", "color"}
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + q.Get(k) + "&")
	}
	return b.String()
}

func (s *Server) iconURL(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if p := q.Get("iconsetpath"); p != "" {
		if uid, group, name, ok := splitIconsetPath(p); ok {
			if _, found := s.findIcon(uid, group, name); found {
				writeText(w, http.StatusOK, s.iconURLBase(r)+url.PathEscape(uid)+"/"+url.PathEscape(firstNonEmpty(group, "_"))+"/"+url.PathEscape(name))
				return
			}
		}
	}
	if q.Get("cotType") == "" && q.Get("groupName") == "" && q.Get("color") == "" && !boolParam(r, "medevac") {
		writeText(w, http.StatusBadRequest, "not enough information to construct an image url")
		return
	}
	rel := s.baseURL(r)
	if boolParam(r, "relative") {
		rel = ""
	}
	writeText(w, http.StatusOK, rel+"/Marti/api/iconimage?"+q.Encode())
}

func (s *Server) iconImage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if p := q.Get("iconsetpath"); p != "" {
		if uid, group, name, ok := splitIconsetPath(p); ok {
			if ic, found := s.findIcon(uid, group, name); found {
				s.serveIcon(w, ic)
				return
			}
		}
	}
	key := iconQueryKey(q)
	s.icons.mu.Lock()
	data, ok := s.icons.cache[key]
	s.icons.mu.Unlock()
	if !ok {
		var buf bytes.Buffer
		png.Encode(&buf, renderTypeIcon(q.Get("cotType"), q.Get("groupName"), q.Get("color"), boolParam(r, "medevac")))
		data = buf.Bytes()
		s.icons.mu.Lock()
		if len(s.icons.cache) > 512 {
			s.icons.cache = map[string][]byte{}
		}
		s.icons.cache[key] = data
		s.icons.mu.Unlock()
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "max-age=86400")
	w.Write(data)
}

var teamColors = map[string]color.RGBA{
	"white": {255, 255, 255, 255}, "yellow": {255, 255, 0, 255}, "orange": {255, 119, 0, 255}, "magenta": {255, 0, 255, 255},
	"red": {255, 0, 0, 255}, "maroon": {127, 0, 0, 255}, "purple": {127, 0, 127, 255}, "dark blue": {0, 0, 127, 255},
	"blue": {0, 0, 255, 255}, "cyan": {0, 255, 255, 255}, "teal": {0, 127, 127, 255}, "green": {0, 255, 0, 255},
	"dark green": {0, 127, 0, 255}, "brown": {165, 42, 42, 255},
}

func renderTypeIcon(cotType, team, argb string, medevac bool) image.Image {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	fill := color.RGBA{255, 255, 128, 255}
	shape := "circle"
	parts := strings.Split(cotType, "-")
	if len(parts) > 1 && parts[0] == "a" {
		switch parts[1] {
		case "f", "a":
			fill, shape = color.RGBA{128, 224, 255, 255}, "rect"
		case "h", "s", "j", "k":
			fill, shape = color.RGBA{255, 128, 128, 255}, "diamond"
		case "n":
			fill, shape = color.RGBA{170, 255, 170, 255}, "square"
		}
	}
	if c, ok := teamColors[strings.ToLower(team)]; ok {
		fill, shape = c, "circle"
	}
	if argb != "" {
		var v int64
		for _, ch := range strings.TrimPrefix(argb, "-") {
			if ch < '0' || ch > '9' {
				v = -1
				break
			}
			v = v*10 + int64(ch-'0')
		}
		if v >= 0 {
			if strings.HasPrefix(argb, "-") {
				v = -v
			}
			u := uint32(int32(v))
			fill = color.RGBA{uint8(u >> 16), uint8(u >> 8), uint8(u), 255}
		}
	}
	black := color.RGBA{0, 0, 0, 255}
	c := float64(n-1) / 2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-c, float64(y)-c
			var inside, edge bool
			switch shape {
			case "rect":
				inside = math.Abs(dx) <= 14 && math.Abs(dy) <= 10
				edge = inside && (math.Abs(dx) > 12.5 || math.Abs(dy) > 8.5)
			case "diamond":
				d := math.Abs(dx) + math.Abs(dy)
				inside, edge = d <= 15, d > 13
			case "square":
				inside = math.Abs(dx) <= 12 && math.Abs(dy) <= 12
				edge = inside && (math.Abs(dx) > 10.5 || math.Abs(dy) > 10.5)
			default:
				d := math.Hypot(dx, dy)
				inside, edge = d <= 14, d > 12.5
			}
			switch {
			case edge:
				img.Set(x, y, black)
			case inside:
				img.Set(x, y, fill)
			}
		}
	}
	if medevac {
		red := color.RGBA{220, 0, 0, 255}
		for i := 9; i <= 22; i++ {
			for j := 13; j <= 18; j++ {
				img.Set(i, j, red)
				img.Set(j, i, red)
			}
		}
	}
	return img
}

func (s *Server) iconRoutes(m, a func(string, http.HandlerFunc)) {
	a("POST /Marti/api/iconset", s.iconsetPost)
	m("GET /Marti/api/iconset/all/uid", s.iconsetUIDs)
	m("GET /Marti/api/iconseturl/{uid}", s.iconsetURLs)
	m("GET /Marti/api/icon/{uid}/{group}/{name}", s.iconGet)
	m("GET /Marti/api/iconurl", s.iconURL)
	m("GET /Marti/api/iconimage", s.iconImage)
}
