package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type Resource struct {
	UID        string    `json:"uid"`
	Hash       string    `json:"hash"`
	Name       string    `json:"name"`
	MIMEType   string    `json:"mimeType"`
	Size       int64     `json:"size"`
	Keywords   []string  `json:"keywords"`
	Tool       string    `json:"tool"`
	CreatorUID string    `json:"creatorUid"`
	Submitter  string    `json:"submitter"`
	Submitted  time.Time `json:"submitted"`
	Groups     []string  `json:"groups"`
	Expiration int64     `json:"expiration"`
	Lat        float64   `json:"lat,omitempty"`
	Lon        float64   `json:"lon,omitempty"`
	Alt        float64   `json:"alt,omitempty"`
	Key        int64     `json:"primaryKey"`
	Package    bool      `json:"package"`
	Enrollment bool      `json:"enrollment,omitempty"`
	Connection bool      `json:"connection,omitempty"`
}

type Resources struct {
	db    *store.Collection[Resource]
	blobs *store.Blobs
	next  atomic.Int64
}

func OpenResources(dir string) (*Resources, error) {
	db, err := store.Open[Resource](filepath.Join(dir, "db", "resources.jsonl"), true)
	if err != nil {
		return nil, err
	}
	blobs, err := store.OpenBlobs(filepath.Join(dir, "files"))
	if err != nil {
		return nil, err
	}
	r := &Resources{db: db, blobs: blobs}
	var max int64
	for _, res := range db.All() {
		if res.Key > max {
			max = res.Key
		}
	}
	r.next.Store(max)
	return r, nil
}

func (rs *Resources) Close() { rs.db.Close() }

func (rs *Resources) Blobs() *store.Blobs { return rs.blobs }

func (rs *Resources) Get(key string) (Resource, bool) {
	if r, ok := rs.db.Get(key); ok {
		return r, true
	}
	low := strings.ToLower(key)
	if store.ValidHash(low) {
		var best Resource
		found := false
		for _, r := range rs.db.All() {
			if r.Hash == low && (!found || r.Submitted.After(best.Submitted)) {
				best, found = r, true
			}
		}
		return best, found
	}
	return Resource{}, false
}

func (rs *Resources) All() []Resource {
	all := rs.db.All()
	sort.Slice(all, func(i, j int) bool { return all[i].Submitted.After(all[j].Submitted) })
	return all
}

func (rs *Resources) Put(r Resource) error {
	if r.Key == 0 {
		r.Key = rs.next.Add(1)
	}
	return rs.db.Put(r.UID, r)
}

func (rs *Resources) Delete(uid string) error {
	r, ok := rs.db.Get(uid)
	if !ok {
		return store.ErrNotFound
	}
	if err := rs.db.Delete(uid); err != nil {
		return err
	}
	for _, other := range rs.db.All() {
		if other.Hash == r.Hash {
			return nil
		}
	}
	return rs.blobs.Delete(r.Hash)
}

func (rs *Resources) Update(uid string, fn func(r *Resource)) (Resource, error) {
	return rs.db.Update(uid, func(r Resource, ok bool) (Resource, bool, error) {
		if !ok {
			return r, false, store.ErrNotFound
		}
		fn(&r)
		return r, true, nil
	})
}

func (s *Server) resourceVisible(id *Identity, r Resource) bool {
	if id == nil {
		return false
	}
	if id.Admin || len(r.Groups) == 0 {
		return true
	}
	if !id.Anon && id.Name == r.Submitter {
		return true
	}
	return s.visibleTo(id, s.dir.Mask(r.Groups))
}

func (s *Server) identityGroups(id *Identity) []string {
	if id == nil {
		return []string{s.dir.AnonGroup()}
	}
	g := s.dir.Names(id.In)
	if len(g) == 0 {
		g = []string{s.dir.AnonGroup()}
	}
	return g
}

func (s *Server) uploadLimit() int64 {
	return int64(s.Config().Limits.MaxUploadMB) << 20
}

var errNoFile = errors.New("no file found in the upload")

func (s *Server) readUpload(w http.ResponseWriter, r *http.Request) (io.Reader, string, string, func(), error) {
	r.Body = http.MaxBytesReader(w, r.Body, s.uploadLimit()+1<<20)
	ct := r.Header.Get("Content-Type")
	mt, _, _ := mime.ParseMediaType(ct)
	if strings.HasPrefix(mt, "multipart/") {
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, "", "", nil, err
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			if part.FormName() == "assetfile" || part.FormName() == "resource" || part.FileName() != "" {
				return part, path.Base(strings.ReplaceAll(part.FileName(), "\\", "/")), part.Header.Get("Content-Type"), func() { part.Close() }, nil
			}
			part.Close()
		}
		return nil, "", "", nil, errNoFile
	}
	if mt == "application/x-www-form-urlencoded" {
		return nil, "", "", nil, errNoFile
	}
	return r.Body, "", mt, func() {}, nil
}

func (s *Server) storeUpload(w http.ResponseWriter, r *http.Request, defaults Resource) (Resource, int, error) {
	src, fname, ctype, done, err := s.readUpload(w, r)
	if err != nil {
		return Resource{}, http.StatusBadRequest, err
	}
	defer done()
	hash, size, err := s.res.blobs.Put(src, s.uploadLimit())
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) || strings.Contains(err.Error(), "larger than") {
			return Resource{}, http.StatusRequestEntityTooLarge, err
		}
		return Resource{}, http.StatusBadRequest, err
	}
	res := defaults
	if res.Name == "" {
		res.Name = fname
	}
	res.Name = safeFileName(firstNonEmpty(res.Name, hash[:12]))
	res.Hash = hash
	res.Size = size
	if res.MIMEType == "" {
		res.MIMEType = firstNonEmpty(ctype, mime.TypeByExtension(strings.ToLower(path.Ext(res.Name))), "application/octet-stream")
	}
	if res.UID == "" {
		res.UID = hash
	}
	if res.Submitted.IsZero() {
		res.Submitted = time.Now().UTC()
	}
	if res.Expiration == 0 {
		res.Expiration = -1
	}
	if old, ok := s.res.db.Get(res.UID); ok {
		res.Key = old.Key
	}
	if err := s.res.Put(res); err != nil {
		return Resource{}, http.StatusInternalServerError, err
	}
	stored, _ := s.res.db.Get(res.UID)
	return stored, http.StatusOK, nil
}

func (s *Server) contentURL(r *http.Request, uid string) string {
	return s.baseURL(r) + "/Marti/sync/content?hash=" + uid
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) martiMissionUpload(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	hash := strings.ToLower(strings.TrimSpace(q.Get("hash")))
	def := Resource{
		Name:       q.Get("filename"),
		MIMEType:   firstNonEmpty(q.Get("mimetype"), "application/x-zip-compressed"),
		Keywords:   splitList(firstNonEmpty(q.Get("keyword"), q.Get("keywords"), "missionpackage")),
		Tool:       firstNonEmpty(q.Get("tool"), "public"),
		CreatorUID: firstNonEmpty(q.Get("creatorUid"), q.Get("CreatorUid")),
		Submitter:  id.Name,
		Groups:     s.identityGroups(id),
		Package:    true,
	}
	if g := q["groups"]; len(g) > 0 {
		def.Groups = g
	}
	if hash != "" {
		def.UID = hash
	}
	if def.Name != "" && !strings.Contains(def.Name, ".") {
		def.Name += ".zip"
	}
	res, code, err := s.storeUpload(w, r, def)
	if err != nil {
		writeText(w, code, "upload failed: "+err.Error())
		return
	}
	if hash != "" && store.ValidHash(hash) && hash != res.Hash {
		s.log.Warn("uploaded package hash differs from the hash the client sent", "client", hash, "actual", res.Hash)
	}
	s.log.Info("data package uploaded", "name", res.Name, "user", id.Name, "size", res.Size, "uid", res.UID)
	writeText(w, http.StatusOK, s.contentURL(r, res.UID))
}

func (s *Server) martiMissionQuery(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("hash")
	res, ok := s.res.Get(key)
	if !ok || !s.res.blobs.Exists(res.Hash) || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	writeText(w, http.StatusOK, s.contentURL(r, res.UID))
}

func (s *Server) martiSyncUpload(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	def := Resource{
		Name:       q.Get("name"),
		Keywords:   append(splitList(q.Get("keywords")), q["keyword"]...),
		Tool:       firstNonEmpty(q.Get("tool"), "public"),
		CreatorUID: firstNonEmpty(q.Get("creatorUid"), q.Get("CreatorUid")),
		Submitter:  id.Name,
		Groups:     s.identityGroups(id),
		UID:        firstNonEmpty(q.Get("uid"), cot.NewUID()),
	}
	if def.Keywords == nil {
		def.Keywords = []string{}
	}
	def.Lat, _ = strconv.ParseFloat(q.Get("latitude"), 64)
	def.Lon, _ = strconv.ParseFloat(q.Get("longitude"), 64)
	def.Alt, _ = strconv.ParseFloat(q.Get("altitude"), 64)
	res, code, err := s.storeUpload(w, r, def)
	if err != nil {
		writeText(w, code, "upload failed: "+err.Error())
		return
	}
	s.log.Info("file uploaded", "name", res.Name, "user", id.Name, "size", res.Size)
	writeJSON(w, http.StatusOK, legacyMetadata(res))
}

func legacyMetadata(r Resource) map[string]any {
	kw := r.Keywords
	if kw == nil {
		kw = []string{}
	}
	return map[string]any{
		"UID":                r.UID,
		"Name":               r.Name,
		"Hash":               r.Hash,
		"CreatorUid":         r.CreatorUID,
		"SubmissionDateTime": isoTime(r.Submitted),
		"SubmissionUser":     r.Submitter,
		"EXPIRATION":         strconv.FormatInt(r.Expiration, 10),
		"Keywords":           kw,
		"MIMEType":           r.MIMEType,
		"Size":               strconv.FormatInt(r.Size, 10),
		"PrimaryKey":         strconv.FormatInt(r.Key, 10),
		"Tool":               firstNonEmpty(r.Tool, "public"),
		"Latitude":           strconv.FormatFloat(r.Lat, 'f', -1, 64),
		"Longitude":          strconv.FormatFloat(r.Lon, 'f', -1, 64),
		"Altitude":           strconv.FormatFloat(r.Alt, 'f', -1, 64),
		"Groups":             r.Groups,
	}
}

func resourceJSON(r Resource) map[string]any {
	kw := r.Keywords
	if kw == nil {
		kw = []string{}
	}
	groups := r.Groups
	if groups == nil {
		groups = []string{}
	}
	return map[string]any{
		"filename":       r.Name,
		"keywords":       kw,
		"mimeType":       r.MIMEType,
		"name":           r.Name,
		"submissionTime": isoTime(r.Submitted),
		"submitter":      r.Submitter,
		"uid":            r.UID,
		"creatorUid":     r.CreatorUID,
		"hash":           r.Hash,
		"size":           r.Size,
		"tool":           firstNonEmpty(r.Tool, "public"),
		"groups":         groups,
		"expiration":     r.Expiration,
		"latitude":       r.Lat,
		"longitude":      r.Lon,
		"altitude":       r.Alt,
	}
}

func (s *Server) searchResources(r *http.Request) []Resource {
	q := r.URL.Query()
	id := identityOf(r)
	keywords := append(splitList(q.Get("keywords")), q["keyword"]...)
	tool := q.Get("tool")
	name := firstNonEmpty(q.Get("name"), q.Get("filename"))
	uid := q.Get("uid")
	hash := strings.ToLower(q.Get("hash"))
	mimeType := q.Get("mimetype")
	creator := q.Get("creatorUid")
	var out []Resource
	for _, res := range s.res.All() {
		if !s.resourceVisible(id, res) {
			continue
		}
		if tool != "" && !strings.EqualFold(firstNonEmpty(res.Tool, "public"), tool) {
			continue
		}
		if uid != "" && res.UID != uid {
			continue
		}
		if hash != "" && res.Hash != hash {
			continue
		}
		if name != "" && !strings.Contains(strings.ToLower(res.Name), strings.ToLower(name)) {
			continue
		}
		if mimeType != "" && res.MIMEType != mimeType {
			continue
		}
		if creator != "" && res.CreatorUID != creator {
			continue
		}
		if len(keywords) > 0 {
			match := false
			for _, k := range keywords {
				if slices.ContainsFunc(res.Keywords, func(x string) bool { return strings.EqualFold(x, k) }) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		out = append(out, res)
	}
	return out
}

func (s *Server) martiSyncSearch(w http.ResponseWriter, r *http.Request) {
	list := s.searchResources(r)
	results := make([]map[string]any, 0, len(list))
	for _, res := range list {
		results = append(results, legacyMetadata(res))
	}
	writeJSON(w, http.StatusOK, map[string]any{"resultCount": len(results), "results": results})
}

func (s *Server) martiAPISyncSearch(w http.ResponseWriter, r *http.Request) {
	list := s.searchResources(r)
	data := make([]map[string]any, 0, len(list))
	for _, res := range list {
		data = append(data, resourceJSON(res))
	}
	writeJSON(w, http.StatusOK, s.envelope("Resource", data))
}

func (s *Server) serveResource(w http.ResponseWriter, r *http.Request, key string) {
	res, ok := s.res.Get(key)
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	f, err := s.res.blobs.Open(res.Hash)
	if err != nil {
		writeText(w, http.StatusNotFound, "File content missing")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", firstNonEmpty(res.MIMEType, "application/octet-stream"))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": res.Name}))
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("ETag", `"`+res.Hash+`"`)
	http.ServeContent(w, r, res.Name, st.ModTime(), f)
}

func (s *Server) martiSyncContent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := firstNonEmpty(q.Get("hash"), q.Get("uid"))
	if key == "" {
		writeText(w, http.StatusBadRequest, "hash or uid is required")
		return
	}
	s.serveResource(w, r, key)
}

func (s *Server) martiSyncContentPut(w http.ResponseWriter, r *http.Request) {
	s.martiSyncUpload(w, r)
}

func (s *Server) canEdit(id *Identity, res Resource) bool {
	return id != nil && (id.Admin || (!id.Anon && id.Name == res.Submitter) || (id.Anon && res.Submitter == ""))
}

func (s *Server) martiMetadataTool(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("hash")
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.serveResource(w, r, key)
		return
	}
	res, ok := s.res.Get(key)
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	tool := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(body)), `"`))
	if tool == "" {
		tool = "public"
	}
	if !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusForbidden, "only the submitter or an administrator can change this file")
		return
	}
	s.res.Update(res.UID, func(x *Resource) { x.Tool = tool })
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiMetadataKeywords(w http.ResponseWriter, r *http.Request) {
	res, ok := s.res.Get(r.PathValue("hash"))
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	var kws []string
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&kws); err != nil {
		writeText(w, http.StatusBadRequest, "expected a JSON list of keywords")
		return
	}
	s.res.Update(res.UID, func(x *Resource) {
		for _, k := range kws {
			if !slices.Contains(x.Keywords, k) {
				x.Keywords = append(x.Keywords, k)
			}
		}
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiMetadataExpiration(w http.ResponseWriter, r *http.Request) {
	res, ok := s.res.Get(r.PathValue("hash"))
	if !ok || !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	exp, err := parseInt64(r.URL.Query().Get("expiration"))
	if err != nil {
		writeText(w, http.StatusBadRequest, "expiration must be seconds since 1970 or -1")
		return
	}
	s.res.Update(res.UID, func(x *Resource) { x.Expiration = exp })
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiFileGet(w http.ResponseWriter, r *http.Request) {
	s.serveResource(w, r, r.PathValue("hash"))
}

func (s *Server) martiFileDelete(w http.ResponseWriter, r *http.Request) {
	key := firstNonEmpty(r.PathValue("hash"), r.URL.Query().Get("hash"), r.URL.Query().Get("uid"))
	res, ok := s.res.Get(key)
	if !ok {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	if !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusForbidden, "only the submitter or an administrator can delete this file")
		return
	}
	if err := s.res.Delete(res.UID); err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("file deleted", "name", res.Name, "by", identityOf(r).Name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiFilesMetadata(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	var data []map[string]any
	for _, res := range s.res.All() {
		if !s.resourceVisible(id, res) {
			continue
		}
		if boolParam(r, "missionPackage") && !res.Package {
			continue
		}
		if n := q.Get("name"); n != "" && !strings.Contains(strings.ToLower(res.Name), strings.ToLower(n)) {
			continue
		}
		data = append(data, map[string]any{
			"Name": res.Name, "User": res.Submitter, "Creator": res.CreatorUID, "Size": res.Size,
			"Time": isoTime(res.Submitted), "MimeType": res.MIMEType, "Keywords": res.Keywords,
			"Expiration": res.Expiration, "Hash": res.Hash, "UID": res.UID, "Tool": res.Tool,
		})
	}
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, s.envelope("Resource", data))
}

func (s *Server) expireResources() {
	now := time.Now().Unix()
	fileDays := s.Config().Retention.FileDays
	for _, res := range s.res.All() {
		if res.Expiration > 0 && res.Expiration < now {
			s.res.Delete(res.UID)
			s.log.Info("expired file removed", "name", res.Name)
			continue
		}
		if fileDays > 0 && !res.Enrollment && !res.Connection && time.Since(res.Submitted) > time.Duration(fileDays)*24*time.Hour && !s.missionUsesHash(res.Hash) {
			s.res.Delete(res.UID)
			s.log.Info("old file removed by retention policy", "name", res.Name)
		}
	}
}
