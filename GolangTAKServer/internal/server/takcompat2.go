package server

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

type certEntry struct {
	User string
	Rec  CertRecord
}

func certID(serial string) int64 {
	sum := sha256.Sum256([]byte(strings.ToLower(serial)))
	n, _ := strconv.ParseInt(hex.EncodeToString(sum[:6]), 16, 64)
	return n
}

func (s *Server) allCerts() []certEntry {
	var out []certEntry
	for _, u := range s.dir.Users() {
		for _, c := range u.Certs {
			out = append(out, certEntry{User: u.Name, Rec: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rec.Created.After(out[j].Rec.Created) })
	return out
}

func (s *Server) replacedSet(all []certEntry) map[string]bool {
	latest := map[string]time.Time{}
	for _, e := range all {
		if e.Rec.ClientUID == "" {
			continue
		}
		k := e.User + "\x00" + e.Rec.ClientUID
		if e.Rec.Created.After(latest[k]) {
			latest[k] = e.Rec.Created
		}
	}
	out := map[string]bool{}
	for _, e := range all {
		if e.Rec.ClientUID == "" {
			continue
		}
		if e.Rec.Created.Before(latest[e.User+"\x00"+e.Rec.ClientUID]) {
			out[e.Rec.Serial] = true
		}
	}
	return out
}

func (s *Server) certJSON(e certEntry) map[string]any {
	c := e.Rec
	out := map[string]any{
		"id": certID(c.Serial), "creatorDn": firstNonEmpty(c.Issuer, "CN="+s.Config().Name+" CA"), "subjectDn": firstNonEmpty(c.Subject, "CN="+e.User),
		"userDn": e.User, "hash": c.Hash, "clientUid": c.ClientUID, "issuanceDate": isoTime(c.Created), "effectiveDate": isoTime(c.Created),
		"expirationDate": isoTime(c.Expires), "token": "", "serialNumber": c.Serial, "certificate": "",
	}
	if len(c.DER) > 0 {
		out["certificate"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER}))
	}
	if c.Revoked {
		out["revocationDate"] = isoTime(firstTime(c.RevokedAt, c.Created))
	}
	return out
}

func firstTime(a, b time.Time) time.Time {
	if !a.IsZero() {
		return a
	}
	return b
}

func (s *Server) findCerts(keys []string) []certEntry {
	var out []certEntry
	for _, e := range s.allCerts() {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if strings.EqualFold(e.Rec.Hash, k) || strings.EqualFold(e.Rec.Serial, k) || strconv.FormatInt(certID(e.Rec.Serial), 10) == k {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

func (s *Server) martiCertAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	a, b := r.PathValue("a"), r.PathValue("b")
	all := s.allCerts()
	list := func(keep func(certEntry) bool) {
		out := []map[string]any{}
		for _, e := range all {
			if keep(e) {
				out = append(out, s.certJSON(e))
			}
		}
		writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.groups.Certificate", out))
	}
	now := time.Now()
	if r.Method == http.MethodGet {
		switch {
		case a == "":
			user := r.URL.Query().Get("username")
			list(func(e certEntry) bool { return user == "" || e.User == user })
		case a == "active" && b == "":
			replaced := s.replacedSet(all)
			list(func(e certEntry) bool { return !e.Rec.Revoked && e.Rec.Expires.After(now) && !replaced[e.Rec.Serial] })
		case a == "revoked" && b == "":
			list(func(e certEntry) bool { return e.Rec.Revoked })
		case a == "expired" && b == "":
			list(func(e certEntry) bool { return !e.Rec.Expires.After(now) })
		case a == "replaced" && b == "":
			replaced := s.replacedSet(all)
			list(func(e certEntry) bool { return replaced[e.Rec.Serial] })
		case a == "download" && b != "":
			s.downloadCerts(w, s.findCerts(strings.Split(b, ",")))
		case b == "download":
			s.downloadCerts(w, s.findCerts([]string{a}))
		case b == "":
			found := s.findCerts([]string{a})
			if len(found) == 0 {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
				return
			}
			writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.groups.Certificate", s.certJSON(found[0])))
		default:
			s.martiUnknown(w, r)
		}
		return
	}
	var targets []certEntry
	del := true
	switch {
	case a == "revoke" && b != "":
		targets, del = s.findCerts(strings.Split(b, ",")), false
	case a == "delete" && b != "":
		targets = s.findCerts(strings.Split(b, ","))
	case b == "":
		targets = s.findCerts([]string{a})
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	var errs []error
	for _, e := range targets {
		errs = append(errs, s.dir.RevokeCert(e.Rec.Serial))
		s.dropCertClients(e.Rec.Serial)
		if del {
			_, err := s.dir.UpdateUser(e.User, func(u *User) error {
				for i := range u.Certs {
					if u.Certs[i].Serial == e.Rec.Serial {
						u.Certs = append(u.Certs[:i], u.Certs[i+1:]...)
						break
					}
				}
				return nil
			})
			errs = append(errs, err)
		}
		s.log.Info("certificate revoked through the TAK certificate API", "serial", e.Rec.Serial, "user", e.User, "deleted", del, "by", identityOf(r).Name)
	}
	if err := errors.Join(errs...); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) downloadCerts(w http.ResponseWriter, list []certEntry) {
	var withDER []certEntry
	for _, e := range list {
		if len(e.Rec.DER) > 0 {
			withDER = append(withDER, e)
		}
	}
	if len(withDER) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found or issued before certificates were kept"})
		return
	}
	if len(withDER) == 1 {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(withDER[0].User)+`.pem"`)
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: withDER[0].Rec.DER}))
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="certificates.zip"`)
	zw := zip.NewWriter(w)
	for _, e := range withDER {
		f, err := zw.Create(safeFilename(e.User) + "-" + e.Rec.Serial + ".pem")
		if err != nil {
			return
		}
		f.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.Rec.DER}))
	}
	zw.Close()
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeFilename(s string) string {
	s = unsafeChars.ReplaceAllString(s, "_")
	if s == "" {
		return "certificate"
	}
	return s
}

type Injector struct {
	ID       string `json:"id"`
	UID      string `json:"uid"`
	ToInject string `json:"toInject"`
}

type Injectors struct {
	db *store.Collection[Injector]
}

func OpenInjectors(dataDir string) (*Injectors, error) {
	db, err := store.Open[Injector](filepath.Join(dataDir, "db", "injectors.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &Injectors{db: db}, nil
}

func (in *Injectors) Close() { in.db.Close() }

func injectorID(uid, x string) string {
	sum := sha256.Sum256([]byte(uid + "\x00" + x))
	return hex.EncodeToString(sum[:12])
}

func (s *Server) injectorsFor(uid string) []Injector {
	var out []Injector
	for _, in := range s.injectors.db.All() {
		if uid == "" || in.UID == uid {
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID+out[i].ToInject < out[j].UID+out[j].ToInject })
	return out
}

func parseFragment(x string) ([]*xmltree.Node, error) {
	n, err := xmltree.Parse([]byte("<x>" + x + "</x>"))
	if err != nil {
		return nil, err
	}
	return n.Children, nil
}

func (s *Server) applyInjectors(m *Message) {
	if s.injectors == nil || m.Event == nil || m.Event.UID == "" {
		return
	}
	list := s.injectorsFor(m.Event.UID)
	if len(list) == 0 || m.Event.Detail == nil {
		return
	}
	for _, in := range list {
		nodes, err := parseFragment(in.ToInject)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			m.Event.Detail.RemoveAll(n.Name)
			m.Event.Detail.Add(n.Clone())
		}
	}
}

func (s *Server) martiInjectors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		out := []map[string]string{}
		for _, in := range s.injectorsFor(r.PathValue("uid")) {
			out = append(out, map[string]string{"uid": in.UID, "toInject": in.ToInject})
		}
		writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.injector.InjectorConfig", out))
	case http.MethodPost, http.MethodPut:
		if !s.requireAdmin(w, r) {
			return
		}
		var in Injector
		if err := readJSON(r, &in); err != nil || in.UID == "" || in.ToInject == "" || len(in.ToInject) > 8192 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected uid and toInject up to 8 KB"})
			return
		}
		if _, err := parseFragment(in.ToInject); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "toInject must be well-formed XML: " + err.Error()})
			return
		}
		in.ID = injectorID(in.UID, in.ToInject)
		s.injectors.db.Put(in.ID, in)
		writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.injector.InjectorConfig", []map[string]string{{"uid": in.UID, "toInject": in.ToInject}}))
	case http.MethodDelete:
		if !s.requireAdmin(w, r) {
			return
		}
		q := r.URL.Query()
		uid, x := firstNonEmpty(q.Get("uid"), r.PathValue("uid")), q.Get("toInject")
		removed := 0
		for _, in := range s.injectorsFor(uid) {
			if x == "" || in.ToInject == x {
				s.injectors.db.Delete(in.ID)
				removed++
			}
		}
		if removed == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no injector matched"})
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		s.martiUnknown(w, r)
	}
}

type LocateConfig struct {
	Enabled bool   `json:"enabled"`
	Public  bool   `json:"public"`
	CotType string `json:"cotType"`
	Group   string `json:"group"`
	Mission string `json:"mission"`
}

var locateLimiter = newLimiter(60, 10*time.Minute)

var locateUnsafe = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func (s *Server) locatePost(w http.ResponseWriter, r *http.Request) {
	lc := s.Config().Locate
	if !lc.Enabled {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "locate is turned off on this server"})
		return
	}
	id := identityOf(r)
	if !lc.Public && (id == nil || id.Anon) {
		w.Header().Set("WWW-Authenticate", `Basic realm="GolangTAKServer"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign in to report a location"})
		return
	}
	if locateLimiter.blocked(requestIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many reports, try again shortly"})
		return
	}
	locateLimiter.fail(requestIP(r))
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	r.ParseForm()
	lat, err1 := strconv.ParseFloat(r.Form.Get("latitude"), 64)
	lon, err2 := strconv.ParseFloat(r.Form.Get("longitude"), 64)
	name := strings.TrimSpace(r.Form.Get("name"))
	if err1 != nil || err2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 || name == "" || len(name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "latitude, longitude and a name up to 80 characters are required"})
		return
	}
	remarks := r.Form.Get("remarks")
	if len(remarks) > 2000 {
		remarks = remarks[:2000]
	}
	e := cot.New("locate-"+strings.ToLower(locateUnsafe.ReplaceAllString(name, "-")), firstNonEmpty(lc.CotType, "a-f-G"), "h-e", 24*time.Hour)
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	if acc, err := strconv.ParseFloat(r.Form.Get("accuracy"), 64); err == nil && acc > 0 {
		e.Point.Ce = acc
	}
	e.Detail.AddNew("contact", "callsign", name)
	if remarks != "" {
		e.Detail.AddNew("remarks").Text = remarks
	}
	e.Detail.AddNew("archive")
	m := NewMessage(e, nil, nil)
	if lc.Group == "" {
		m.Everyone = true
	} else {
		if _, err := s.dir.EnsureGroup(lc.Group, "Locate reports", false); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		m.Groups = s.dir.Mask([]string{lc.Group})
	}
	if lc.Mission != "" {
		e.SetDests([]cot.Dest{{Mission: lc.Mission}})
		s.ensureSystemMission(lc.Mission, "Locate reports", nil)
	}
	s.hub.Publish(m)
	if lc.Mission != "" {
		e2 := e.Clone()
		e2.SetDests(nil)
		m2 := NewMessage(e2, nil, m.Groups)
		m2.Everyone = m.Everyone
		s.hub.Publish(m2)
	}
	s.log.Info("location reported", "name", name, "remote", requestIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"uid": e.UID})
}

func (s *Server) locatePage(w http.ResponseWriter, r *http.Request) {
	if !s.Config().Locate.Enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
	w.Write([]byte(locateHTML))
}

const locateHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share your location</title>
<style>
:root{color-scheme:light dark;--bg:#f4f4f3;--panel:#fff;--text:#1d1d20;--muted:#5d5d63;--line:rgba(20,20,22,.17);--btn:#232326;--btnfg:#f7f7f7}
@media (prefers-color-scheme:dark){:root{--bg:#1c1c1f;--panel:#232326;--text:#f2f2f2;--muted:#a3a3a8;--line:rgba(255,255,255,.16);--btn:#f2f2f2;--btnfg:#161618}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px}
main{width:min(420px,100%);background:var(--panel);border:1px solid var(--line);padding:24px}
h1{font-size:20px;margin:0 0 6px}p{color:var(--muted);margin:0 0 18px}label{display:block;font-weight:600;margin:12px 0 4px}
input,textarea{width:100%;padding:10px;border:1px solid var(--line);background:transparent;color:inherit;font:inherit;border-radius:0}
button{margin-top:18px;width:100%;padding:12px;border:0;background:var(--btn);color:var(--btnfg);font:inherit;font-weight:600;cursor:pointer;border-radius:0}
#status{margin-top:14px;min-height:24px}
</style></head><body><main>
<h1>Share your location</h1><p>Your position goes to the response team's map. Allow location access when your browser asks.</p>
<form id="f"><label for="name">Your name</label><input id="name" required maxlength="80" autocomplete="name">
<label for="remarks">Message (optional)</label><textarea id="remarks" rows="3" maxlength="2000"></textarea>
<button type="submit">Send my location</button></form><div id="status" role="status"></div>
</main><script>
var f=document.getElementById("f"),st=document.getElementById("status");
f.addEventListener("submit",function(ev){ev.preventDefault();
if(!navigator.geolocation){st.textContent="This browser cannot share a location.";return}
st.textContent="Finding your location...";
navigator.geolocation.getCurrentPosition(function(p){
var b=new URLSearchParams({latitude:p.coords.latitude,longitude:p.coords.longitude,accuracy:p.coords.accuracy||0,name:document.getElementById("name").value,remarks:document.getElementById("remarks").value});
fetch("locate/api",{method:"POST",body:b,credentials:"same-origin"}).then(function(r){st.textContent=r.ok?"Sent. Keep this page open and send again if you move.":"The server did not accept the report ("+r.status+")."}).catch(function(){st.textContent="Could not reach the server."});
},function(e){st.textContent="Location unavailable: "+e.message},{enableHighAccuracy:true,timeout:20000,maximumAge:0})});
</script></body></html>`

func (s *Server) filesConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"uploadSizeLimit": s.Config().Limits.MaxUploadMB})
}

func (s *Server) filesCount(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	n := 0
	for _, res := range s.res.All() {
		if s.resourceVisible(id, res) {
			n++
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Integer", n))
}

func (s *Server) syncMetadata(w http.ResponseWriter, r *http.Request) {
	res, ok := s.res.Get(r.PathValue("hash"))
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no file with that hash"})
		return
	}
	writeJSON(w, http.StatusOK, legacyMetadata(res))
}

func (s *Server) missionContentsList(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	out := []map[string]any{}
	for _, c := range m.Contents {
		out = append(out, s.contentJSON(c))
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionContent", out))
}
