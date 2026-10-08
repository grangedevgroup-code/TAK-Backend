package server

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
)

type userView struct {
	Name      string       `json:"name"`
	Admin     bool         `json:"admin"`
	Disabled  bool         `json:"disabled"`
	In        []string     `json:"in"`
	Out       []string     `json:"out"`
	Inactive  []string     `json:"inactive"`
	Callsign  string       `json:"callsign"`
	Team      string       `json:"team"`
	TeamRole  string       `json:"teamRole"`
	Note      string       `json:"note"`
	Created   time.Time    `json:"created"`
	LastLogin time.Time    `json:"lastLogin"`
	Certs     []CertRecord `json:"certs"`
	External  bool         `json:"external"`
	Online    int          `json:"online"`
	Password  bool         `json:"hasPassword"`
}

func (s *Server) viewUser(u User) userView {
	online := 0
	for _, c := range s.hub.Clients() {
		if c.User() == u.Name {
			online++
		}
	}
	nz := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	certs := u.Certs
	if certs == nil {
		certs = []CertRecord{}
	}
	return userView{Name: u.Name, Admin: u.Admin, Disabled: u.Disabled, In: nz(u.In), Out: nz(u.Out), Inactive: nz(u.Inactive),
		Callsign: u.Callsign, Team: u.Team, TeamRole: u.TeamRole, Note: u.Note, Created: u.Created, LastLogin: u.LastLogin,
		Certs: certs, External: u.External, Online: online, Password: u.Hash != ""}
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	out := []userView{}
	for _, u := range s.dir.Users() {
		if u.Name == SelfTestUser {
			continue
		}
		out = append(out, s.viewUser(u))
	}
	writeJSON(w, http.StatusOK, out)
}

type userBody struct {
	Name     string    `json:"name"`
	Password string    `json:"password"`
	Admin    *bool     `json:"admin"`
	Disabled *bool     `json:"disabled"`
	Groups   []string  `json:"groups"`
	In       *[]string `json:"in"`
	Out      *[]string `json:"out"`
	Callsign *string   `json:"callsign"`
	Team     *string   `json:"team"`
	TeamRole *string   `json:"teamRole"`
	Note     *string   `json:"note"`
}

func (s *Server) apiUserCreate(w http.ResponseWriter, r *http.Request) {
	var body userBody
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	generated := ""
	if body.Password == "" {
		generated = FriendlySecret()
		body.Password = generated
	}
	admin := body.Admin != nil && *body.Admin
	if _, err := s.dir.AddUser(body.Name, body.Password, admin, body.Groups); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.dir.UpdateUser(body.Name, func(u *User) error {
		if body.Callsign != nil {
			u.Callsign = strings.TrimSpace(*body.Callsign)
		}
		if body.Team != nil {
			u.Team = *body.Team
		}
		if body.TeamRole != nil {
			u.TeamRole = *body.TeamRole
		}
		if body.Note != nil {
			u.Note = *body.Note
		}
		return nil
	})
	s.log.Info("user created", "name", body.Name, "admin", admin, "by", identityOf(r).Name)
	u, _ := s.dir.User(body.Name)
	writeJSON(w, http.StatusOK, map[string]any{"user": s.viewUser(u), "password": generated})
}

func (s *Server) apiUserGet(w http.ResponseWriter, r *http.Request) {
	u, ok := s.dir.User(r.PathValue("name"))
	if !ok {
		apiError(w, http.StatusNotFound, ErrNoUser)
		return
	}
	writeJSON(w, http.StatusOK, s.viewUser(u))
}

func (s *Server) apiUserUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body userBody
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	id := identityOf(r)
	if body.Password != "" {
		if err := s.dir.SetPassword(name, body.Password); err != nil {
			apiError(w, http.StatusBadRequest, err)
			return
		}
		s.forgetInitialPassword(name)
	}
	if body.In != nil || body.Out != nil {
		u, ok := s.dir.User(name)
		if !ok {
			apiError(w, http.StatusNotFound, ErrNoUser)
			return
		}
		in, out := u.In, u.Out
		if body.In != nil {
			in = *body.In
		}
		if body.Out != nil {
			out = *body.Out
		}
		if err := s.dir.SetGroups(name, in, out); err != nil {
			apiError(w, http.StatusBadRequest, err)
			return
		}
	}
	if body.Admin != nil && !*body.Admin && strings.EqualFold(name, id.Name) {
		apiError(w, http.StatusBadRequest, errors.New("you cannot remove your own administrator access"))
		return
	}
	_, err := s.dir.UpdateUser(name, func(u *User) error {
		if body.Admin != nil {
			u.Admin = *body.Admin
		}
		if body.Disabled != nil {
			u.Disabled = *body.Disabled
		}
		if body.Callsign != nil {
			u.Callsign = strings.TrimSpace(*body.Callsign)
		}
		if body.Team != nil {
			u.Team = *body.Team
		}
		if body.TeamRole != nil {
			u.TeamRole = *body.TeamRole
		}
		if body.Note != nil {
			u.Note = *body.Note
		}
		return nil
	})
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if body.Disabled != nil && *body.Disabled {
		s.dir.EndSessions(name)
		for _, c := range s.hub.Clients() {
			if c.User() == name {
				c.Close()
			}
		}
	}
	u, _ := s.dir.User(name)
	writeJSON(w, http.StatusOK, s.viewUser(u))
}

func (s *Server) apiUserDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.EqualFold(name, identityOf(r).Name) {
		apiError(w, http.StatusBadRequest, errors.New("you cannot delete your own account"))
		return
	}
	n, err := s.dir.DeleteUser(name)
	if err != nil {
		apiError(w, http.StatusNotFound, err)
		return
	}
	for _, c := range s.hub.Clients() {
		if c.User() == name {
			c.Close()
		}
	}
	s.log.Info("user deleted", "name", name, "revokedCertificates", n, "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n})
}

func (s *Server) apiUserRevoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	n := s.dir.RevokeAll(name)
	for _, c := range s.hub.Clients() {
		if c.User() == name && c.Kind == KindTLS {
			c.Close()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n})
}

func (s *Server) apiCertRevoke(w http.ResponseWriter, r *http.Request) {
	serial := strings.ToLower(r.PathValue("serial"))
	s.dir.RevokeCert(serial)
	for _, c := range s.hub.Clients() {
		if id := c.Identity(); id != nil && id.Cert != nil && pki.SerialHex(id.Cert) == serial {
			c.Close()
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	type gv struct {
		Group
		Members int `json:"members"`
	}
	out := []gv{}
	users := s.dir.Users()
	for _, g := range s.dir.Groups() {
		n := 0
		for _, u := range users {
			if slices.Contains(u.In, g.Name) || slices.Contains(u.Out, g.Name) {
				n++
			}
		}
		out = append(out, gv{g, n})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiGroupCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	g, err := s.dir.EnsureGroup(body.Name, body.Description, false)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) apiGroupDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.dir.DeleteGroup(r.PathValue("name")); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []Token{}
	for _, t := range s.dir.Tokens() {
		if id.Admin || t.User == id.Name {
			t.Hash = ""
			out = append(out, t)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiTokenCreate(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Name string `json:"name"`
		User string `json:"user"`
		Days int    `json:"days"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	user := firstNonEmpty(body.User, id.Name)
	if !s.canActFor(id, user) {
		apiError(w, http.StatusForbidden, errors.New("you can only create tokens for yourself"))
		return
	}
	ttl := time.Duration(0)
	if body.Days > 0 {
		ttl = time.Duration(body.Days) * 24 * time.Hour
	}
	secret, t, err := s.dir.CreateToken(user, "api", firstNonEmpty(body.Name, "api token"), ttl, 0)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	t.Hash = ""
	writeJSON(w, http.StatusOK, map[string]any{"token": secret, "info": t})
}

func (s *Server) apiTokenDelete(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	tid := r.PathValue("id")
	for _, t := range s.dir.Tokens() {
		if t.ID == tid && (id.Admin || t.User == id.Name) {
			s.dir.DeleteToken(tid)
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
	}
	apiError(w, http.StatusNotFound, errors.New("no such token"))
}

func (s *Server) apiFiles(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []Resource{}
	for _, res := range s.res.All() {
		if s.resourceVisible(id, res) {
			out = append(out, res)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiFileUpload(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	groups := splitList(q.Get("groups"))
	if len(groups) == 0 {
		groups = s.identityGroups(id)
	}
	def := Resource{
		Name: q.Get("name"), Keywords: splitList(q.Get("keywords")), Tool: firstNonEmpty(q.Get("tool"), "public"),
		Submitter: id.Name, CreatorUID: s.UID(), Groups: groups, UID: cot.NewUID(),
		Enrollment: boolParam(r, "enrollment"), Connection: boolParam(r, "connection"),
	}
	if def.Keywords == nil {
		def.Keywords = []string{}
	}
	res, code, err := s.storeUpload(w, r, def)
	if err != nil {
		apiError(w, code, err)
		return
	}
	if strings.HasSuffix(strings.ToLower(res.Name), ".zip") {
		s.res.Update(res.UID, func(x *Resource) {
			x.Package = true
			if !slices.Contains(x.Keywords, "missionpackage") {
				x.Keywords = append(x.Keywords, "missionpackage")
			}
			if x.MIMEType == "application/octet-stream" {
				x.MIMEType = "application/x-zip-compressed"
			}
		})
		res, _ = s.res.Get(res.UID)
	}
	s.log.Info("file uploaded from dashboard", "name", res.Name, "by", id.Name)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) apiFileUpdate(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	res, ok := s.res.Get(r.PathValue("uid"))
	if !ok || !s.canEdit(id, res) {
		apiError(w, http.StatusNotFound, errors.New("file not found"))
		return
	}
	var body struct {
		Name       *string   `json:"name"`
		Tool       *string   `json:"tool"`
		Keywords   *[]string `json:"keywords"`
		Groups     *[]string `json:"groups"`
		Enrollment *bool     `json:"enrollment"`
		Connection *bool     `json:"connection"`
		Expiration *int64    `json:"expiration"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	res, err := s.res.Update(res.UID, func(x *Resource) {
		if body.Name != nil && strings.TrimSpace(*body.Name) != "" {
			x.Name = safeFileName(*body.Name)
		}
		if body.Tool != nil {
			x.Tool = *body.Tool
		}
		if body.Keywords != nil {
			x.Keywords = *body.Keywords
		}
		if body.Groups != nil {
			x.Groups = *body.Groups
		}
		if body.Enrollment != nil {
			x.Enrollment = *body.Enrollment
		}
		if body.Connection != nil {
			x.Connection = *body.Connection
		}
		if body.Expiration != nil {
			x.Expiration = *body.Expiration
		}
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) apiFileShare(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	res, ok := s.res.Get(r.PathValue("uid"))
	if !ok || !s.resourceVisible(id, res) {
		apiError(w, http.StatusNotFound, errors.New("file not found"))
		return
	}
	var body struct {
		To   []string `json:"to"`
		Host string   `json:"host"`
	}
	decodeBody(r, &body)
	host := firstNonEmpty(body.Host, s.Config().Address)
	url := fmt.Sprintf("https://%s:%d/Marti/sync/content?hash=%s", HostForURL(host), s.Config().Ports.HTTPS, res.UID)
	e := cot.New(cot.NewUID(), "b-f-t-r", "h-e", 10*time.Minute)
	e.Detail.AddNew("fileshare", "filename", res.Name, "senderUrl", url, "sizeInBytes", itoa(int(res.Size)), "sha256", res.Hash,
		"senderUid", s.UID(), "senderCallsign", s.Config().Name, "name", strings.TrimSuffix(res.Name, filepath.Ext(res.Name)))
	e.Detail.AddNew("ackrequest", "uid", cot.NewUID(), "ackrequested", "true", "tag", res.Name)
	var dests []cot.Dest
	for _, t := range body.To {
		if c := s.hub.ByUID(t); c != nil {
			dests = append(dests, cot.Dest{UID: t})
		} else if t != "" {
			dests = append(dests, cot.Dest{Callsign: t})
		}
	}
	if len(dests) > 0 {
		e.SetDests(dests)
	}
	m := NewMessage(e, nil, s.dir.Mask(res.Groups))
	m.NoReplay = true
	if len(res.Groups) == 0 {
		m.Everyone = true
	}
	s.hub.Publish(m)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": url})
}

func (s *Server) apiMissions(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []map[string]any{}
	for _, m := range s.missions.All() {
		if !s.missionVisible(id, m) {
			continue
		}
		j := s.missionJSON(m, missionOpts{})
		j["subscribers"] = len(m.Subs)
		j["items"] = len(m.Items)
		j["files"] = len(m.Contents)
		j["changes"] = len(m.Changes)
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiMissionCreate(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Groups      []string `json:"groups"`
		Password    string   `json:"password"`
		DefaultRole string   `json:"defaultRole"`
		InviteOnly  bool     `json:"inviteOnly"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 255 {
		apiError(w, http.StatusBadRequest, errors.New("mission name is required"))
		return
	}
	if len(body.Groups) == 0 {
		body.Groups = s.identityGroups(id)
	}
	for _, g := range body.Groups {
		if _, ok := s.dir.Group(g); !ok {
			apiError(w, http.StatusBadRequest, errors.New("no such group "+g))
			return
		}
	}
	role := normalizeRole(body.DefaultRole)
	if role == "" {
		role = RoleSubscriber
	}
	m, err := s.missions.db.Update(name, func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			return m, true, errors.New("a mission with that name already exists")
		}
		m = Mission{Name: name, GUID: cot.NewUID(), Description: body.Description, Tool: "public", Created: time.Now().UTC(), CreatorUID: s.UID(),
			CreatorUser: id.Name, Groups: body.Groups, DefaultRole: role, InviteOnly: body.InviteOnly, Expiration: -1, Keywords: []string{}}
		if body.Password != "" {
			m.PasswordHash = HashPassword(body.Password)
		}
		m.addChange(MissionChange{Type: "CREATE_MISSION", CreatorUID: s.UID()})
		return m, true, nil
	})
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.notifyMissionAll(m, "t-x-m-n", "CREATE", s.UID())
	writeJSON(w, http.StatusOK, s.missionJSON(m, missionOpts{}))
}

func (s *Server) apiMissionGet(w http.ResponseWriter, r *http.Request) {
	m, ok := s.missions.Get(r.PathValue("name"))
	if !ok || !s.missionVisible(identityOf(r), m) {
		apiError(w, http.StatusNotFound, errMissionNotFound)
		return
	}
	j := s.missionJSON(m, missionOpts{changes: true, logs: true})
	subs := []map[string]any{}
	for _, sub := range m.Subs {
		dev, _ := s.devices.Get(sub.ClientUID)
		subs = append(subs, map[string]any{"clientUid": sub.ClientUID, "callsign": dev.Callsign, "username": sub.Username, "role": sub.Role, "created": sub.Created})
	}
	j["subscriptions"] = subs
	j["invitations"] = m.Invites
	writeJSON(w, http.StatusOK, j)
}

func (s *Server) apiMissionDelete(w http.ResponseWriter, r *http.Request) {
	m, ok := s.missions.Get(r.PathValue("name"))
	if !ok {
		apiError(w, http.StatusNotFound, errMissionNotFound)
		return
	}
	id := identityOf(r)
	if !id.Admin && m.CreatorUser != id.Name {
		apiError(w, http.StatusForbidden, errors.New("only the mission creator or an administrator can delete it"))
		return
	}
	s.missions.db.Delete(m.Name)
	s.missions.DeleteAllCoT(m.Name)
	s.notifyMissionAll(m, "t-x-m-d", "DELETE", s.UID())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiVideos(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []map[string]any{}
	for _, f := range s.videos.All() {
		if s.videoVisible(id, f) {
			out = append(out, map[string]any{"feed": f, "url": f.URL()})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiVideoCreate(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Alias  string   `json:"alias"`
		URL    string   `json:"url"`
		Groups []string `json:"groups"`
		Lat    string   `json:"latitude"`
		Lon    string   `json:"longitude"`
	}
	if err := decodeBody(r, &body); err != nil || strings.TrimSpace(body.URL) == "" {
		apiError(w, http.StatusBadRequest, errors.New("a stream URL is required"))
		return
	}
	f := feedFromURL(body.URL)
	f.Alias = firstNonEmpty(body.Alias, f.Path, f.Address)
	f.Groups = body.Groups
	if len(f.Groups) == 0 {
		f.Groups = s.identityGroups(id)
	}
	f.Lat, f.Lon, f.Creator, f.Active = body.Lat, body.Lon, id.Name, true
	f.UID = cot.NewUID()
	if err := s.videos.Put(f); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) apiVideoDelete(w http.ResponseWriter, r *http.Request) {
	s.videoDelete(w, r)
}

func (s *Server) apiVideoShare(w http.ResponseWriter, r *http.Request) {
	f, ok := s.videos.Get(r.PathValue("uid"))
	if !ok || !s.videoVisible(identityOf(r), f) {
		apiError(w, http.StatusNotFound, errors.New("video not found"))
		return
	}
	m := NewMessage(s.VideoEvent(f), nil, s.dir.Mask(f.Groups))
	if len(f.Groups) == 0 {
		m.Everyone = true
	}
	s.hub.Publish(m)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.profiles.Items())
}

func (s *Server) apiProfileCreate(w http.ResponseWriter, r *http.Request) {
	var it ProfileItem
	if err := decodeBody(r, &it); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if it.Kind != "file" && strings.TrimSpace(it.Key) == "" {
		apiError(w, http.StatusBadRequest, errors.New("a preference key is required"))
		return
	}
	if it.Kind == "file" && !s.res.blobs.Exists(it.Hash) {
		apiError(w, http.StatusBadRequest, errors.New("upload the file first and pass its hash"))
		return
	}
	saved, err := s.profiles.PutItem(it)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) apiProfileDelete(w http.ResponseWriter, r *http.Request) {
	s.profiles.DeleteItem(r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiPlugins(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.profiles.Plugins())
}

func (s *Server) apiPluginUpload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	src, fname, _, done, err := s.readUpload(w, r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	defer done()
	hash, size, err := s.res.blobs.Put(src, s.uploadLimit())
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	fname = safeFileName(firstNonEmpty(q.Get("file"), fname, hash[:12]+".apk"))
	meta := apkInfo(s.res.blobs.Path(hash))
	pl := Plugin{
		Platform: firstNonEmpty(q.Get("platform"), "Android"), Type: firstNonEmpty(q.Get("type"), "plugin"),
		Package: firstNonEmpty(q.Get("package"), meta.Package), Name: firstNonEmpty(q.Get("name"), meta.Label, strings.TrimSuffix(fname, filepath.Ext(fname))),
		Version: firstNonEmpty(q.Get("version"), meta.Version, "1.0"), Revision: firstNonEmpty(q.Get("revision"), meta.Code, "1"),
		File: fname, Hash: hash, Size: size, Description: q.Get("description"), OSRequired: firstNonEmpty(q.Get("osRequired"), meta.MinSDK),
		TAKPrereq: q.Get("takPrereq"), ATAKVersion: q.Get("atakVersion"), Enrollment: boolParam(r, "enrollment"), Connection: boolParam(r, "connection"),
	}
	if pl.Package == "" {
		apiError(w, http.StatusBadRequest, errors.New("could not read the package name from the APK; pass ?package="))
		return
	}
	for _, old := range s.profiles.Plugins() {
		if old.Package == pl.Package && old.ATAKVersion == pl.ATAKVersion {
			pl.ID = old.ID
		}
	}
	saved, err := s.profiles.PutPlugin(pl)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	s.log.Info("plugin published to update server", "package", pl.Package, "version", pl.Version)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) apiPluginDelete(w http.ResponseWriter, r *http.Request) {
	s.profiles.DeletePlugin(r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	peers := make([]PeerConfig, len(cfg.Peers))
	for i, p := range cfg.Peers {
		if p.Password != "" {
			p.Password = "********"
		}
		if p.CertPass != "" {
			p.CertPass = "********"
		}
		peers[i] = p
	}
	cfg.Peers = peers
	if cfg.LDAP.BindPassword != "" {
		cfg.LDAP.BindPassword = "********"
	}
	if cfg.Feeds.ADSB.APIKey != "" {
		cfg.Feeds.ADSB.APIKey = "********"
	}
	plugins := make([]PluginConfig, len(cfg.Plugins))
	for i, p := range cfg.Plugins {
		if len(p.Env) > 0 {
			env := map[string]string{}
			for k := range p.Env {
				env[k] = "********"
			}
			p.Env = env
		}
		plugins[i] = p
	}
	cfg.Plugins = plugins
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) apiSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	before := s.Config()
	next, err := s.UpdateConfig(func(c *Config) error {
		old := c.Peers
		oldPlugins := append([]PluginConfig(nil), c.Plugins...)
		oldBind, oldKey := c.LDAP.BindPassword, c.Feeds.ADSB.APIKey
		if err := jsonUnmarshalStrict(body, c); err != nil {
			return err
		}
		c.Plugins = oldPlugins
		if c.LDAP.BindPassword == "********" {
			c.LDAP.BindPassword = oldBind
		}
		if c.Feeds.ADSB.APIKey == "********" {
			c.Feeds.ADSB.APIKey = oldKey
		}
		for i := range c.Peers {
			for _, o := range old {
				if o.Name == c.Peers[i].Name {
					if c.Peers[i].Password == "********" {
						c.Peers[i].Password = o.Password
					}
					if c.Peers[i].CertPass == "********" {
						c.Peers[i].CertPass = o.CertPass
					}
				}
			}
		}
		return validateConfig(c)
	})
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	fb, _ := json.Marshal(before.DataFeeds)
	vb, _ := json.Marshal(before.Video)
	vn, _ := json.Marshal(next.Video)
	fn, _ := json.Marshal(next.DataFeeds)
	mb, _ := json.Marshal(before.Meshtastic)
	mn, _ := json.Marshal(next.Meshtastic)
	restart := before.Ports != next.Ports || before.Bind != next.Bind || before.Mesh.Enabled != next.Mesh.Enabled || before.Mesh.Send != next.Mesh.Send || string(mb) != string(mn) ||
		strings.Join(before.Mesh.Groups, ",") != strings.Join(next.Mesh.Groups, ",") || before.Federation.Enabled != next.Federation.Enabled || string(fb) != string(fn) || string(vb) != string(vn)
	if before.Address != next.Address || strings.Join(before.ExtraNames, ",") != strings.Join(next.ExtraNames, ",") {
		if err := s.pki.EnsureServer(next); err != nil {
			s.log.Error("server certificate update failed", "err", err)
		}
	}
	s.reloadPeers()
	s.log.Info("settings changed", "by", identityOf(r).Name, "restartRequired", restart)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restartRequired": restart})
}

func validateConfig(c *Config) error {
	seen := map[string]string{}
	check := func(name string, port int, proto string) error {
		if port < 0 || port > 65535 {
			return fmt.Errorf("%s port %d is out of range", name, port)
		}
		if port == 0 {
			return nil
		}
		key := proto + "/" + itoa(port)
		if other, ok := seen[key]; ok && !(name == "tcpAlt" && other == "tcp") {
			return fmt.Errorf("%s and %s both use %s", name, other, key)
		}
		seen[key] = name
		return nil
	}
	p := c.Ports
	for _, x := range []struct {
		n     string
		v     int
		proto string
	}{{"tcp", p.TCP, "tcp"}, {"tcpAlt", p.TCPAlt, "tcp"}, {"tls", p.TLS, "tcp"}, {"http", p.HTTP, "tcp"}, {"https", p.HTTPS, "tcp"}, {"enroll", p.Enroll, "tcp"},
		{"websocket", p.WebSocket, "tcp"}, {"federation", p.Federation, "tcp"}, {"federationV2", p.FederationV2, "tcp"}, {"api", p.API, "tcp"}, {"udp", p.UDP, "udp"}} {
		if x.n == "tcpAlt" && x.v == p.TCP {
			continue
		}
		if err := check(x.n, x.v, x.proto); err != nil {
			return err
		}
	}
	if v := c.Video; v.Enabled {
		for _, x := range []struct {
			n     string
			v     int
			proto string
		}{{"videoServer.rtspPort", v.RTSPPort, "tcp"}, {"videoServer.rtspsPort", v.RTSPSPort, "tcp"}, {"videoServer.rtmpPort", v.RTMPPort, "tcp"}, {"videoServer.rtpPort", v.RTPPort, "udp"}} {
			if err := check(x.n, x.v, x.proto); err != nil {
				return err
			}
		}
		if v.RTPPort > 0 {
			if v.RTPPort%2 != 0 {
				return errors.New("the video RTP port must be even")
			}
			if err := check("videoServer.rtcpPort", v.RTPPort+1, "udp"); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("server name cannot be empty")
	}
	if strings.TrimSpace(c.Address) == "" {
		return errors.New("server address cannot be empty")
	}
	switch c.Replay {
	case "all", "sa", "none":
	default:
		return errors.New("replay must be all, sa or none")
	}
	if a := c.Feeds.ADSB; a.Enabled {
		if a.Lat < -90 || a.Lat > 90 || a.Lon < -180 || a.Lon > 180 {
			return errors.New("ADS-B center must be a valid latitude and longitude")
		}
		if a.RadiusNM <= 0 || a.RadiusNM > 250 {
			return errors.New("ADS-B radius must be between 1 and 250 nautical miles")
		}
		if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
			return errors.New("ADS-B URL must start with http:// or https://")
		}
	}
	if l := c.LDAP; l.Enabled {
		if !strings.HasPrefix(l.URL, "ldap://") && !strings.HasPrefix(l.URL, "ldaps://") {
			return errors.New("the LDAP server URL must start with ldap:// or ldaps://")
		}
		if l.UserDN == "" && l.BaseDN == "" {
			return errors.New("LDAP needs a base DN or a user DN template")
		}
	}
	if m := c.Meshtastic; m.Enabled {
		if m.BrokerPort < 0 || m.BrokerPort > 65535 {
			return errors.New("the Meshtastic broker port is out of range")
		}
		if m.BrokerPort > 0 {
			if other, ok := seen["tcp/"+itoa(m.BrokerPort)]; ok {
				return fmt.Errorf("the Meshtastic broker and %s both use tcp/%d", other, m.BrokerPort)
			}
		}
		if m.BrokerPort == 0 && m.Upstream == "" {
			return errors.New("the Meshtastic bridge needs the built-in broker or an upstream broker")
		}
		if m.Upstream != "" && !strings.HasPrefix(m.Upstream, "mqtt://") && !strings.HasPrefix(m.Upstream, "mqtts://") {
			return errors.New("the upstream broker URL must start with mqtt:// or mqtts://")
		}
		if _, _, err := meshKeys(m); err != nil {
			return err
		}
		if m.DownlinkChannel != "" {
			found := false
			for _, ch := range m.Channels {
				if ch.Name == m.DownlinkChannel {
					found = true
				}
			}
			if !found {
				return errors.New("the Meshtastic downlink channel is not in the channel list")
			}
		}
	}
	if a := c.Feeds.AIS; a.Enabled {
		if strings.TrimSpace(a.Username) == "" {
			return errors.New("the AIS feed needs an AISHub user name")
		}
		if a.South < -90 || a.North > 90 || a.South >= a.North || a.West < -180 || a.East > 180 || a.West >= a.East {
			return errors.New("the AIS area must be south < north and west < east")
		}
	}
	return nil
}

func (s *Server) apiRenewServerCert(w http.ResponseWriter, r *http.Request) {
	os.Remove(filepath.Join(certDir(s.DataDir), "server.pem"))
	if err := s.pki.EnsureServer(s.Config()); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	leaf := s.pki.ServerLeaf()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expires": leaf.NotAfter, "names": append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...)})
}

func (s *Server) apiBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="golangtak-backup-`+time.Now().UTC().Format("20060102-150405")+`.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()
	include := boolParam(r, "files")
	s.minuteTasks()
	s.devices.Flush()
	filepath.WalkDir(s.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.DataDir, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "logs" || rel == "history" || (rel == "files" && !include) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), ".tmp") || strings.HasPrefix(d.Name(), ".upload") || rel == "control.token" || rel == "golangtak.lock" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		hdr := &zip.FileHeader{Name: rel, Method: zip.Deflate}
		if info, err := d.Info(); err == nil {
			hdr.Modified = info.ModTime()
		}
		zf, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		io.Copy(zf, f)
		return nil
	})
	s.log.Info("backup downloaded", "by", identityOf(r).Name, "includesFiles", include)
}
