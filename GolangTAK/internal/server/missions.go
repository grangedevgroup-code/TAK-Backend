package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/xmltree"
)

const (
	RoleOwner      = "MISSION_OWNER"
	RoleSubscriber = "MISSION_SUBSCRIBER"
	RoleReadOnly   = "MISSION_READONLY_SUBSCRIBER"
)

var rolePermissions = map[string][]string{
	RoleOwner:      {"MISSION_MANAGE_FEEDS", "MISSION_SET_PASSWORD", "MISSION_WRITE", "MISSION_MANAGE_LAYERS", "MISSION_UPDATE_GROUPS", "MISSION_DELETE", "MISSION_SET_ROLE", "MISSION_READ"},
	RoleSubscriber: {"MISSION_READ", "MISSION_WRITE"},
	RoleReadOnly:   {"MISSION_READ"},
}

func normalizeRole(r string) string {
	switch strings.ToUpper(strings.TrimSpace(r)) {
	case RoleOwner, "OWNER":
		return RoleOwner
	case RoleReadOnly, "MISSION_READ_ONLY", "READ_ONLY", "READONLY", "READONLY_SUBSCRIBER":
		return RoleReadOnly
	case RoleSubscriber, "SUBSCRIBER", "":
		return RoleSubscriber
	}
	return ""
}

func roleJSON(r string) map[string]any {
	r = normalizeRole(r)
	if r == "" {
		r = RoleSubscriber
	}
	return map[string]any{"type": r, "permissions": rolePermissions[r]}
}

type MissionContent struct {
	UID        string    `json:"uid"`
	Hash       string    `json:"hash"`
	CreatorUID string    `json:"creatorUid"`
	Added      time.Time `json:"added"`
}

type MissionItem struct {
	UID         string    `json:"uid"`
	CreatorUID  string    `json:"creatorUid"`
	Added       time.Time `json:"added"`
	Type        string    `json:"type"`
	Callsign    string    `json:"callsign"`
	IconsetPath string    `json:"iconsetPath"`
	Color       string    `json:"color"`
	Lat         float64   `json:"lat"`
	Lon         float64   `json:"lon"`
}

type MissionSub struct {
	ClientUID string    `json:"clientUid"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Created   time.Time `json:"created"`
}

type MissionInvite struct {
	Type       string    `json:"type"`
	Invitee    string    `json:"invitee"`
	Role       string    `json:"role"`
	CreatorUID string    `json:"creatorUid"`
	Created    time.Time `json:"created"`
}

type MissionLog struct {
	ID            string    `json:"id"`
	Content       string    `json:"content"`
	CreatorUID    string    `json:"creatorUid"`
	ServerTime    time.Time `json:"servertime"`
	DTG           time.Time `json:"dtg"`
	Created       time.Time `json:"created"`
	ContentHashes []string  `json:"contentHashes"`
	Keywords      []string  `json:"keywords"`
}

type MissionChange struct {
	Seq        int64        `json:"seq"`
	Type       string       `json:"type"`
	Time       time.Time    `json:"timestamp"`
	CreatorUID string       `json:"creatorUid"`
	ContentUID string       `json:"contentUid,omitempty"`
	Resource   *Resource    `json:"resource,omitempty"`
	Item       *MissionItem `json:"item,omitempty"`
}

type Mission struct {
	Name           string           `json:"name"`
	GUID           string           `json:"guid"`
	Description    string           `json:"description"`
	ChatRoom       string           `json:"chatRoom"`
	BaseLayer      string           `json:"baseLayer"`
	BBox           string           `json:"bbox"`
	Path           string           `json:"path"`
	Classification string           `json:"classification"`
	Tool           string           `json:"tool"`
	Keywords       []string         `json:"keywords"`
	CreatorUID     string           `json:"creatorUid"`
	CreatorUser    string           `json:"creatorUser"`
	Created        time.Time        `json:"created"`
	Groups         []string         `json:"groups"`
	DefaultRole    string           `json:"defaultRole"`
	InviteOnly     bool             `json:"inviteOnly"`
	Expiration     int64            `json:"expiration"`
	PasswordHash   string           `json:"passwordHash,omitempty"`
	Contents       []MissionContent `json:"contents"`
	Items          []MissionItem    `json:"items"`
	Subs           []MissionSub     `json:"subs"`
	Invites        []MissionInvite  `json:"invites"`
	Logs           []MissionLog     `json:"logs"`
	Changes        []MissionChange  `json:"changes"`
	ExternalData   []map[string]any `json:"externalData"`
	Parent         string           `json:"parent,omitempty"`
	Origin         string           `json:"federatedFrom,omitempty"`
	NextSeq        int64            `json:"nextSeq"`
}

const maxMissionChanges = 5000

func (m *Mission) addChange(c MissionChange) {
	m.NextSeq++
	c.Seq = m.NextSeq
	if c.Time.IsZero() {
		c.Time = time.Now().UTC()
	}
	m.Changes = append(m.Changes, c)
	if len(m.Changes) > maxMissionChanges {
		m.Changes = append([]MissionChange(nil), m.Changes[len(m.Changes)-maxMissionChanges:]...)
	}
}

func (m *Mission) sub(clientUID string) *MissionSub {
	for i := range m.Subs {
		if m.Subs[i].ClientUID == clientUID {
			return &m.Subs[i]
		}
	}
	return nil
}

func (m *Mission) item(uid string) *MissionItem {
	for i := range m.Items {
		if m.Items[i].UID == uid {
			return &m.Items[i]
		}
	}
	return nil
}

type Missions struct {
	db   *store.Collection[Mission]
	cots *store.Collection[string]
}

func OpenMissions(dataDir string) (*Missions, error) {
	db, err := store.Open[Mission](filepath.Join(dataDir, "db", "missions.jsonl"), true)
	if err != nil {
		return nil, err
	}
	cots, err := store.Open[string](filepath.Join(dataDir, "db", "mission-cot.jsonl"), false)
	if err != nil {
		return nil, err
	}
	return &Missions{db: db, cots: cots}, nil
}

func (ms *Missions) Close() {
	ms.db.Close()
	ms.cots.Close()
}

func (ms *Missions) key(name string) string {
	if ms.db.Has(name) {
		return name
	}
	for _, k := range ms.db.Keys() {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return name
}

func (ms *Missions) Get(name string) (Mission, bool) {
	return ms.db.Get(ms.key(name))
}

func (ms *Missions) ByGUID(guid string) (Mission, bool) {
	for _, m := range ms.db.All() {
		if m.GUID == guid {
			return m, true
		}
	}
	return Mission{}, false
}

func (ms *Missions) All() []Mission { return ms.db.All() }

func (ms *Missions) Update(name string, fn func(m *Mission) error) (Mission, error) {
	return ms.db.Update(ms.key(name), func(m Mission, ok bool) (Mission, bool, error) {
		if !ok {
			return m, false, errMissionNotFound
		}
		if err := fn(&m); err != nil {
			return m, true, err
		}
		return m, true, nil
	})
}

var errMissionNotFound = errors.New("mission not found")

func cotKey(mission, uid string) string { return mission + "\x00" + uid }

func (ms *Missions) SetCoT(mission, uid string, xml []byte) {
	ms.cots.Put(cotKey(mission, uid), string(xml))
}

func (ms *Missions) CoT(mission, uid string) (string, bool) { return ms.cots.Get(cotKey(mission, uid)) }

func (ms *Missions) DeleteCoT(mission, uid string) { ms.cots.Delete(cotKey(mission, uid)) }

func (ms *Missions) DeleteAllCoT(mission string) {
	prefix := mission + "\x00"
	for _, k := range ms.cots.Keys() {
		if strings.HasPrefix(k, prefix) {
			ms.cots.Delete(k)
		}
	}
}

func (s *Server) missionUsesHash(hash string) bool {
	if s.missions == nil {
		return false
	}
	for _, m := range s.missions.All() {
		for _, c := range m.Contents {
			if c.Hash == hash {
				return true
			}
		}
	}
	return false
}

func (s *Server) missionVisible(id *Identity, m Mission) bool {
	if id == nil {
		return false
	}
	if id.Admin || len(m.Groups) == 0 {
		return true
	}
	return s.visibleTo(id, s.dir.Mask(m.Groups))
}

func itemJSON(it MissionItem) map[string]any {
	return map[string]any{
		"data":       it.UID,
		"timestamp":  isoTime(it.Added),
		"creatorUid": it.CreatorUID,
		"details": map[string]any{
			"type":        it.Type,
			"callsign":    it.Callsign,
			"iconsetPath": it.IconsetPath,
			"color":       it.Color,
			"location":    map[string]any{"lat": it.Lat, "lon": it.Lon},
		},
	}
}

func (s *Server) contentJSON(c MissionContent) map[string]any {
	res, ok := s.res.Get(c.UID)
	if !ok {
		res, _ = s.res.Get(c.Hash)
	}
	if res.UID == "" {
		res = Resource{UID: c.UID, Hash: c.Hash}
	}
	return map[string]any{"data": resourceJSON(res), "timestamp": isoTime(c.Added), "creatorUid": c.CreatorUID}
}

func (s *Server) changeJSON(m Mission, c MissionChange) map[string]any {
	out := map[string]any{
		"isFederatedChange": false,
		"type":              c.Type,
		"contentUid":        c.ContentUID,
		"missionName":       m.Name,
		"missionGuid":       m.GUID,
		"timestamp":         isoTime(c.Time),
		"creatorUid":        c.CreatorUID,
		"serverTime":        isoTime(c.Time),
	}
	if c.Resource != nil {
		out["contentResource"] = resourceJSON(*c.Resource)
		out["contentHash"] = c.Resource.Hash
	}
	if c.Item != nil {
		out["details"] = itemJSON(*c.Item)["details"]
	}
	return out
}

func (s *Server) logJSON(m Mission, l MissionLog) map[string]any {
	hashes := l.ContentHashes
	if hashes == nil {
		hashes = []string{}
	}
	kw := l.Keywords
	if kw == nil {
		kw = []string{}
	}
	return map[string]any{
		"id": l.ID, "content": l.Content, "creatorUid": l.CreatorUID, "entryUid": l.ID,
		"missionNames": []string{m.Name}, "servertime": isoTime(l.ServerTime), "dtg": isoTime(l.DTG),
		"created": isoTime(l.Created), "contentHashes": hashes, "keywords": kw,
	}
}

type missionOpts struct {
	changes bool
	logs    bool
	since   time.Time
	until   time.Time
}

func (s *Server) missionJSON(m Mission, o missionOpts) map[string]any {
	kw := m.Keywords
	if kw == nil {
		kw = []string{}
	}
	groups := m.Groups
	if groups == nil {
		groups = []string{}
	}
	uids := make([]map[string]any, 0, len(m.Items))
	for _, it := range m.Items {
		uids = append(uids, itemJSON(it))
	}
	contents := make([]map[string]any, 0, len(m.Contents))
	for _, c := range m.Contents {
		contents = append(contents, s.contentJSON(c))
	}
	ext := m.ExternalData
	if ext == nil {
		ext = []map[string]any{}
	}
	out := map[string]any{
		"name": m.Name, "description": m.Description, "chatRoom": m.ChatRoom, "baseLayer": m.BaseLayer,
		"bbox": m.BBox, "path": m.Path, "classification": m.Classification, "tool": firstNonEmpty(m.Tool, "public"),
		"keywords": kw, "creatorUid": m.CreatorUID, "createTime": isoTime(m.Created),
		"externalData": ext, "feeds": []any{}, "mapLayers": []any{},
		"defaultRole": roleJSON(m.DefaultRole), "inviteOnly": m.InviteOnly, "expiration": m.Expiration,
		"guid": m.GUID, "uids": uids, "contents": contents, "passwordProtected": m.PasswordHash != "",
		"groups": groups,
	}
	if m.Parent != "" {
		out["parentMission"] = m.Parent
	}
	if o.changes {
		var ch []map[string]any
		for _, c := range m.Changes {
			if (!o.since.IsZero() && c.Time.Before(o.since)) || (!o.until.IsZero() && c.Time.After(o.until)) {
				continue
			}
			ch = append(ch, s.changeJSON(m, c))
		}
		if ch == nil {
			ch = []map[string]any{}
		}
		out["missionChanges"] = ch
	}
	if o.logs {
		logs := make([]map[string]any, 0, len(m.Logs))
		for _, l := range m.Logs {
			logs = append(logs, s.logJSON(m, l))
		}
		out["logs"] = logs
	}
	return out
}

func timeWindow(r *http.Request) (time.Time, time.Time) {
	q := r.URL.Query()
	var since, until time.Time
	if v := q.Get("secago"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			since = time.Now().Add(-time.Duration(n) * time.Second)
		}
	}
	if v := q.Get("start"); v != "" {
		since, _ = cot.ParseTime(v)
	}
	if v := q.Get("end"); v != "" {
		until, _ = cot.ParseTime(v)
	}
	return since, until
}

func (s *Server) missionToken(r *http.Request) (missionClaims, bool) {
	h := r.Header.Get("Authorization")
	if scheme, cred, ok := strings.Cut(h, " "); ok && strings.EqualFold(scheme, "bearer") {
		if c, err := s.parseMissionToken(strings.TrimSpace(cred)); err == nil {
			return c, true
		}
	}
	return missionClaims{}, false
}

func (s *Server) callerUID(r *http.Request) string {
	if c, ok := s.missionToken(r); ok && c.Sub != "" {
		return c.Sub
	}
	q := r.URL.Query()
	return firstNonEmpty(q.Get("creatorUid"), q.Get("CreatorUid"), q.Get("clientUid"), q.Get("uid"))
}

func (s *Server) subBelongsTo(r *http.Request, sub *MissionSub) bool {
	if c, ok := s.missionToken(r); ok && c.Sub == sub.ClientUID {
		return true
	}
	if sub.Username == "" {
		return true
	}
	id := identityOf(r)
	return id != nil && !id.Anon && strings.EqualFold(id.Name, sub.Username)
}

func (s *Server) callerRole(r *http.Request, m Mission) string {
	id := identityOf(r)
	if id != nil && id.Admin {
		return RoleOwner
	}
	uid := s.callerUID(r)
	if sub := m.sub(uid); sub != nil && s.subBelongsTo(r, sub) {
		return normalizeRole(sub.Role)
	}
	if id != nil && !id.Anon {
		for _, sub := range m.Subs {
			if sub.Username == id.Name && sub.Role == RoleOwner {
				return RoleOwner
			}
		}
		if m.CreatorUser != "" && m.CreatorUser == id.Name {
			return RoleOwner
		}
	}
	if c, ok := s.missionToken(r); ok && c.GUID == m.GUID {
		return normalizeRole(m.DefaultRole)
	}
	if m.InviteOnly || m.PasswordHash != "" {
		return ""
	}
	return normalizeRole(m.DefaultRole)
}

func (s *Server) loadMission(w http.ResponseWriter, r *http.Request) (Mission, bool) {
	var m Mission
	var ok bool
	if guid := r.PathValue("guid"); guid != "" {
		m, ok = s.missions.ByGUID(guid)
	} else {
		m, ok = s.missions.Get(r.PathValue("name"))
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mission not found"})
		return m, false
	}
	if !s.missionVisible(identityOf(r), m) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you are not in a group that can see this mission"})
		return m, false
	}
	return m, true
}

func (s *Server) canWriteMission(r *http.Request, m Mission) bool {
	return slices.Contains(rolePermissions[s.callerRole(r, m)], "MISSION_WRITE")
}

func (s *Server) requirePermission(w http.ResponseWriter, r *http.Request, m Mission, perm string) bool {
	role := s.callerRole(r, m)
	if role != "" && slices.Contains(rolePermissions[role], perm) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "your mission role does not allow " + perm})
	return false
}

func (s *Server) missionList(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	includePw := boolParam(r, "passwordProtected")
	tool := q.Get("tool")
	data := []map[string]any{}
	for _, m := range s.missions.All() {
		if !s.missionVisible(id, m) {
			continue
		}
		if m.PasswordHash != "" && !includePw {
			continue
		}
		if tool != "" && !strings.EqualFold(firstNonEmpty(m.Tool, "public"), tool) {
			continue
		}
		data = append(data, s.missionJSON(m, missionOpts{}))
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", data))
}

func (s *Server) missionCreate(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "\x00\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mission name"})
		return
	}
	q := r.URL.Query()
	creator := firstNonEmpty(q.Get("creatorUid"), q.Get("uid"), q.Get("clientUid"))
	groups := splitList(q.Get("group"))
	groups = append(groups, q["groups"]...)
	if len(groups) == 0 {
		groups = s.identityGroups(id)
	}
	for _, g := range groups {
		if _, ok := s.dir.Group(g); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "group not found: " + g})
			return
		}
		if !id.Admin && !slices.Contains(s.identityGroups(id), g) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "you are not a member of group " + g})
			return
		}
	}
	created := false
	var token string
	m, err := s.missions.db.Update(s.missions.key(name), func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			if !s.missionVisible(id, m) {
				return m, true, errors.New("forbidden")
			}
			role := ""
			if sub := m.sub(creator); sub != nil {
				role = sub.Role
			}
			if !id.Admin && role != RoleOwner && !(m.CreatorUser == id.Name && !id.Anon) {
				return m, true, errors.New("forbidden")
			}
		} else {
			created = true
			m = Mission{Name: name, GUID: cot.NewUID(), Created: time.Now().UTC(), CreatorUID: creator, Groups: groups, Expiration: -1, Keywords: []string{}}
			if !id.Anon {
				m.CreatorUser = id.Name
			}
			m.DefaultRole = RoleSubscriber
		}
		set := func(param string, dst *string) {
			if q.Has(param) {
				*dst = q.Get(param)
			}
		}
		set("description", &m.Description)
		set("chatRoom", &m.ChatRoom)
		set("baseLayer", &m.BaseLayer)
		set("bbox", &m.BBox)
		set("path", &m.Path)
		set("classification", &m.Classification)
		set("tool", &m.Tool)
		if m.Tool == "" {
			m.Tool = "public"
		}
		if q.Has("defaultRole") {
			if role := normalizeRole(q.Get("defaultRole")); role != "" {
				m.DefaultRole = role
			}
		}
		if q.Has("inviteOnly") {
			m.InviteOnly = boolParam(r, "inviteOnly")
		}
		if q.Has("expiration") {
			if v, err := parseInt64(q.Get("expiration")); err == nil {
				m.Expiration = v
			}
		}
		if kws := q["keywords"]; len(kws) > 0 {
			m.Keywords = splitList(strings.Join(kws, ","))
		}
		if pw := q.Get("password"); pw != "" && created {
			m.PasswordHash = HashPassword(pw)
		}
		if created {
			if creator != "" {
				m.Subs = append(m.Subs, MissionSub{ClientUID: creator, Username: id.Name, Role: RoleOwner, Created: time.Now().UTC()})
			}
			m.addChange(MissionChange{Type: "CREATE_MISSION", CreatorUID: creator})
		}
		return m, true, nil
	})
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the mission owner can change this mission"})
		return
	}
	out := s.missionJSON(m, missionOpts{})
	if creator != "" {
		token = s.signMissionToken(missionClaims{Sub: creator, Mission: m.Name, GUID: m.GUID})
		out["token"] = token
	}
	status := http.StatusOK
	if created {
		out["ownerRole"] = roleJSON(RoleOwner)
		status = http.StatusCreated
		s.log.Info("mission created", "name", m.Name, "by", id.Name, "client", creator)
		s.notifyMissionAll(m, "t-x-m-n", "CREATE", creator)
	}
	writeJSON(w, status, s.envelope("Mission", []any{out}))
}

func (s *Server) missionGet(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if m.PasswordHash != "" && s.callerRole(r, m) == "" {
		if !checkHash(m.PasswordHash, r.URL.Query().Get("password")) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "this mission is password protected"})
			return
		}
	}
	since, until := timeWindow(r)
	o := missionOpts{changes: boolParam(r, "changes"), logs: boolParam(r, "logs"), since: since, until: until}
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, o)}))
}

func (s *Server) missionDelete(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_DELETE") {
		return
	}
	if err := s.missions.db.Delete(m.Name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.missions.DeleteAllCoT(m.Name)
	if boolParam(r, "deepDelete") {
		for _, c := range m.Contents {
			if s.missionUsesHash(c.Hash) {
				continue
			}
			if res, ok := s.res.Get(c.UID); ok && s.canEdit(identityOf(r), res) {
				s.res.Delete(c.UID)
			}
		}
	}
	s.log.Info("mission deleted", "name", m.Name, "by", identityOf(r).Name)
	s.notifyMissionAll(m, "t-x-m-d", "DELETE", s.callerUID(r))
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) missionSubscribe(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	name := r.PathValue("name")
	if _, ok := s.missions.Get(name); !ok && strings.EqualFold(name, "citrap") && r.PathValue("guid") == "" {
		s.ensureSystemMission("citrap", "Reports", id)
	}
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	uid := firstNonEmpty(q.Get("uid"), q.Get("clientUid"), s.callerUID(r))
	if uid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "uid is required"})
		return
	}
	tok, hasToken := s.missionToken(r)
	if hasToken && tok.GUID != m.GUID {
		hasToken = false
	}
	invited := s.isInvited(m, uid, id)
	if !hasToken && m.sub(uid) == nil && !(id != nil && id.Admin) {
		if m.PasswordHash != "" && !checkHash(m.PasswordHash, q.Get("password")) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid mission password"})
			return
		}
		if m.InviteOnly && !invited {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this mission is invite only"})
			return
		}
	}
	m, err := s.missions.Update(m.Name, func(x *Mission) error {
		if sub := x.sub(uid); sub == nil {
			role := normalizeRole(x.DefaultRole)
			for _, inv := range x.Invites {
				if s.inviteMatches(inv, uid, id) && inv.Role != "" {
					role = normalizeRole(inv.Role)
				}
			}
			x.Subs = append(x.Subs, MissionSub{ClientUID: uid, Username: id.Name, Role: role, Created: time.Now().UTC()})
		}
		x.Invites = slices.DeleteFunc(x.Invites, func(inv MissionInvite) bool { return s.inviteMatches(inv, uid, id) })
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sub := m.sub(uid)
	token := s.signMissionToken(missionClaims{Sub: uid, Mission: m.Name, GUID: m.GUID})
	since, until := timeWindow(r)
	data := map[string]any{
		"token":      token,
		"clientUid":  uid,
		"username":   sub.Username,
		"createTime": isoTime(sub.Created),
		"role":       roleJSON(sub.Role),
		"mission":    s.missionJSON(m, missionOpts{changes: !since.IsZero(), since: since, until: until}),
	}
	s.log.Info("mission subscription", "mission", m.Name, "client", uid, "user", id.Name, "role", sub.Role)
	writeJSON(w, http.StatusCreated, s.envelope("com.bbn.marti.sync.model.MissionSubscription", data))
}

func (s *Server) missionSubscription(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	uid := firstNonEmpty(r.URL.Query().Get("uid"), s.callerUID(r))
	sub := m.sub(uid)
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not subscribed"})
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.sync.model.MissionSubscription", map[string]any{
		"token": s.signMissionToken(missionClaims{Sub: uid, Mission: m.Name, GUID: m.GUID}), "clientUid": uid,
		"username": sub.Username, "createTime": isoTime(sub.Created), "role": roleJSON(sub.Role),
	}))
}

func (s *Server) missionUnsubscribe(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	uid := firstNonEmpty(r.URL.Query().Get("uid"), s.callerUID(r))
	if boolParam(r, "disconnectOnly") {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.missions.Update(m.Name, func(x *Mission) error {
		x.Subs = slices.DeleteFunc(x.Subs, func(sub MissionSub) bool { return sub.ClientUID == uid })
		return nil
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) missionSubscriptions(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	uids := []string{}
	for _, sub := range m.Subs {
		uids = append(uids, sub.ClientUID)
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionSubscription", uids))
}

func (s *Server) missionRoles(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	data := []map[string]any{}
	for _, sub := range m.Subs {
		data = append(data, map[string]any{"clientUid": sub.ClientUID, "username": sub.Username, "createTime": isoTime(sub.Created), "role": roleJSON(sub.Role)})
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionSubscription", data))
}

func (s *Server) missionMyRole(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	role := s.callerRole(r, m)
	if role == "" {
		role = RoleReadOnly
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.sync.model.MissionRole", roleJSON(role)))
}

func (s *Server) missionSetRole(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_SET_ROLE") {
		return
	}
	q := r.URL.Query()
	target := q.Get("clientUid")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clientUid is required"})
		return
	}
	role := normalizeRole(q.Get("role"))
	if q.Get("role") != "" && role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
		return
	}
	m, err := s.missions.Update(m.Name, func(x *Mission) error {
		if q.Get("role") == "" {
			x.Subs = slices.DeleteFunc(x.Subs, func(sub MissionSub) bool { return sub.ClientUID == target })
			return nil
		}
		if sub := x.sub(target); sub != nil {
			sub.Role = role
		} else {
			user := ""
			if dev, ok := s.devices.Get(target); ok {
				user = dev.User
			}
			x.Subs = append(x.Subs, MissionSub{ClientUID: target, Username: user, Role: role, Created: time.Now().UTC()})
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	e := s.missionEvent(m, "t-x-m-r", "INVITE", s.callerUID(r))
	if role != "" {
		addRoleXML(e.Detail.Child("mission"), role)
	}
	s.sendToUID(target, e)
	w.WriteHeader(http.StatusOK)
}

func addRoleXML(mission *xmltree.Node, role string) {
	rn := mission.AddNew("role", "type", role)
	perms := rn.AddNew("permissions")
	for _, p := range rolePermissions[role] {
		perms.AddNew("permission", "type", p)
	}
}

func (s *Server) missionContentsAdd(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	var body struct {
		Hashes []string `json:"hashes"`
		UIDs   []string `json:"uids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected JSON with hashes and/or uids"})
		return
	}
	creator := s.callerUID(r)
	var newRes []Resource
	var newItems []MissionItem
	for _, h := range body.Hashes {
		if _, ok := s.res.Get(h); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no file with hash " + h})
			return
		}
	}
	m, err := s.missions.Update(m.Name, func(x *Mission) error {
		for _, h := range body.Hashes {
			res, _ := s.res.Get(h)
			if slices.ContainsFunc(x.Contents, func(c MissionContent) bool { return c.Hash == res.Hash }) {
				continue
			}
			x.Contents = append(x.Contents, MissionContent{UID: res.UID, Hash: res.Hash, CreatorUID: creator, Added: time.Now().UTC()})
			rc := res
			x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: creator, ContentUID: res.UID, Resource: &rc})
			newRes = append(newRes, res)
		}
		for _, uid := range body.UIDs {
			if x.item(uid) != nil {
				continue
			}
			it := s.itemFromCache(uid, creator)
			x.Items = append(x.Items, it)
			ic := it
			x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: creator, ContentUID: uid, Item: &ic})
			newItems = append(newItems, it)
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for _, it := range newItems {
		if c := s.hub.CachedEvent(it.UID); c != nil {
			s.missions.SetCoT(m.Name, it.UID, c.XML())
		}
	}
	for _, res := range newRes {
		s.notifyMissionChange(m, "ADD_CONTENT", creator, &res, nil)
	}
	for _, it := range newItems {
		s.notifyMissionChange(m, "ADD_CONTENT", creator, nil, &it)
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) itemFromCache(uid, creator string) MissionItem {
	it := MissionItem{UID: uid, CreatorUID: creator, Added: time.Now().UTC()}
	if c := s.hub.CachedEvent(uid); c != nil {
		fillItem(&it, c.Event)
	}
	return it
}

func fillItem(it *MissionItem, e *cot.Event) {
	it.Type = e.Type
	it.Callsign = firstNonEmpty(e.Callsign(), it.Callsign)
	it.Lat, it.Lon = e.Point.Lat, e.Point.Lon
	if ic := e.D("usericon"); ic != nil {
		it.IconsetPath = firstNonEmpty(ic.Attr("iconsetpath"), ic.Attr("iconsetPath"))
	}
	if c := e.D("color"); c != nil {
		it.Color = firstNonEmpty(c.Attr("argb"), c.Attr("value"))
	}
}

func (s *Server) missionContentsRemove(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	q := r.URL.Query()
	hash, uid := q.Get("hash"), q.Get("uid")
	creator := s.callerUID(r)
	var removedRes *Resource
	var removedItem *MissionItem
	m, err := s.missions.Update(m.Name, func(x *Mission) error {
		if hash != "" {
			idx := slices.IndexFunc(x.Contents, func(c MissionContent) bool { return c.Hash == strings.ToLower(hash) || c.UID == hash })
			if idx < 0 {
				return errMissionNotFound
			}
			res, _ := s.res.Get(x.Contents[idx].UID)
			if res.UID == "" {
				res = Resource{UID: x.Contents[idx].UID, Hash: x.Contents[idx].Hash}
			}
			x.Contents = slices.Delete(x.Contents, idx, idx+1)
			removedRes = &res
			x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: creator, ContentUID: res.UID, Resource: &res})
		}
		if uid != "" {
			it := x.item(uid)
			if it == nil {
				return errMissionNotFound
			}
			cp := *it
			x.Items = slices.DeleteFunc(x.Items, func(i MissionItem) bool { return i.UID == uid })
			removedItem = &cp
			x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: creator, ContentUID: uid, Item: &cp})
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "content not found in mission"})
		return
	}
	if removedItem != nil {
		s.missions.DeleteCoT(m.Name, removedItem.UID)
		s.notifyMissionChange(m, "REMOVE_CONTENT", creator, nil, removedItem)
	}
	if removedRes != nil {
		s.notifyMissionChange(m, "REMOVE_CONTENT", creator, removedRes, nil)
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) missionContentsPackage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	id := identityOf(r)
	creator := s.callerUID(r)
	res, code, err := s.storeUpload(w, r, Resource{Name: m.Name + ".zip", MIMEType: "application/zip", Keywords: []string{"missionpackage"}, Tool: "public", Submitter: id.Name, CreatorUID: creator, Groups: m.Groups, UID: cot.NewUID(), Package: true})
	if err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	m, _ = s.missions.Update(m.Name, func(x *Mission) error {
		x.Contents = append(x.Contents, MissionContent{UID: res.UID, Hash: res.Hash, CreatorUID: creator, Added: time.Now().UTC()})
		rc := res
		x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: creator, ContentUID: res.UID, Resource: &rc})
		return nil
	})
	s.notifyMissionChange(m, "ADD_CONTENT", creator, &res, nil)
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) missionChanges(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	since, until := timeWindow(r)
	squashed := boolParam(r, "squashed")
	var list []MissionChange
	for _, c := range m.Changes {
		if (!since.IsZero() && c.Time.Before(since)) || (!until.IsZero() && c.Time.After(until)) {
			continue
		}
		list = append(list, c)
	}
	if squashed {
		seen := map[string]int{}
		var out []MissionChange
		for _, c := range list {
			k := c.ContentUID
			if k == "" {
				out = append(out, c)
				continue
			}
			if i, ok := seen[k]; ok {
				out[i] = c
				continue
			}
			seen[k] = len(out)
			out = append(out, c)
		}
		list = out
	}
	data := make([]map[string]any, 0, len(list))
	for _, c := range list {
		data = append(data, s.changeJSON(m, c))
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionChange", data))
}

func (s *Server) missionCoT(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><events>`)
	for _, it := range m.Items {
		if x, ok := s.missions.CoT(m.Name, it.UID); ok {
			b.WriteString(x)
		} else if c := s.hub.CachedEvent(it.UID); c != nil {
			b.Write(c.XML())
		}
	}
	b.WriteString("</events>")
	writeXML(w, http.StatusOK, b.String())
}

func (s *Server) missionKML(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>` + kmlEscape(m.Name) + `</name>`)
	for _, it := range m.Items {
		b.WriteString(`<Placemark><name>` + kmlEscape(firstNonEmpty(it.Callsign, it.UID)) + `</name><description>` + kmlEscape(it.Type) + `</description><Point><coordinates>` +
			cot.FormatFloat(it.Lon) + "," + cot.FormatFloat(it.Lat) + `,0</coordinates></Point></Placemark>`)
	}
	b.WriteString(`</Document></kml>`)
	w.Header().Set("Content-Type", "application/vnd.google-earth.kml+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFileName(m.Name)+`.kml"`)
	w.Write([]byte(b.String()))
}

func (s *Server) missionLogs(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	data := make([]map[string]any, 0, len(m.Logs))
	for _, l := range m.Logs {
		data = append(data, s.logJSON(m, l))
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.sync.model.LogEntry", data))
}

type logBody struct {
	ID            string   `json:"id"`
	Content       string   `json:"content"`
	CreatorUID    string   `json:"creatorUid"`
	MissionNames  []string `json:"missionNames"`
	DTG           string   `json:"dtg"`
	ContentHashes []string `json:"contentHashes"`
	Keywords      []string `json:"keywords"`
}

func (s *Server) missionLogCreate(w http.ResponseWriter, r *http.Request) {
	var body logBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || len(body.MissionNames) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a log entry with missionNames"})
		return
	}
	id := identityOf(r)
	entry := MissionLog{ID: firstNonEmpty(body.ID, cot.NewUID()), Content: body.Content, CreatorUID: body.CreatorUID, ServerTime: time.Now().UTC(), Created: time.Now().UTC(), ContentHashes: body.ContentHashes, Keywords: body.Keywords}
	entry.DTG, _ = cot.ParseTime(body.DTG)
	if entry.DTG.IsZero() {
		entry.DTG = entry.ServerTime
	}
	var out []map[string]any
	for _, name := range body.MissionNames {
		m, ok := s.missions.Get(name)
		if !ok || !s.missionVisible(id, m) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "mission not found: " + name})
			return
		}
		if !s.canWriteMission(r, m) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "your mission role does not allow MISSION_WRITE in " + name})
			return
		}
		if r.Method == http.MethodPut && body.ID != "" {
			m, _ = s.missions.Update(m.Name, func(x *Mission) error {
				for i := range x.Logs {
					if x.Logs[i].ID == body.ID {
						x.Logs[i].Content = body.Content
						x.Logs[i].Keywords = body.Keywords
						x.Logs[i].ContentHashes = body.ContentHashes
						entry = x.Logs[i]
					}
				}
				return nil
			})
		} else {
			m, _ = s.missions.Update(m.Name, func(x *Mission) error {
				x.Logs = append(x.Logs, entry)
				x.addChange(MissionChange{Type: "CHANGE", CreatorUID: body.CreatorUID})
				return nil
			})
		}
		out = append(out, s.logJSON(m, entry))
		s.rolMissionLog(m, entry, false)
		e := s.missionEvent(m, "t-x-m-c-l", "CHANGE", body.CreatorUID)
		s.sendToSubscribers(m, e, "")
	}
	status := http.StatusCreated
	if r.Method == http.MethodPut {
		status = http.StatusOK
	}
	writeJSON(w, status, s.envelope("com.bbn.marti.sync.model.LogEntry", out))
}

func (s *Server) missionLogDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	for _, m := range s.missions.All() {
		if !s.missionVisible(identityOf(r), m) {
			continue
		}
		if slices.ContainsFunc(m.Logs, func(l MissionLog) bool { return l.ID == id }) {
			if !s.canWriteMission(r, m) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "your mission role does not allow MISSION_WRITE"})
				return
			}
			s.missions.Update(m.Name, func(x *Mission) error {
				x.Logs = slices.DeleteFunc(x.Logs, func(l MissionLog) bool { return l.ID == id })
				return nil
			})
			s.rolMissionLog(m, MissionLog{ID: id}, true)
			found = true
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "log entry not found"})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) missionLogGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, m := range s.missions.All() {
		if !s.missionVisible(identityOf(r), m) {
			continue
		}
		for _, l := range m.Logs {
			if l.ID == id {
				writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.sync.model.LogEntry", []any{s.logJSON(m, l)}))
				return
			}
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "log entry not found"})
}

func (s *Server) missionAllLogs(w http.ResponseWriter, r *http.Request) {
	data := []map[string]any{}
	for _, m := range s.missions.All() {
		if !s.missionVisible(identityOf(r), m) {
			continue
		}
		for _, l := range m.Logs {
			data = append(data, s.logJSON(m, l))
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.sync.model.LogEntry", data))
}

func (s *Server) missionKeywords(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	var kws []string
	if r.Method == http.MethodPut {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&kws); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of keywords"})
			return
		}
	}
	single := r.PathValue("keyword")
	m, _ = s.missions.Update(m.Name, func(x *Mission) error {
		switch {
		case r.Method == http.MethodPut:
			x.Keywords = uniqueSorted(append(x.Keywords, kws...))
		case single != "":
			x.Keywords = slices.DeleteFunc(x.Keywords, func(k string) bool { return k == single })
		default:
			x.Keywords = []string{}
		}
		x.addChange(MissionChange{Type: "CHANGE", CreatorUID: s.callerUID(r)})
		return nil
	})
	s.sendToSubscribers(m, s.missionEvent(m, "t-x-m-c-k", "CHANGE", s.callerUID(r)), "")
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) missionPassword(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_SET_PASSWORD") {
		return
	}
	pw := r.URL.Query().Get("password")
	if r.Method == http.MethodPut && pw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
		return
	}
	s.missions.Update(m.Name, func(x *Mission) error {
		if r.Method == http.MethodDelete {
			x.PasswordHash = ""
		} else {
			x.PasswordHash = HashPassword(pw)
		}
		return nil
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) missionExpiration(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_SET_PASSWORD") {
		return
	}
	exp, err := parseInt64(r.URL.Query().Get("expiration"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expiration must be seconds since 1970 or -1"})
		return
	}
	if m, err := s.missions.Update(m.Name, func(x *Mission) error {
		x.Expiration = exp
		return nil
	}); err == nil {
		s.rolMissionExpiration(m)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) inviteMatches(inv MissionInvite, uid string, id *Identity) bool {
	switch strings.ToLower(inv.Type) {
	case "clientuid":
		return inv.Invitee == uid
	case "callsign":
		if dev, ok := s.devices.Get(uid); ok {
			return strings.EqualFold(dev.Callsign, inv.Invitee)
		}
	case "username":
		return id != nil && !id.Anon && strings.EqualFold(id.Name, inv.Invitee)
	case "group":
		return id != nil && slices.Contains(s.identityGroups(id), inv.Invitee)
	case "team":
		if dev, ok := s.devices.Get(uid); ok {
			return strings.EqualFold(dev.Team, inv.Invitee)
		}
	}
	return false
}

func (s *Server) isInvited(m Mission, uid string, id *Identity) bool {
	for _, inv := range m.Invites {
		if s.inviteMatches(inv, uid, id) {
			return true
		}
	}
	return false
}

func (s *Server) missionInvite(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	creator := s.callerUID(r)
	var invites []MissionInvite
	if r.Method == http.MethodPost {
		var body []struct {
			Type    string `json:"type"`
			Invitee string `json:"invitee"`
			Role    struct {
				Type string `json:"type"`
			} `json:"role"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of invitations"})
			return
		}
		for _, b := range body {
			invites = append(invites, MissionInvite{Type: b.Type, Invitee: b.Invitee, Role: normalizeRole(b.Role.Type), CreatorUID: creator, Created: time.Now().UTC()})
		}
	} else {
		invites = append(invites, MissionInvite{Type: r.PathValue("type"), Invitee: r.PathValue("invitee"), Role: normalizeRole(r.URL.Query().Get("role")), CreatorUID: creator, Created: time.Now().UTC()})
	}
	for _, inv := range invites {
		switch strings.ToLower(inv.Type) {
		case "clientuid", "callsign", "username", "group", "team":
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid invitation type " + inv.Type})
			return
		}
	}
	m, _ = s.missions.Update(m.Name, func(x *Mission) error {
		for _, inv := range invites {
			x.Invites = slices.DeleteFunc(x.Invites, func(old MissionInvite) bool {
				return strings.EqualFold(old.Type, inv.Type) && old.Invitee == inv.Invitee
			})
			x.Invites = append(x.Invites, inv)
		}
		return nil
	})
	for _, inv := range invites {
		s.deliverInvite(m, inv)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) deliverInvite(m Mission, inv MissionInvite) {
	role := firstNonEmpty(inv.Role, normalizeRole(m.DefaultRole))
	build := func(uid string) *cot.Event {
		e := s.missionEvent(m, "t-x-m-i", "INVITE", inv.CreatorUID)
		mn := e.Detail.Child("mission")
		mn.SetAttr("token", s.signMissionToken(missionClaims{Sub: uid, Mission: m.Name, GUID: m.GUID}))
		addRoleXML(mn, role)
		return e
	}
	for _, c := range s.hub.Clients() {
		if c.Relay {
			continue
		}
		uid := c.UID()
		if uid == "" {
			continue
		}
		info := c.Info()
		match := false
		switch strings.ToLower(inv.Type) {
		case "clientuid":
			match = uid == inv.Invitee
		case "callsign":
			match = strings.EqualFold(info.Callsign, inv.Invitee)
		case "username":
			match = strings.EqualFold(c.User(), inv.Invitee)
		case "group":
			match = slices.Contains(s.dir.Names(c.OutMask()), inv.Invitee)
		case "team":
			match = strings.EqualFold(info.Team, inv.Invitee)
		}
		if match {
			c.Send(NewMessage(build(uid), nil, nil))
		}
	}
}

func (s *Server) missionUninvite(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	typ, invitee := r.PathValue("type"), r.PathValue("invitee")
	s.missions.Update(m.Name, func(x *Mission) error {
		x.Invites = slices.DeleteFunc(x.Invites, func(inv MissionInvite) bool {
			return strings.EqualFold(inv.Type, typ) && inv.Invitee == invitee
		})
		return nil
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) missionInvitations(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	uid := r.URL.Query().Get("clientUid")
	only := r.PathValue("name")
	data := []map[string]any{}
	for _, m := range s.missions.All() {
		if only != "" && !strings.EqualFold(m.Name, only) {
			continue
		}
		if guid := r.PathValue("guid"); guid != "" && m.GUID != guid {
			continue
		}
		if !s.missionVisible(id, m) && uid == "" {
			continue
		}
		for _, inv := range m.Invites {
			if uid != "" && !s.inviteMatches(inv, uid, id) {
				continue
			}
			data = append(data, map[string]any{
				"missionName": m.Name, "missionGuid": m.GUID, "invitee": inv.Invitee, "type": inv.Type,
				"role": roleJSON(firstNonEmpty(inv.Role, m.DefaultRole)), "creatorUid": inv.CreatorUID,
				"createTime": isoTime(inv.Created), "token": s.signMissionToken(missionClaims{Sub: uid, Mission: m.Name, GUID: m.GUID}),
			})
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionInvitation", data))
}

func (s *Server) missionAllSubscriptions(w http.ResponseWriter, r *http.Request) {
	data := []map[string]any{}
	for _, m := range s.missions.All() {
		if !s.missionVisible(identityOf(r), m) {
			continue
		}
		for _, sub := range m.Subs {
			data = append(data, map[string]any{"missionName": m.Name, "missionGuid": m.GUID, "clientUid": sub.ClientUID, "username": sub.Username, "createTime": isoTime(sub.Created), "role": roleJSON(sub.Role)})
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionSubscription", data))
}

func (s *Server) missionContacts(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	data := []map[string]any{}
	for _, sub := range m.Subs {
		dev, _ := s.devices.Get(sub.ClientUID)
		data = append(data, map[string]any{"uid": sub.ClientUID, "callsign": dev.Callsign, "username": sub.Username, "team": dev.Team, "role": dev.Role, "lastEventTime": isoTime(dev.LastSeen), "lastStatus": firstNonEmpty(dev.LastStatus, "Disconnected")})
	}
	writeJSON(w, http.StatusOK, data)
}

func (s *Server) missionSetParent(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	parent := r.PathValue("parent")
	if r.Method == http.MethodPut {
		p, ok := s.missions.Get(parent)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "parent mission not found"})
			return
		}
		if strings.EqualFold(p.Name, m.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a mission cannot be its own parent"})
			return
		}
		parent = p.Name
	} else {
		parent = ""
	}
	if m, err := s.missions.Update(m.Name, func(x *Mission) error {
		x.Parent = parent
		return nil
	}); err == nil {
		s.rolMissionParent(m)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) missionParent(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if m.Parent == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no parent mission"})
		return
	}
	p, ok := s.missions.Get(m.Parent)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no parent mission"})
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", s.missionJSON(p, missionOpts{})))
}

func (s *Server) missionChildren(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	data := []map[string]any{}
	for _, c := range s.missions.All() {
		if strings.EqualFold(c.Parent, m.Name) && s.missionVisible(identityOf(r), c) {
			data = append(data, s.missionJSON(c, missionOpts{}))
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", data))
}

func (s *Server) missionExternalData(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	idParam := r.PathValue("id")
	var body map[string]any
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected JSON"})
			return
		}
		if _, ok := body["id"]; !ok {
			body["id"] = cot.NewUID()
		}
	}
	m, _ = s.missions.Update(m.Name, func(x *Mission) error {
		if r.Method == http.MethodDelete {
			x.ExternalData = slices.DeleteFunc(x.ExternalData, func(d map[string]any) bool { return d["id"] == idParam })
		} else {
			x.ExternalData = append(x.ExternalData, body)
		}
		x.addChange(MissionChange{Type: "CHANGE", CreatorUID: s.callerUID(r)})
		return nil
	})
	s.sendToSubscribers(m, s.missionEvent(m, "t-x-m-c-e", "CHANGE", s.callerUID(r)), "")
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) missionArchive(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	var entries []zipEntry
	var names []string
	for _, c := range m.Contents {
		res, ok := s.res.Get(c.UID)
		if !ok {
			continue
		}
		data, err := s.res.blobs.Read(res.Hash)
		if err != nil {
			continue
		}
		name := res.Hash[:16] + "/" + safeFileName(res.Name)
		entries = append(entries, zipEntry{name, data})
		names = append(names, name)
	}
	for _, it := range m.Items {
		if x, ok := s.missions.CoT(m.Name, it.UID); ok {
			name := "cot/" + safeFileName(it.UID) + ".cot"
			entries = append(entries, zipEntry{name, []byte(x)})
			names = append(names, name)
		}
	}
	manifest := manifestXML(m.GUID, m.Name, false, names)
	data, err := buildZip(append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifest)}}, entries...))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFileName(m.Name)+`.zip"`)
	w.Write(data)
}

func (s *Server) missionEvent(m Mission, cotType, msgType, author string) *cot.Event {
	e := cot.New(cot.NewUID(), cotType, "h-g-i-g-o", 20*time.Second)
	e.Access = "Undefined"
	e.Point.Hae = 0
	mn := e.Detail.AddNew("mission", "type", msgType, "tool", firstNonEmpty(m.Tool, "public"), "name", m.Name, "guid", m.GUID)
	if author != "" {
		mn.SetAttr("authorUid", author)
	}
	return e
}

func (s *Server) changeXML(m Mission, typ, author string, res *Resource, it *MissionItem) *xmltree.Node {
	mc := xmltree.New("MissionChange")
	text := func(name, v string) { mc.AddNew(name).Text = v }
	if res != nil {
		cr := mc.AddNew("contentResource")
		add := func(name, v string) { cr.AddNew(name).Text = v }
		add("creatorUid", res.CreatorUID)
		add("expiration", strconv.FormatInt(res.Expiration, 10))
		add("groupVector", "0")
		add("hash", res.Hash)
		for _, k := range res.Keywords {
			add("keywords", k)
		}
		add("mimeType", res.MIMEType)
		add("name", res.Name)
		add("size", strconv.FormatInt(res.Size, 10))
		add("submissionTime", isoTime(res.Submitted))
		add("submitter", res.Submitter)
		add("tool", firstNonEmpty(res.Tool, "public"))
		add("uid", res.UID)
		text("contentUid", res.UID)
	}
	if it != nil {
		d := mc.AddNew("details", "type", it.Type)
		if it.Callsign != "" {
			d.SetAttr("callsign", it.Callsign)
		}
		if it.Color != "" {
			d.SetAttr("color", it.Color)
		}
		if it.IconsetPath != "" {
			d.SetAttr("iconsetPath", it.IconsetPath)
		}
		d.AddNew("location", "lat", cot.FormatFloat(it.Lat), "lon", cot.FormatFloat(it.Lon))
		text("contentUid", it.UID)
	}
	text("creatorUid", author)
	text("isFederatedChange", "false")
	text("missionGuid", m.GUID)
	text("missionName", m.Name)
	text("timestamp", cot.FormatTime(time.Now()))
	text("type", typ)
	return mc
}

func (s *Server) notifyMissionChange(m Mission, typ, author string, res *Resource, it *MissionItem) {
	s.notifyMissionChangeLocal(m, typ, author, res, it)
	s.rolMissionChanged(m, typ, author, res, it)
}

func (s *Server) notifyMissionChangeLocal(m Mission, typ, author string, res *Resource, it *MissionItem) {
	e := s.missionEvent(m, "t-x-m-c", "CHANGE", author)
	e.Detail.Child("mission").AddNew("MissionChanges").Add(s.changeXML(m, typ, author, res, it))
	s.sendToSubscribers(m, e, "")
}

func (s *Server) notifyMissionAll(m Mission, cotType, msgType, author string) {
	s.notifyMissionAllLocal(m, cotType, msgType, author)
	switch msgType {
	case "CREATE":
		s.rolMissionCreated(m)
	case "DELETE":
		s.rolMissionDeleted(m, author)
	}
}

func (s *Server) notifyMissionAllLocal(m Mission, cotType, msgType, author string) {
	e := s.missionEvent(m, cotType, msgType, author)
	msg := NewMessage(e, nil, s.dir.Mask(m.Groups))
	msg.NoReplay = true
	if len(m.Groups) == 0 {
		msg.Everyone = true
	}
	s.hub.broadcast(msg)
}

func (s *Server) sendToUID(uid string, e *cot.Event) bool {
	c := s.hub.ByUID(uid)
	if c == nil {
		return false
	}
	return c.Send(NewMessage(e, nil, nil))
}

func (s *Server) sendToSubscribers(m Mission, e *cot.Event, exceptUID string) {
	msg := NewMessage(e, nil, nil)
	msg.NoReplay = true
	s.deliverToSubscribers(m, msg, exceptUID)
}

func (s *Server) deliverToSubscribers(m Mission, msg *Message, exceptUID string) {
	sent := map[*Client]bool{}
	for _, sub := range m.Subs {
		if sub.ClientUID == exceptUID {
			continue
		}
		if c := s.hub.ByUID(sub.ClientUID); c != nil && c != msg.Source && !sent[c] {
			sent[c] = true
			c.Send(msg)
		}
	}
}

func (s *Server) onMissionCoT(msg *Message, names []string) {
	e := msg.Event
	sender := ""
	if msg.Source != nil {
		sender = msg.Source.UID()
	}
	for _, name := range names {
		m, ok := s.missions.Get(name)
		if !ok {
			continue
		}
		if msg.Source != nil && !msg.Source.Relay {
			id := msg.Source.Identity()
			role := ""
			if sub := m.sub(sender); sub != nil {
				role = sub.Role
			} else if s.missionVisible(id, m) && !m.InviteOnly && m.PasswordHash == "" {
				role = normalizeRole(m.DefaultRole)
			}
			if id != nil && id.Admin {
				role = RoleOwner
			}
			if !slices.Contains(rolePermissions[role], "MISSION_WRITE") {
				continue
			}
		}
		if e.IsChat() || (e.IsControl() && !e.IsDelete()) {
			s.deliverToSubscribers(m, msg, "")
			continue
		}
		if e.IsDelete() {
			for _, l := range e.Links() {
				var removed *MissionItem
				m, _ = s.missions.Update(m.Name, func(x *Mission) error {
					if it := x.item(l.UID); it != nil {
						cp := *it
						removed = &cp
						x.Items = slices.DeleteFunc(x.Items, func(i MissionItem) bool { return i.UID == l.UID })
						x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: sender, ContentUID: l.UID, Item: &cp})
					}
					return nil
				})
				if removed != nil {
					s.missions.DeleteCoT(m.Name, l.UID)
					s.notifyMissionChange(m, "REMOVE_CONTENT", sender, nil, removed)
				}
			}
			s.deliverToSubscribers(m, msg, "")
			continue
		}
		var added *MissionItem
		m, _ = s.missions.Update(m.Name, func(x *Mission) error {
			if it := x.item(e.UID); it != nil {
				fillItem(it, e)
				return nil
			}
			it := MissionItem{UID: e.UID, CreatorUID: sender, Added: time.Now().UTC()}
			fillItem(&it, e)
			x.Items = append(x.Items, it)
			cp := it
			added = &cp
			x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: sender, ContentUID: e.UID, Item: &cp})
			return nil
		})
		s.missions.SetCoT(m.Name, e.UID, msg.XML())
		s.deliverToSubscribers(m, msg, "")
		if added != nil {
			s.notifyMissionChange(m, "ADD_CONTENT", sender, nil, added)
		}
	}
}

func (s *Server) ensureSystemMission(name, desc string, id *Identity) {
	s.missions.db.Update(name, func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			return m, true, nil
		}
		m = Mission{Name: name, GUID: cot.NewUID(), Description: desc, Tool: "public", Created: time.Now().UTC(), DefaultRole: RoleSubscriber, Expiration: -1, Keywords: []string{}}
		if id != nil && !id.Anon {
			m.Groups = s.identityGroups(id)
		}
		return m, true, nil
	})
}

func (s *Server) expireMissions() {
	now := time.Now().Unix()
	days := s.Config().Retention.MissionDays
	for _, m := range s.missions.All() {
		expired := m.Expiration > 0 && m.Expiration < now
		if !expired && days > 0 {
			last := m.Created
			if n := len(m.Changes); n > 0 {
				last = m.Changes[n-1].Time
			}
			expired = time.Since(last) > time.Duration(days)*24*time.Hour
		}
		if expired {
			s.missions.db.Delete(m.Name)
			s.missions.DeleteAllCoT(m.Name)
			s.log.Info("mission expired", "name", m.Name)
		}
	}
}
