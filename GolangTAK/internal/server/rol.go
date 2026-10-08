package server

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
)

const rolTimeFormat = "2006-01-02T15:04:05.000Z"

type rolTarget struct {
	c       *Client
	allowed []string
	out     chan takproto.ROL
	done    <-chan struct{}
	node    string
}

type rolMissionMeta struct {
	Type            string `json:"type"`
	Name            string `json:"name"`
	CreatorUID      string `json:"creatorUid"`
	Description     string `json:"description"`
	ChatRoom        string `json:"chatRoom"`
	Tool            string `json:"tool"`
	BoundingPolygon string `json:"boundingPolygon"`
	BBox            string `json:"bbox"`
	PasswordHash    string `json:"passwordHash"`
	Path            string `json:"path"`
	Classification  string `json:"classification"`
	BaseLayer       string `json:"baseLayer"`
	ParentMissionID int64  `json:"parentMissionId"`
	DefaultRoleID   int64  `json:"defaultRoleId"`
	Expiration      int64  `json:"expiration"`
	InviteOnly      bool   `json:"inviteOnly"`
	GUID            string `json:"guid"`
}

type rolContent struct {
	Hashes []string `json:"hashes"`
	UIDs   []string `json:"uids"`
}

type rolMissionUpdate struct {
	Content            rolContent `json:"content"`
	CreatorUID         string     `json:"creatorUid"`
	ChangeType         string     `json:"changeType"`
	MissionName        string     `json:"missionName"`
	MissionCreatorUID  string     `json:"missionCreatorUid"`
	MissionChatRoom    string     `json:"missionChatRoom"`
	MissionTool        string     `json:"missionTool"`
	MissionDescription string     `json:"missionDescription"`
	Date               int64      `json:"date,omitempty"`
}

type rolLogEntry struct {
	ID            string   `json:"id"`
	Content       string   `json:"content"`
	CreatorUID    string   `json:"creatorUid"`
	EntryUID      string   `json:"entryUid,omitempty"`
	MissionNames  []string `json:"missionNames"`
	ServerTime    string   `json:"servertime,omitempty"`
	DTG           string   `json:"dtg,omitempty"`
	Created       string   `json:"created,omitempty"`
	ContentHashes []string `json:"contentHashes"`
	Keywords      []string `json:"keywords"`
}

type rolLogUpdate struct {
	ID       string      `json:"id"`
	LogEntry rolLogEntry `json:"logEntry"`
	Created  int64       `json:"created,omitempty"`
	Type     string      `json:"missionUpdateDetailsForLogEntryType"`
}

type rolHierarchy struct {
	MissionName       string `json:"missionName"`
	ParentMissionName string `json:"parentMissionName"`
}

type rolExpiration struct {
	MissionName       string `json:"missionName"`
	MissionExpiration int64  `json:"missionExpiration"`
}

type rolResource struct {
	ID             int      `json:"id"`
	Filename       string   `json:"filename"`
	Keywords       []string `json:"keywords"`
	MIMEType       string   `json:"mimeType"`
	Name           string   `json:"name"`
	SubmissionTime string   `json:"submissionTime,omitempty"`
	Submitter      string   `json:"submitter"`
	UID            string   `json:"uid"`
	CreatorUID     string   `json:"creatorUid"`
	Hash           string   `json:"hash"`
	Size           int64    `json:"size"`
	Tool           string   `json:"tool,omitempty"`
	Expiration     *int64   `json:"expiration,omitempty"`
	Latitude       *float64 `json:"latitude,omitempty"`
	Longitude      *float64 `json:"longitude,omitempty"`
	Altitude       *float64 `json:"altitude,omitempty"`
}

func rolJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimSpace(b.String())
}

func rolProgram(op, resource string, v any) string {
	return op + " " + resource + "\n" + rolJSON(v) + ";"
}

func parseROL(program string) (op, resource string, params []byte) {
	p := strings.TrimSpace(program)
	p = strings.TrimSpace(strings.TrimSuffix(p, ";"))
	head := p
	if i := strings.IndexAny(p, "{\n"); i >= 0 {
		head, params = p[:i], []byte(strings.TrimSpace(p[i:]))
	}
	f := strings.Fields(head)
	if len(f) > 0 {
		op = strings.ToLower(f[0])
	}
	if len(f) > 1 {
		resource = strings.ToLower(f[1])
	}
	return op, resource, params
}

func rolTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(rolTimeFormat)
}

func parseROLTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := cot.ParseTime(v); err == nil {
		return t
	}
	return time.Time{}
}

func (s *Server) rolTargets() []rolTarget {
	var out []rolTarget
	if s.fig2 != nil {
		for _, ss := range s.fig2.sessionsList() {
			out = append(out, s.fig2.target(ss))
		}
	}
	s.fig2Out.Range(func(_, v any) bool {
		if l, ok := v.(*fig2Link); ok && !l.inOnly {
			out = append(out, rolTarget{c: l.c, allowed: l.allowed, out: l.rolOut, done: l.done, node: l.node})
		}
		return true
	})
	return out
}

func (s *Server) missionFederates(m Mission) bool {
	cfg := s.Config()
	return cfg.Federation.Enabled && !cfg.Federation.NoMissions && (m.Tool == "" || m.Tool == "public")
}

func (s *Server) rolFor(t rolTarget, rol takproto.ROL, groups []string) (takproto.ROL, bool) {
	if len(groups) > 0 && !s.dir.Mask(groups).Intersects(t.c.OutMask()) {
		return rol, false
	}
	if t.node != "" && slices.ContainsFunc(rol.Provenance, func(p takproto.Provenance) bool { return p.ServerID == t.node }) {
		return rol, false
	}
	cfg := s.Config()
	rol.Groups = intersectNames(groups, t.allowed)
	rol.Provenance = append(slices.Clone(rol.Provenance), takproto.Provenance{ServerID: cfg.NodeID, ServerName: cfg.Name})
	if rol.MaxHops == 0 {
		rol.MaxHops = int64(cfg.Federation.MaxHops)
	}
	rol.CurrentHops++
	return rol, rol.CurrentHops <= rol.MaxHops
}

func (s *Server) broadcastROL(rol takproto.ROL, groups []string, except *Client) {
	for _, t := range s.rolTargets() {
		if t.c == except {
			continue
		}
		r, ok := s.rolFor(t, rol, groups)
		if !ok {
			continue
		}
		select {
		case t.out <- r:
		default:
			s.log.Warn("federation v2 mission queue full, dropping change", "federate", t.c.Name)
		}
	}
}

func (s *Server) resourceROL(res Resource, withContent bool) takproto.ROL {
	rr := rolResource{Filename: res.Name, Keywords: res.Keywords, MIMEType: res.MIMEType, Name: res.Name, SubmissionTime: rolTime(res.Submitted), Submitter: res.Submitter, UID: res.UID, CreatorUID: res.CreatorUID, Hash: res.Hash, Size: res.Size, Tool: res.Tool}
	if rr.Keywords == nil {
		rr.Keywords = []string{}
	}
	exp := res.Expiration
	rr.Expiration = &exp
	if res.Lat != 0 || res.Lon != 0 {
		lat, lon, alt := res.Lat, res.Lon, res.Alt
		rr.Latitude, rr.Longitude, rr.Altitude = &lat, &lon, &alt
	}
	rol := takproto.ROL{Program: rolProgram("create", "resource", rr)}
	if withContent {
		limit := int64(s.Config().Limits.MaxMessageBytes) - 64<<10
		if res.Size <= limit {
			if data, err := s.res.Blobs().Read(res.Hash); err == nil {
				rol.Payload = []takproto.Blob{{Type: takproto.BlobOther, Data: data, Filename: res.Name, Timestamp: res.Submitted.UnixMilli()}}
			}
		}
	}
	return rol
}

func missionMetaOf(m Mission) rolMissionMeta {
	md := rolMissionMeta{Type: "MissionMetadata", Name: m.Name, CreatorUID: m.CreatorUID, Description: m.Description, ChatRoom: m.ChatRoom, Tool: firstNonEmpty(m.Tool, "public"), BBox: m.BBox, Path: m.Path, Classification: m.Classification, BaseLayer: m.BaseLayer, Expiration: m.Expiration, InviteOnly: m.InviteOnly, GUID: m.GUID}
	if i := slices.Index(missionRoleOrder, m.DefaultRole); i >= 0 {
		md.DefaultRoleID = int64(i + 1)
	}
	return md
}

var missionRoleOrder = []string{RoleOwner, RoleSubscriber, RoleReadOnly}

func (s *Server) missionUpdateROL(m Mission, change, creator string, hashes, uids []string) takproto.ROL {
	mud := rolMissionUpdate{Content: rolContent{Hashes: hashes, UIDs: uids}, CreatorUID: creator, ChangeType: change, MissionName: m.Name, MissionCreatorUID: m.CreatorUID, MissionChatRoom: m.ChatRoom, MissionTool: firstNonEmpty(m.Tool, "public"), MissionDescription: m.Description, Date: time.Now().UnixMilli()}
	if mud.Content.Hashes == nil {
		mud.Content.Hashes = []string{}
	}
	if mud.Content.UIDs == nil {
		mud.Content.UIDs = []string{}
	}
	return takproto.ROL{Program: rolProgram("update", "mission", mud)}
}

func logEntryROL(m Mission, l MissionLog, kind string) takproto.ROL {
	le := rolLogEntry{ID: l.ID, Content: l.Content, CreatorUID: l.CreatorUID, MissionNames: []string{m.Name}, ServerTime: rolTime(l.ServerTime), DTG: rolTime(l.DTG), Created: rolTime(l.Created), ContentHashes: l.ContentHashes, Keywords: l.Keywords}
	if le.ContentHashes == nil {
		le.ContentHashes = []string{}
	}
	if le.Keywords == nil {
		le.Keywords = []string{}
	}
	return takproto.ROL{Program: rolProgram("update", "mission", rolLogUpdate{ID: l.ID, LogEntry: le, Created: l.Created.UnixMilli(), Type: kind})}
}

func (s *Server) rolMissionCreated(m Mission) {
	if s.missionFederates(m) {
		s.broadcastROL(takproto.ROL{Program: rolProgram("create", "mission", missionMetaOf(m))}, m.Groups, nil)
	}
}

func (s *Server) rolMissionDeleted(m Mission, creator string) {
	if s.missionFederates(m) {
		md := rolMissionMeta{Type: "MissionMetadata", Name: m.Name, CreatorUID: creator, Tool: firstNonEmpty(m.Tool, "public")}
		s.broadcastROL(takproto.ROL{Program: rolProgram("delete", "mission", md)}, m.Groups, nil)
	}
}

func (s *Server) rolMissionChanged(m Mission, typ, creator string, res *Resource, it *MissionItem) {
	if !s.missionFederates(m) || (typ != "ADD_CONTENT" && typ != "REMOVE_CONTENT") {
		return
	}
	var hashes, uids []string
	if res != nil {
		if typ == "ADD_CONTENT" {
			s.broadcastROL(s.resourceROL(*res, true), m.Groups, nil)
		}
		hashes = []string{res.Hash}
	}
	if it != nil {
		uids = []string{it.UID}
	}
	s.broadcastROL(s.missionUpdateROL(m, typ, creator, hashes, uids), m.Groups, nil)
}

func (s *Server) rolMissionLog(m Mission, l MissionLog, deleted bool) {
	if !s.missionFederates(m) {
		return
	}
	kind := "ADD_UPDATE_LOG_ENTRY"
	if deleted {
		kind = "DELETE_LOG_ENTRY"
	}
	s.broadcastROL(logEntryROL(m, l, kind), m.Groups, nil)
}

func (s *Server) rolMissionParent(m Mission) {
	if s.missionFederates(m) {
		s.broadcastROL(takproto.ROL{Program: rolProgram("assign", "mission", rolHierarchy{MissionName: m.Name, ParentMissionName: m.Parent})}, m.Groups, nil)
	}
}

func (s *Server) rolMissionExpiration(m Mission) {
	if s.missionFederates(m) {
		s.broadcastROL(takproto.ROL{Program: rolProgram("assign", "mission", rolExpiration{MissionName: m.Name, MissionExpiration: m.Expiration})}, m.Groups, nil)
	}
}

func (s *Server) rolSnapshot(ctx context.Context, t rolTarget) {
	cfg := s.Config()
	if !cfg.Federation.Enabled || cfg.Federation.NoMissions {
		return
	}
	push := func(rol takproto.ROL, groups []string) bool {
		r, ok := s.rolFor(t, rol, groups)
		if !ok {
			return true
		}
		select {
		case t.out <- r:
			return true
		case <-ctx.Done():
		case <-t.done:
		}
		return false
	}
	for _, m := range s.missions.All() {
		if !s.missionFederates(m) || (t.node != "" && m.Origin == t.node) {
			continue
		}
		if !push(takproto.ROL{Program: rolProgram("create", "mission", missionMetaOf(m))}, m.Groups) {
			return
		}
		var hashes, uids []string
		for _, c := range m.Contents {
			if res, ok := s.res.Get(c.UID); ok {
				if !push(s.resourceROL(res, true), m.Groups) {
					return
				}
				hashes = append(hashes, res.Hash)
			}
		}
		for _, it := range m.Items {
			uids = append(uids, it.UID)
		}
		if len(hashes)+len(uids) > 0 && !push(s.missionUpdateROL(m, "ADD_CONTENT", m.CreatorUID, hashes, uids), m.Groups) {
			return
		}
		for _, l := range m.Logs {
			if !push(logEntryROL(m, l, "ADD_UPDATE_LOG_ENTRY"), m.Groups) {
				return
			}
		}
		if m.Parent != "" && !push(takproto.ROL{Program: rolProgram("assign", "mission", rolHierarchy{MissionName: m.Name, ParentMissionName: m.Parent})}, m.Groups) {
			return
		}
	}
}

func (s *Server) rolGroups(c *Client, groups, allowed []string) []string {
	var out []string
	for _, g := range groups {
		if len(allowed) > 0 && !slices.Contains(allowed, g) {
			continue
		}
		if _, ok := s.dir.Group(g); ok {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		out = s.dir.Names(c.InMask())
	}
	return out
}

func (s *Server) handleROL(src *Client, rol takproto.ROL, allowed []string, node string) {
	cfg := s.Config()
	for _, p := range rol.Provenance {
		if p.ServerID == cfg.NodeID {
			return
		}
	}
	if cfg.Federation.NoMissions {
		return
	}
	op, resource, params := parseROL(rol.Program)
	groups := s.rolGroups(src, rol.Groups, allowed)
	applied := false
	switch resource {
	case "mission":
		origin := node
		if len(rol.Provenance) > 0 {
			origin = rol.Provenance[0].ServerID
		}
		applied = s.rolMission(src, op, params, groups, origin)
	case "resource":
		applied = s.rolResource(src, op, params, rol.Payload, groups)
	default:
		s.log.Debug("federated ROL not handled", "from", src.Name, "op", op, "resource", resource)
	}
	if applied {
		s.broadcastROL(rol, groups, src)
	}
}

func (s *Server) rolMission(src *Client, op string, params []byte, groups []string, origin string) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(params, &probe); err != nil {
		s.log.Debug("federated mission ROL has bad parameters", "from", src.Name, "err", err)
		return false
	}
	switch op {
	case "create":
		var md rolMissionMeta
		if json.Unmarshal(params, &md) != nil || md.Name == "" {
			return false
		}
		return s.rolCreateMission(md, groups, origin)
	case "delete":
		var md rolMissionMeta
		if json.Unmarshal(params, &md) != nil || md.Name == "" || !s.Config().Federation.AllowDelete {
			return false
		}
		m, ok := s.missions.Get(md.Name)
		if !ok || !s.missionFederates(m) || !s.groupsOverlap(m.Groups, groups) {
			return false
		}
		if err := s.missions.db.Delete(m.Name); err != nil {
			return false
		}
		s.missions.DeleteAllCoT(m.Name)
		s.log.Info("federated mission deleted", "name", m.Name, "from", src.Name)
		s.notifyMissionAllLocal(m, "t-x-m-d", "DELETE", md.CreatorUID)
		return true
	case "update":
		if _, ok := probe["changeType"]; ok {
			var mud rolMissionUpdate
			if json.Unmarshal(params, &mud) != nil {
				return false
			}
			return s.rolMissionContent(src, mud, groups, origin)
		}
		if _, ok := probe["missionUpdateDetailsForLogEntryType"]; ok {
			var lu rolLogUpdate
			if json.Unmarshal(params, &lu) != nil {
				return false
			}
			return s.rolLog(lu, groups)
		}
	case "assign":
		if _, ok := probe["missionExpiration"]; ok {
			var me rolExpiration
			if json.Unmarshal(params, &me) != nil {
				return false
			}
			m, ok := s.missions.Get(me.MissionName)
			if !ok || !s.groupsOverlap(m.Groups, groups) {
				return false
			}
			s.missions.Update(m.Name, func(x *Mission) error {
				x.Expiration = me.MissionExpiration
				return nil
			})
			return true
		}
		var mh rolHierarchy
		if json.Unmarshal(params, &mh) != nil || mh.MissionName == "" {
			return false
		}
		m, ok := s.missions.Get(mh.MissionName)
		if !ok || !s.groupsOverlap(m.Groups, groups) {
			return false
		}
		parent := ""
		if mh.ParentMissionName != "" {
			p, ok := s.missions.Get(mh.ParentMissionName)
			if !ok {
				return false
			}
			parent = p.Name
		}
		s.missions.Update(m.Name, func(x *Mission) error {
			x.Parent = parent
			return nil
		})
		return true
	}
	s.log.Debug("federated mission ROL not handled", "from", src.Name, "op", op)
	return false
}

func (s *Server) groupsOverlap(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	return s.dir.Mask(a).Intersects(s.dir.Mask(b))
}

func roleFromID(id int64) string {
	if id > 0 && int(id) <= len(missionRoleOrder) {
		return missionRoleOrder[id-1]
	}
	return RoleSubscriber
}

func (s *Server) rolCreateMission(md rolMissionMeta, groups []string, origin string) bool {
	if md.Tool != "" && md.Tool != "public" {
		return false
	}
	created := false
	m, err := s.missions.db.Update(s.missions.key(md.Name), func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			return m, false, nil
		}
		created = true
		guid := md.GUID
		if guid == "" {
			guid = cot.NewUID()
		}
		exp := md.Expiration
		if exp == 0 {
			exp = -1
		}
		m = Mission{Name: md.Name, GUID: guid, Description: md.Description, ChatRoom: md.ChatRoom, BaseLayer: md.BaseLayer, BBox: md.BBox, Path: md.Path, Classification: md.Classification, Tool: "public", Keywords: []string{}, CreatorUID: md.CreatorUID, Created: time.Now().UTC(), Groups: groups, DefaultRole: roleFromID(md.DefaultRoleID), InviteOnly: md.InviteOnly, Expiration: exp, PasswordHash: md.PasswordHash, Origin: origin}
		m.addChange(MissionChange{Type: "CREATE_MISSION", CreatorUID: md.CreatorUID})
		return m, true, nil
	})
	if err != nil || !created {
		return false
	}
	s.log.Info("federated mission created", "name", m.Name)
	s.notifyMissionAllLocal(m, "t-x-m-n", "CREATE", md.CreatorUID)
	return true
}

func (s *Server) rolMissionContent(src *Client, mud rolMissionUpdate, groups []string, origin string) bool {
	if mud.MissionName == "" || (mud.MissionTool != "" && mud.MissionTool != "public") {
		return false
	}
	switch mud.ChangeType {
	case "ADD_CONTENT":
		if _, ok := s.missions.Get(mud.MissionName); !ok {
			s.rolCreateMission(rolMissionMeta{Name: mud.MissionName, CreatorUID: mud.MissionCreatorUID, ChatRoom: mud.MissionChatRoom, Description: mud.MissionDescription, Tool: "public"}, groups, origin)
		}
		m, ok := s.missions.Get(mud.MissionName)
		if !ok || !s.groupsOverlap(m.Groups, groups) {
			return false
		}
		var newRes []Resource
		var newItems []MissionItem
		m, err := s.missions.Update(m.Name, func(x *Mission) error {
			for _, h := range mud.Content.Hashes {
				h = strings.ToLower(h)
				if !store.ValidHash(h) || slices.ContainsFunc(x.Contents, func(c MissionContent) bool { return c.Hash == h }) {
					continue
				}
				res, ok := s.res.Get(h)
				if !ok {
					res = Resource{UID: h, Hash: h}
				}
				x.Contents = append(x.Contents, MissionContent{UID: res.UID, Hash: h, CreatorUID: mud.CreatorUID, Added: time.Now().UTC()})
				rc := res
				x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: mud.CreatorUID, ContentUID: res.UID, Resource: &rc})
				newRes = append(newRes, res)
			}
			for _, uid := range mud.Content.UIDs {
				if uid == "" || x.item(uid) != nil {
					continue
				}
				it := s.itemFromCache(uid, mud.CreatorUID)
				x.Items = append(x.Items, it)
				ic := it
				x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: mud.CreatorUID, ContentUID: uid, Item: &ic})
				newItems = append(newItems, it)
			}
			return nil
		})
		if err != nil {
			return false
		}
		for _, it := range newItems {
			if c := s.hub.CachedEvent(it.UID); c != nil {
				s.missions.SetCoT(m.Name, it.UID, c.XML())
			}
			s.notifyMissionChangeLocal(m, "ADD_CONTENT", mud.CreatorUID, nil, &it)
		}
		for _, res := range newRes {
			s.notifyMissionChangeLocal(m, "ADD_CONTENT", mud.CreatorUID, &res, nil)
		}
		return len(newRes)+len(newItems) > 0
	case "REMOVE_CONTENT":
		if !s.Config().Federation.AllowDelete {
			return false
		}
		m, ok := s.missions.Get(mud.MissionName)
		if !ok || !s.groupsOverlap(m.Groups, groups) {
			return false
		}
		var removedRes []Resource
		var removedItems []MissionItem
		m, err := s.missions.Update(m.Name, func(x *Mission) error {
			for _, h := range mud.Content.Hashes {
				h = strings.ToLower(h)
				idx := slices.IndexFunc(x.Contents, func(c MissionContent) bool { return c.Hash == h })
				if idx < 0 {
					continue
				}
				res, ok := s.res.Get(x.Contents[idx].UID)
				if !ok {
					res = Resource{UID: x.Contents[idx].UID, Hash: h}
				}
				x.Contents = slices.Delete(x.Contents, idx, idx+1)
				rc := res
				x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: mud.CreatorUID, ContentUID: res.UID, Resource: &rc})
				removedRes = append(removedRes, res)
			}
			for _, uid := range mud.Content.UIDs {
				it := x.item(uid)
				if it == nil {
					continue
				}
				cp := *it
				x.Items = slices.DeleteFunc(x.Items, func(i MissionItem) bool { return i.UID == uid })
				x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: mud.CreatorUID, ContentUID: uid, Item: &cp})
				removedItems = append(removedItems, cp)
			}
			return nil
		})
		if err != nil {
			return false
		}
		for _, it := range removedItems {
			s.missions.DeleteCoT(m.Name, it.UID)
			s.notifyMissionChangeLocal(m, "REMOVE_CONTENT", mud.CreatorUID, nil, &it)
		}
		for _, res := range removedRes {
			s.notifyMissionChangeLocal(m, "REMOVE_CONTENT", mud.CreatorUID, &res, nil)
		}
		return len(removedRes)+len(removedItems) > 0
	}
	return false
}

func (s *Server) rolLog(lu rolLogUpdate, groups []string) bool {
	id := firstNonEmpty(lu.ID, lu.LogEntry.ID)
	if id == "" {
		return false
	}
	changed := false
	for _, name := range lu.LogEntry.MissionNames {
		m, ok := s.missions.Get(name)
		if !ok || !s.groupsOverlap(m.Groups, groups) {
			continue
		}
		m, _ = s.missions.Update(m.Name, func(x *Mission) error {
			idx := slices.IndexFunc(x.Logs, func(l MissionLog) bool { return l.ID == id })
			if lu.Type == "DELETE_LOG_ENTRY" {
				if idx >= 0 {
					x.Logs = slices.Delete(x.Logs, idx, idx+1)
					changed = true
				}
				return nil
			}
			entry := MissionLog{ID: id, Content: lu.LogEntry.Content, CreatorUID: lu.LogEntry.CreatorUID, ServerTime: time.Now().UTC(), DTG: parseROLTime(lu.LogEntry.DTG), Created: parseROLTime(lu.LogEntry.Created), ContentHashes: lu.LogEntry.ContentHashes, Keywords: lu.LogEntry.Keywords}
			if entry.Created.IsZero() {
				entry.Created = entry.ServerTime
			}
			if entry.DTG.IsZero() {
				entry.DTG = entry.Created
			}
			if idx >= 0 {
				if x.Logs[idx].Content == entry.Content && slices.Equal(x.Logs[idx].Keywords, entry.Keywords) {
					return nil
				}
				x.Logs[idx] = entry
			} else {
				x.Logs = append(x.Logs, entry)
			}
			x.addChange(MissionChange{Type: "CHANGE", CreatorUID: entry.CreatorUID})
			changed = true
			return nil
		})
		if changed {
			s.sendToSubscribers(m, s.missionEvent(m, "t-x-m-c-l", "CHANGE", lu.LogEntry.CreatorUID), "")
		}
	}
	return changed
}

func (s *Server) rolResource(src *Client, op string, params []byte, payload []takproto.Blob, groups []string) bool {
	var rr rolResource
	if err := json.Unmarshal(params, &rr); err != nil {
		return false
	}
	hash := strings.ToLower(rr.Hash)
	switch op {
	case "create":
		if len(payload) == 0 || int64(len(payload[0].Data)) > s.uploadLimit() {
			return false
		}
		got, err := s.res.Blobs().PutBytes(payload[0].Data)
		if err != nil {
			return false
		}
		if hash != "" && got != hash {
			s.log.Warn("federated file does not match its hash, ignoring it", "from", src.Name, "name", rr.Name)
			if _, ok := s.res.Get(got); !ok {
				s.res.Blobs().Delete(got)
			}
			return false
		}
		if existing, ok := s.res.Get(got); ok && existing.Hash == got {
			return false
		}
		res := Resource{UID: firstNonEmpty(rr.UID, got), Hash: got, Name: firstNonEmpty(rr.Name, rr.Filename, got), MIMEType: firstNonEmpty(rr.MIMEType, "application/octet-stream"), Size: int64(len(payload[0].Data)), Keywords: rr.Keywords, Tool: rr.Tool, CreatorUID: rr.CreatorUID, Submitter: rr.Submitter, Submitted: parseROLTime(rr.SubmissionTime), Groups: groups, Expiration: -1}
		if res.Keywords == nil {
			res.Keywords = []string{}
		}
		if res.Submitted.IsZero() {
			res.Submitted = time.Now().UTC()
		}
		if rr.Expiration != nil && *rr.Expiration != 0 {
			res.Expiration = *rr.Expiration
		}
		if rr.Latitude != nil && rr.Longitude != nil {
			res.Lat, res.Lon = *rr.Latitude, *rr.Longitude
			if rr.Altitude != nil {
				res.Alt = *rr.Altitude
			}
		}
		if err := s.res.Put(res); err != nil {
			return false
		}
		s.log.Info("federated file received", "name", res.Name, "size", res.Size, "from", src.Name)
		return true
	case "update":
		if !store.ValidHash(hash) {
			return false
		}
		res, ok := s.res.Get(hash)
		if !ok {
			return false
		}
		_, err := s.res.Update(res.UID, func(x *Resource) {
			if rr.Expiration != nil && *rr.Expiration != 0 {
				x.Expiration = *rr.Expiration
			}
			if len(rr.Keywords) > 0 {
				x.Keywords = rr.Keywords
			}
			if rr.Name != "" {
				x.Name = rr.Name
			}
			if rr.MIMEType != "" {
				x.MIMEType = rr.MIMEType
			}
			if rr.Tool != "" {
				x.Tool = rr.Tool
			}
		})
		return err == nil
	}
	return false
}
