package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

type MissionLayerRec struct {
	UID        string    `json:"uid"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Parent     string    `json:"parent,omitempty"`
	CreatorUID string    `json:"creatorUid,omitempty"`
	Created    time.Time `json:"created"`
}

var missionLayerTypes = []string{"GROUP", "UID", "CONTENTS", "MAPLAYER", "ITEM"}

func (s *Server) missionArchiveBytes(m Mission) ([]byte, error) {
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
	return buildZip(append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifest)}}, entries...))
}

func (s *Server) missionSend(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok || !s.requirePermission(w, r, m, "MISSION_READ") {
		return
	}
	contacts := r.URL.Query()["contacts"]
	if len(contacts) == 1 && strings.Contains(contacts[0], ",") {
		contacts = splitList(contacts[0])
	}
	if len(contacts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty contacts array"})
		return
	}
	data, err := s.missionArchiveBytes(m)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	hash, size, err := s.res.blobs.Put(bytes.NewReader(data), s.uploadLimit())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	id := identityOf(r)
	name := safeFileName(m.Name) + ".zip"
	res := Resource{UID: hash, Hash: hash, Name: name, MIMEType: "application/zip", Size: size, Keywords: []string{"missionpackage"}, Tool: "public",
		CreatorUID: s.callerUID(r), Submitter: id.Name, Submitted: time.Now().UTC(), Groups: m.Groups, Expiration: -1, Package: true}
	if old, ok := s.res.db.Get(hash); ok {
		res.Key = old.Key
	}
	if err := s.res.Put(res); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	url := s.contentURL(r, hash)
	e := cot.New(hash, "b-f-t-r", "h-e", 10*time.Minute)
	e.Point.Hae = 0
	e.Detail.AddNew("fileshare", "filename", name, "senderUrl", url, "sizeInBytes", itoa(int(size)), "sha256", hash,
		"senderUid", firstNonEmpty(s.callerUID(r), s.UID()), "senderCallsign", firstNonEmpty(id.Name, s.Config().Name), "name", m.Name)
	e.Detail.AddNew("ackrequest", "uid", cot.NewUID(), "ackrequested", "true", "tag", name)
	dests := make([]cot.Dest, 0, len(contacts))
	for _, c := range contacts {
		dests = append(dests, cot.Dest{UID: c})
	}
	e.SetDests(dests)
	msg := NewMessage(e, nil, nil)
	msg.Everyone = true
	msg.NoReplay = true
	s.hub.Publish(msg)
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{s.missionJSON(m, missionOpts{})}))
}

func (s *Server) missionCopy(w http.ResponseWriter, r *http.Request) {
	src, ok := s.loadMission(w, r)
	if !ok || !s.requirePermission(w, r, src, "MISSION_READ") {
		return
	}
	q := r.URL.Query()
	copyName := strings.TrimSpace(q.Get("copyName"))
	if copyName == "" || len(copyName) > 255 || strings.ContainsAny(copyName, "\x00\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "copyName is required"})
		return
	}
	id := identityOf(r)
	creator := s.callerUID(r)
	m, err := s.missions.db.Update(s.missions.key(copyName), func(old Mission, exists bool) (Mission, bool, error) {
		if exists {
			return old, false, errors.New("a mission with that name already exists")
		}
		c := src
		c.Name = copyName
		c.GUID = cot.NewUID()
		c.Created = time.Now().UTC()
		c.CreatorUID = creator
		c.CreatorUser = ""
		if !id.Anon {
			c.CreatorUser = id.Name
		}
		c.Origin = ""
		c.Parent = ""
		c.Subs = nil
		c.Invites = nil
		c.Logs = nil
		c.Changes = nil
		c.NextSeq = 0
		c.Keywords = slices.Clone(src.Keywords)
		c.Contents = slices.Clone(src.Contents)
		c.Items = slices.Clone(src.Items)
		c.Feeds = slices.Clone(src.Feeds)
		c.MapLayers = slices.Clone(src.MapLayers)
		c.Layers = slices.Clone(src.Layers)
		c.ExternalData = slices.Clone(src.ExternalData)
		c.Properties = nil
		c.PasswordHash = ""
		if q.Has("copyPath") {
			c.Path = q.Get("copyPath")
		}
		if role := normalizeRole(q.Get("defaultRole")); q.Has("defaultRole") && role != "" {
			c.DefaultRole = role
		}
		if pw := q.Get("password"); pw != "" {
			c.PasswordHash = HashPassword(pw)
		}
		if creator != "" {
			c.Subs = []MissionSub{{ClientUID: creator, Username: c.CreatorUser, Role: RoleOwner, Created: time.Now().UTC()}}
		}
		c.addChange(MissionChange{Type: "CREATE_MISSION", CreatorUID: creator})
		return c, true, nil
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	for _, it := range src.Items {
		if x, ok := s.missions.CoT(src.Name, it.UID); ok {
			s.missions.SetCoT(m.Name, it.UID, []byte(x))
		}
	}
	s.log.Info("mission copied", "from", src.Name, "to", m.Name, "by", id.Name)
	s.notifyMissionAll(m, "t-x-m-n", "CREATE", creator)
	out := s.missionJSON(m, missionOpts{})
	if creator != "" {
		out["token"] = s.signMissionToken(missionClaims{Sub: creator, Mission: m.Name, GUID: m.GUID})
		out["ownerRole"] = roleJSON(RoleOwner)
	}
	writeJSON(w, http.StatusOK, s.envelope("Mission", []any{out}))
}

func (s *Server) missionAccessToken(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	if m.PasswordHash != "" && s.callerRole(r, m) == "" && !checkHash(m.PasswordHash, r.URL.Query().Get("password")) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wrong mission password"})
		return
	}
	token := s.signMissionToken(missionClaims{Sub: cot.NewUID(), Mission: m.Name, GUID: m.GUID})
	writeJSON(w, http.StatusCreated, s.envelope("java.lang.String", token))
}

func readKeywordList(r *http.Request) ([]string, error) {
	var kws []string
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&kws); err != nil {
		return nil, errors.New("expected a JSON list of keywords")
	}
	return uniqueSorted(kws), nil
}

func (s *Server) missionItemKeywords(w http.ResponseWriter, r *http.Request, kind, key string) {
	m, ok := s.loadMission(w, r)
	if !ok || !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	var kws []string
	if r.Method == http.MethodPut {
		var err error
		if kws, err = readKeywordList(r); err != nil || len(kws) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty keywords array"})
			return
		}
	}
	found := false
	creator := s.callerUID(r)
	m, err := s.missions.Update(m.Name, func(x *Mission) error {
		switch kind {
		case "content":
			for i := range x.Contents {
				if x.Contents[i].Hash == key || x.Contents[i].UID == key {
					x.Contents[i].Keywords = kws
					found = true
				}
			}
		case "uid":
			for i := range x.Items {
				if x.Items[i].UID == key {
					x.Items[i].Keywords = kws
					found = true
				}
			}
		}
		if !found {
			return errors.New("not in this mission")
		}
		x.addChange(MissionChange{Type: "CHANGE", CreatorUID: creator, ContentUID: key})
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	s.sendToSubscribers(m, s.missionEvent(m, "t-x-m-c", "CHANGE", creator), "")
	w.WriteHeader(http.StatusOK)
}

func layerJSON(l MissionLayerRec, all []MissionLayerRec) map[string]any {
	out := map[string]any{"uid": l.UID, "name": l.Name, "type": l.Type}
	if l.Parent != "" {
		out["parentUid"] = l.Parent
	}
	var kids []map[string]any
	for _, c := range all {
		if c.Parent == l.UID {
			kids = append(kids, layerJSON(c, all))
		}
	}
	if len(kids) > 0 {
		out["mission_layers"] = kids
	}
	return out
}

func moveLayer(list []MissionLayerRec, l MissionLayerRec, after string) []MissionLayerRec {
	list = slices.DeleteFunc(list, func(x MissionLayerRec) bool { return x.UID == l.UID })
	pos := -1
	if after != "" {
		pos = slices.IndexFunc(list, func(x MissionLayerRec) bool { return x.UID == after })
	}
	if pos < 0 {
		first := slices.IndexFunc(list, func(x MissionLayerRec) bool { return x.Parent == l.Parent })
		if first < 0 {
			return append(list, l)
		}
		return slices.Insert(list, first, l)
	}
	return slices.Insert(list, pos+1, l)
}

func descendants(list []MissionLayerRec, uid string) map[string]bool {
	out := map[string]bool{uid: true}
	for changed := true; changed; {
		changed = false
		for _, l := range list {
			if !out[l.UID] && out[l.Parent] {
				out[l.UID] = true
				changed = true
			}
		}
	}
	return out
}

func (s *Server) missionLayers(w http.ResponseWriter, r *http.Request, seg []string) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	write := r.Method != http.MethodGet
	if write && !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	creator := s.callerUID(r)
	if !write {
		if len(seg) >= 1 {
			for _, l := range m.Layers {
				if l.UID == seg[0] {
					writeJSON(w, http.StatusOK, s.envelope("MissionLayer", layerJSON(l, m.Layers)))
					return
				}
			}
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "layer not found"})
			return
		}
		out := []map[string]any{}
		for _, l := range m.Layers {
			if l.Parent == "" {
				out = append(out, layerJSON(l, m.Layers))
			}
		}
		writeJSON(w, http.StatusOK, s.envelope("MissionLayer", out))
		return
	}
	var created MissionLayerRec
	m, err := s.missions.Update(m.Name, func(x *Mission) error {
		find := func(uid string) (MissionLayerRec, bool) {
			i := slices.IndexFunc(x.Layers, func(l MissionLayerRec) bool { return l.UID == uid })
			if i < 0 {
				return MissionLayerRec{}, false
			}
			return x.Layers[i], true
		}
		switch {
		case r.Method == http.MethodPut && len(seg) == 0:
			typ := strings.ToUpper(q.Get("type"))
			name := strings.TrimSpace(q.Get("name"))
			if name == "" || !slices.Contains(missionLayerTypes, typ) {
				return errors.New("name and a type of GROUP, UID, CONTENTS, MAPLAYER or ITEM are required")
			}
			uid := firstNonEmpty(q.Get("uid"), cot.NewUID())
			if _, dup := find(uid); dup {
				return errors.New("a layer with that uid already exists")
			}
			parent := q.Get("parentUid")
			if parent != "" {
				if _, ok := find(parent); !ok {
					return errors.New("parent layer not found")
				}
			}
			created = MissionLayerRec{UID: uid, Name: name, Type: typ, Parent: parent, CreatorUID: creator, Created: time.Now().UTC()}
			x.Layers = moveLayer(x.Layers, created, q.Get("afterUid"))
		case r.Method == http.MethodPut && len(seg) == 1 && seg[0] == "parent":
			parent := q.Get("parentUid")
			if parent != "" {
				if _, ok := find(parent); !ok {
					return errors.New("parent layer not found")
				}
			}
			after := q.Get("afterUid")
			for _, uid := range q["layerUid"] {
				l, ok := find(uid)
				if !ok {
					return fmt.Errorf("layer %s not found", uid)
				}
				if descendants(x.Layers, uid)[parent] {
					return errors.New("a layer cannot be moved under itself")
				}
				l.Parent = parent
				x.Layers = moveLayer(x.Layers, l, after)
				after = uid
			}
		case r.Method == http.MethodPut && len(seg) == 2 && seg[1] == "name":
			l, ok := find(seg[0])
			name := strings.TrimSpace(q.Get("name"))
			if !ok || name == "" {
				return errors.New("layer not found or empty name")
			}
			l.Name = name
			i := slices.IndexFunc(x.Layers, func(e MissionLayerRec) bool { return e.UID == l.UID })
			x.Layers[i] = l
		case r.Method == http.MethodPut && len(seg) == 2 && seg[1] == "position":
			l, ok := find(seg[0])
			if !ok {
				return errors.New("layer not found")
			}
			x.Layers = moveLayer(x.Layers, l, q.Get("afterUid"))
		case r.Method == http.MethodDelete && len(seg) == 0:
			remove := map[string]bool{}
			for _, uid := range q["uid"] {
				for k := range descendants(x.Layers, uid) {
					remove[k] = true
				}
			}
			x.Layers = slices.DeleteFunc(x.Layers, func(l MissionLayerRec) bool { return remove[l.UID] })
		default:
			return errUnsupported
		}
		x.addChange(MissionChange{Type: "CHANGE", CreatorUID: creator})
		return nil
	})
	if errors.Is(err, errUnsupported) {
		s.martiUnknown(w, r)
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.sendToSubscribers(m, s.missionEvent(m, "t-x-m-c", "CHANGE", creator), "")
	if created.UID != "" {
		writeJSON(w, http.StatusOK, s.envelope("MissionLayer", layerJSON(created, m.Layers)))
		return
	}
	w.WriteHeader(http.StatusOK)
}

var errUnsupported = errors.New("unsupported")

func (s *Server) missionAllSubscriptionsGUID(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || !id.Admin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrators only"})
		return
	}
	data := []map[string]any{}
	for _, m := range s.missions.All() {
		for _, sub := range m.Subs {
			data = append(data, map[string]any{"missionName": m.Name, "missionGuid": m.GUID, "clientUid": sub.ClientUID, "username": sub.Username})
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("MissionSubscription", data))
}
