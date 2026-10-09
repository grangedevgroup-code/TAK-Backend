package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if identityOf(r).Admin {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrators only"})
	return false
}

func splitTAKGroups(in, out []string) (both, inOnly, outOnly []string) {
	both, inOnly, outOnly = []string{}, []string{}, []string{}
	for _, g := range in {
		if slices.Contains(out, g) {
			both = append(both, g)
		} else {
			inOnly = append(inOnly, g)
		}
	}
	for _, g := range out {
		if !slices.Contains(in, g) {
			outOnly = append(outOnly, g)
		}
	}
	return
}

func joinTAKGroups(both, inOnly, outOnly []string) (in, out []string) {
	in = uniqueSorted(append(slices.Clone(both), inOnly...))
	out = uniqueSorted(append(slices.Clone(both), outOnly...))
	return
}

type takUserModel struct {
	Username     string   `json:"username"`
	Password     string   `json:"password,omitempty"`
	GroupList    []string `json:"groupList"`
	GroupListIN  []string `json:"groupListIN"`
	GroupListOUT []string `json:"groupListOUT"`
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) umError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func (s *Server) umCreate(m takUserModel) error {
	in, out := joinTAKGroups(m.GroupList, m.GroupListIN, m.GroupListOUT)
	groups := uniqueSorted(append(slices.Clone(in), out...))
	if _, err := s.dir.AddUser(m.Username, m.Password, false, groups); err != nil {
		return err
	}
	if len(in)+len(out) > 0 {
		_, err := s.dir.UpdateUser(m.Username, func(u *User) error {
			u.In, u.Out = in, out
			return nil
		})
		return err
	}
	return nil
}

func (s *Server) martiUserManagement(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	action := r.PathValue("action")
	arg := r.PathValue("arg")
	switch {
	case action == "new-user" && r.Method == http.MethodPost:
		var m takUserModel
		if err := readJSON(r, &m); err != nil {
			s.umError(w, err)
			return
		}
		if err := s.umCreate(m); err != nil {
			s.umError(w, err)
			return
		}
		s.log.Info("user created through the TAK user API", "user", m.Username, "by", identityOf(r).Name)
		w.WriteHeader(http.StatusOK)
	case action == "new-users" && r.Method == http.MethodPost:
		var m struct {
			UsernameExpression string   `json:"usernameExpression"`
			StartN             int      `json:"startN"`
			EndN               int      `json:"endN"`
			GroupList          []string `json:"groupList"`
			GroupListIN        []string `json:"groupListIN"`
			GroupListOUT       []string `json:"groupListOUT"`
		}
		if err := readJSON(r, &m); err != nil {
			s.umError(w, err)
			return
		}
		if !strings.Contains(m.UsernameExpression, "[N]") {
			s.umError(w, errors.New("username expression must contain [N]"))
			return
		}
		if m.EndN < m.StartN || m.EndN-m.StartN > 1000 {
			s.umError(w, errors.New("startN to endN must cover 1 to 1000 users"))
			return
		}
		out := []map[string]string{}
		for i := m.StartN; i <= m.EndN; i++ {
			name := strings.ReplaceAll(m.UsernameExpression, "[N]", strconv.Itoa(i))
			pw := NewSecret(12)
			if err := s.umCreate(takUserModel{Username: name, Password: pw, GroupList: m.GroupList, GroupListIN: m.GroupListIN, GroupListOUT: m.GroupListOUT}); err == nil {
				out = append(out, map[string]string{"username": name, "password": pw})
			}
		}
		if len(out) == 0 {
			s.umError(w, errors.New("no new user was created; check that the names are valid and not already in use"))
			return
		}
		writeJSON(w, http.StatusOK, out)
	case action == "list-users" && r.Method == http.MethodGet:
		out := []map[string]string{}
		for _, u := range s.dir.Users() {
			out = append(out, map[string]string{"username": u.Name})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["username"] < out[j]["username"] })
		writeJSON(w, http.StatusOK, out)
	case action == "get-groups-for-user" && r.Method == http.MethodGet:
		u, ok := s.dir.User(arg)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		both, in, out := splitTAKGroups(u.In, u.Out)
		writeJSON(w, http.StatusOK, takUserModel{Username: u.Name, GroupList: both, GroupListIN: in, GroupListOUT: out})
	case action == "change-user-password" && r.Method == http.MethodPut:
		var m takUserModel
		if err := readJSON(r, &m); err != nil {
			s.umError(w, err)
			return
		}
		if err := s.dir.SetPassword(m.Username, m.Password); err != nil {
			s.umError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	case action == "update-groups" && r.Method == http.MethodPut:
		var m takUserModel
		if err := readJSON(r, &m); err != nil {
			s.umError(w, err)
			return
		}
		in, out := joinTAKGroups(m.GroupList, m.GroupListIN, m.GroupListOUT)
		if err := s.dir.ensureGroups(uniqueSorted(append(slices.Clone(in), out...))); err != nil {
			s.umError(w, err)
			return
		}
		if _, err := s.dir.UpdateUser(m.Username, func(u *User) error {
			u.In, u.Out = in, out
			return nil
		}); err != nil {
			s.umError(w, err)
			return
		}
		s.refreshUserIdentity(m.Username)
		w.WriteHeader(http.StatusOK)
	case action == "update-group-users" && r.Method == http.MethodPut:
		var m struct {
			GroupName       string   `json:"groupname"`
			UsersInGroup    []string `json:"usersInGroup"`
			UsersInGroupIN  []string `json:"usersInGroupIN"`
			UsersInGroupOUT []string `json:"usersInGroupOUT"`
		}
		if err := readJSON(r, &m); err != nil || m.GroupName == "" {
			s.umError(w, errors.New("expected groupname and user lists"))
			return
		}
		if err := s.dir.ensureGroups([]string{m.GroupName}); err != nil {
			s.umError(w, err)
			return
		}
		for _, u := range s.dir.Users() {
			wantIn := slices.Contains(m.UsersInGroup, u.Name) || slices.Contains(m.UsersInGroupIN, u.Name)
			wantOut := slices.Contains(m.UsersInGroup, u.Name) || slices.Contains(m.UsersInGroupOUT, u.Name)
			hasIn, hasOut := slices.Contains(u.In, m.GroupName), slices.Contains(u.Out, m.GroupName)
			if wantIn == hasIn && wantOut == hasOut {
				continue
			}
			s.dir.UpdateUser(u.Name, func(x *User) error {
				x.In = setMember(x.In, m.GroupName, wantIn)
				x.Out = setMember(x.Out, m.GroupName, wantOut)
				return nil
			})
			s.refreshUserIdentity(u.Name)
		}
		w.WriteHeader(http.StatusOK)
	case action == "delete-user" && r.Method == http.MethodDelete:
		if arg == identityOf(r).Name {
			s.umError(w, errors.New("you cannot delete your own account"))
			return
		}
		if _, err := s.dir.DeleteUser(arg); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		s.log.Info("user deleted through the TAK user API", "user", arg, "by", identityOf(r).Name)
		w.WriteHeader(http.StatusOK)
	case action == "list-groupnames" && r.Method == http.MethodGet:
		out := []map[string]string{}
		for _, g := range s.dir.Groups() {
			out = append(out, map[string]string{"groupname": g.Name})
		}
		writeJSON(w, http.StatusOK, out)
	case action == "users-in-group" && r.Method == http.MethodGet:
		both, in, out := []string{}, []string{}, []string{}
		for _, u := range s.dir.Users() {
			hi, ho := slices.Contains(u.In, arg), slices.Contains(u.Out, arg)
			switch {
			case hi && ho:
				both = append(both, u.Name)
			case hi:
				in = append(in, u.Name)
			case ho:
				out = append(out, u.Name)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"groupname": arg, "usersInGroup": both, "usersInGroupIN": in, "usersInGroupOUT": out})
	default:
		s.martiUnknown(w, r)
	}
}

func setMember(list []string, g string, want bool) []string {
	has := slices.Contains(list, g)
	switch {
	case want && !has:
		return uniqueSorted(append(list, g))
	case !want && has:
		return slices.DeleteFunc(slices.Clone(list), func(x string) bool { return x == g })
	}
	return list
}

func (s *Server) refreshUserIdentity(name string) {
	id, err := s.dir.Identity(name, "")
	if err != nil {
		return
	}
	for _, c := range s.hub.Clients() {
		if c.User() == name && !c.Relay {
			cur := c.Identity()
			if cur != nil && cur.Cert == nil && cur.TokenID == "" {
				nid := *id
				nid.Via = cur.Via
				c.SetIdentity(&nid)
			}
		}
	}
}

type repeatable struct {
	UID       string `json:"uid"`
	RepeatTyp string `json:"repeatType"`
	CotType   string `json:"cotType"`
	Activated int64  `json:"dateTimeActivated"`
	XML       string `json:"xml"`
	Callsign  string `json:"callsign"`
}

func (s *Server) martiRepeaterList(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []repeatable{}
	for _, m := range s.hub.Emergencies() {
		if !m.Everyone && !id.Admin && !s.visibleTo(id, m.Groups) {
			continue
		}
		e := m.Event
		out = append(out, repeatable{UID: e.UID, RepeatTyp: "Emergency", CotType: e.Type, Activated: m.Received.UnixMilli(), XML: string(m.XML()), Callsign: e.Callsign()})
	}
	for _, rm := range s.repeatedList() {
		if len(rm.Groups) > 0 && !id.Admin && !s.visibleTo(id, s.dir.Mask(rm.Groups)) {
			continue
		}
		out = append(out, repeatable{UID: rm.UID, RepeatTyp: "Repeated", CotType: rm.Type, Activated: rm.Created.UnixMilli(), XML: rm.XML, Callsign: rm.Callsign})
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", out))
}

func (s *Server) martiRepeaterPeriod(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.envelope("java.lang.Integer", s.Config().Repeater.IntervalSec*1000))
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64))
	ms, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil || ms < 1000 || ms > 3600000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "period is milliseconds between 1000 and 3600000"})
		return
	}
	if _, err := s.UpdateConfig(func(c *Config) error {
		c.Repeater.IntervalSec = ms / 1000
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiRepeaterRemove(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	removed := false
	for _, m := range s.hub.Emergencies() {
		if m.Event.UID == uid {
			if !identityOf(r).Admin && !m.Everyone && !s.visibleTo(identityOf(r), m.Groups) {
				break
			}
			cancel := cot.New(cot.NewUID(), "b-a-o-can", "h-e", time.Minute)
			cancel.Point = m.Event.Point
			cancel.Detail.AddNew("link", "uid", uid, "type", m.Event.Type, "relation", "p-p")
			cancel.Detail.AddNew("emergency", "cancel", "true").Text = m.Event.Callsign()
			msg := NewMessage(cancel, nil, m.Groups)
			msg.Everyone = m.Everyone
			msg.NoReplay = true
			s.hub.cancelEmergency(uid)
			s.hub.Publish(msg)
			removed = true
		}
	}
	if !removed && identityOf(r).Admin {
		removed = s.removeRepeated(uid)
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", removed))
}

func (s *Server) martiSecurityConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	cfg := s.Config()
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.SecurityConfigInfo", map[string]any{
		"keystoreFile": "certs/server.pem", "truststoreFile": "certs/ca.pem", "tlsVersion": "TLSv1.2", "x509Groups": true, "x509addAnon": cfg.AllowAnonymous,
		"enableEnrollment": cfg.Ports.Enroll > 0, "caType": "TAKServer", "signingKeystoreFile": "certs/ca.pem", "validityDays": cfg.Certificates.ClientDays,
	}))
}

func (s *Server) martiAuthConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ld := s.Config().LDAP
	if !ld.Enabled {
		writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.AuthenticationConfigInfo", nil))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.AuthenticationConfigInfo", map[string]any{"url": ld.URL, "userString": ld.UserFilter, "updateInterval": 60, "groupPrefix": ld.GroupPrefix, "serviceAccountDN": ld.BindDN, "groupBaseRDN": ld.GroupBaseDN}))
}

func (s *Server) martiVerifyConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.pki.ServerCert() == nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("verifyConfig?", "Failed to verify config - no server certificate"))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("verifyConfig?", "Successfully verified config"))
}

func (s *Server) martiPagedMissions(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	includePw := q.Get("passwordProtected") != "false"
	tool := q.Get("tool")
	nameFilter := strings.ToLower(q.Get("nameFilter"))
	uidFilter := q.Get("uidFilter")
	keywords := q["keywordFilter"]
	groups := q["groupFilter"]
	var list []Mission
	for _, m := range s.missions.All() {
		if !s.missionVisible(id, m) || (m.PasswordHash != "" && !includePw) {
			continue
		}
		if tool != "" && !strings.EqualFold(firstNonEmpty(m.Tool, "public"), tool) {
			continue
		}
		if nameFilter != "" && !strings.Contains(strings.ToLower(m.Name), nameFilter) {
			continue
		}
		if uidFilter != "" && m.GUID != uidFilter && m.CreatorUID != uidFilter {
			continue
		}
		if len(keywords) > 0 && !slices.ContainsFunc(keywords, func(k string) bool { return slices.Contains(m.Keywords, k) }) {
			continue
		}
		if len(groups) > 0 && !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(m.Groups, g) }) {
			continue
		}
		list = append(list, m)
	}
	asc := q.Get("ascending") != "false"
	sortBy := q.Get("sort")
	sort.SliceStable(list, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "createTime", "created":
			less = list[i].Created.Before(list[j].Created)
		case "creatorUid":
			less = list[i].CreatorUID < list[j].CreatorUID
		default:
			less = strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		}
		if !asc {
			return !less
		}
		return less
	})
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(firstNonEmpty(q.Get("pagesize"), q.Get("limit")))
	if size <= 0 {
		size = 10
	}
	size = min(size, 500)
	page = max(page, 0)
	start := min(page*size, len(list))
	end := min(start+size, len(list))
	data := []map[string]any{}
	for _, m := range list[start:end] {
		data = append(data, s.missionJSON(m, missionOpts{}))
	}
	env := s.envelope("Mission", data)
	env["total"] = len(list)
	writeJSON(w, http.StatusOK, env)
}

func (s *Server) missionProperties(w http.ResponseWriter, r *http.Request, key string) {
	m, ok := s.loadMission(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if key != "" {
			v, ok := m.Properties[key]
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "no property with that key"})
				return
			}
			writeJSON(w, http.StatusOK, s.envelope("MissionProperty", map[string]string{"key": key, "value": v}))
			return
		}
		prefix := r.URL.Query().Get("prefix")
		keys := make([]string, 0, len(m.Properties))
		for k := range m.Properties {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		out := []map[string]string{}
		for _, k := range keys {
			out = append(out, map[string]string{"key": k, "value": m.Properties[k]})
		}
		writeJSON(w, http.StatusOK, s.envelope("MissionProperty", out))
	case http.MethodPut, http.MethodPost:
		if !s.requirePermission(w, r, m, "MISSION_WRITE") {
			return
		}
		var body struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := readJSON(r, &body); err != nil || body.Key == "" || len(body.Key) > 255 || len(body.Value) > 64<<10 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a key up to 255 characters and a value up to 64 KB"})
			return
		}
		creator := firstNonEmpty(r.URL.Query().Get("creatorUid"), s.callerUID(r))
		m, err := s.missions.Update(m.Name, func(x *Mission) error {
			if x.Properties == nil {
				x.Properties = map[string]string{}
			}
			if _, exists := x.Properties[body.Key]; !exists && len(x.Properties) >= 1000 {
				return errors.New("a mission can have up to 1000 properties")
			}
			x.Properties[body.Key] = body.Value
			x.addChange(MissionChange{Type: "CHANGE", CreatorUID: creator, ContentUID: body.Key})
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.sendToSubscribers(m, s.missionEvent(m, "t-x-m-c", "CHANGE", creator), "")
		writeJSON(w, http.StatusOK, s.envelope("MissionProperty", map[string]string{"key": body.Key, "value": body.Value}))
	case http.MethodDelete:
		if !s.requirePermission(w, r, m, "MISSION_WRITE") {
			return
		}
		creator := firstNonEmpty(r.URL.Query().Get("creatorUid"), s.callerUID(r))
		s.missions.Update(m.Name, func(x *Mission) error {
			if key == "" {
				x.Properties = nil
			} else {
				delete(x.Properties, key)
			}
			x.addChange(MissionChange{Type: "CHANGE", CreatorUID: creator, ContentUID: key})
			return nil
		})
		w.WriteHeader(http.StatusOK)
	default:
		s.martiUnknown(w, r)
	}
}

func (s *Server) videoPut(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	old, exists := s.videos.Get(uid)
	id := identityOf(r)
	if exists && !id.Admin && old.Creator != id.Name {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the creator or an administrator can change this video"})
		return
	}
	var vc struct {
		Active         *bool  `json:"active"`
		Alias          string `json:"alias"`
		Classification string `json:"classification"`
		Thumbnail      string `json:"thumbnail"`
		Feeds          []struct {
			Alias          string `json:"alias"`
			URL            string `json:"url"`
			MacAddress     string `json:"macAddress"`
			RoverPort      string `json:"roverPort"`
			IgnoreKLV      string `json:"ignoreEmbeddedKLV"`
			NetworkTimeout string `json:"networkTimeout"`
			BufferTime     string `json:"bufferTime"`
			RTSPReliable   string `json:"rtspReliable"`
			Latitude       string `json:"latitude"`
			Longitude      string `json:"longitude"`
			FOV            string `json:"fov"`
			Heading        string `json:"heading"`
			Range          string `json:"range"`
		} `json:"feeds"`
	}
	if err := readJSON(r, &vc); err != nil || len(vc.Feeds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a video connection with at least one feed"})
		return
	}
	fd := vc.Feeds[0]
	f := feedFromURL(fd.URL)
	f.UID = uid
	f.Alias = firstNonEmpty(vc.Alias, fd.Alias)
	f.Classification, f.Thumbnail = vc.Classification, vc.Thumbnail
	f.PreferredMAC, f.RoverPort = fd.MacAddress, fd.RoverPort
	f.IgnoreKLV = strings.EqualFold(fd.IgnoreKLV, "true")
	f.Timeout, f.Buffer, f.RTSPReliable = fd.NetworkTimeout, fd.BufferTime, fd.RTSPReliable
	f.Lat, f.Lon, f.FOV, f.Heading, f.Range = fd.Latitude, fd.Longitude, fd.FOV, fd.Heading, fd.Range
	f.Active = vc.Active == nil || *vc.Active
	f.Updated = time.Now().UTC()
	if exists {
		f.Groups, f.Creator = old.Groups, old.Creator
	} else {
		f.Groups, f.Creator = s.identityGroups(id), id.Name
	}
	if err := s.videos.Put(f); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.videoJSON(f))
}

func (s *Server) missionDeleteByQuery(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	m, ok := s.missions.ByGUID(guid)
	if guid == "" || !ok {
		if m2, ok2 := s.missions.Get(guid); ok2 {
			m, ok = m2, true
		}
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mission not found"})
		return
	}
	r.SetPathValue("name", m.Name)
	s.missionDelete(w, r)
}
