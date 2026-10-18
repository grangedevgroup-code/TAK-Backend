package server

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/ldap"
)

type takLdapUser struct {
	DN          string   `json:"dn,omitempty"`
	CommonName  string   `json:"commonName"`
	GivenName   string   `json:"givenName"`
	Surname     string   `json:"surname"`
	Email       string   `json:"email"`
	Description string   `json:"description"`
	UID         string   `json:"uid"`
	Password    string   `json:"password,omitempty"`
	CallSign    string   `json:"callSign"`
	Role        string   `json:"role"`
	Color       string   `json:"color"`
	Groups      []string `json:"groups"`
	Locked      string   `json:"pwdAccountLockedTime,omitempty"`
}

func (s *Server) ldapUserBase(c LDAPConfig) string {
	if c.BaseDN != "" {
		return c.BaseDN
	}
	return ""
}

func (s *Server) ldapGroupBase(c LDAPConfig) string {
	return firstNonEmpty(c.GroupBaseDN, c.BaseDN)
}

func (s *Server) ldapAttrNames(c LDAPConfig) (callsign, color, role string) {
	return firstNonEmpty(c.CallsignAttribute, "takCallSign"), firstNonEmpty(c.ColorAttribute, "takColor"), firstNonEmpty(c.RoleAttribute, "takRole")
}

func (s *Server) ldapAdmin(w http.ResponseWriter) (*ldap.Admin, LDAPConfig, bool) {
	c := s.Config().LDAP
	if !c.Enabled || c.URL == "" || s.ldapUserBase(c) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "LDAP is not configured with a base DN"})
		return nil, c, false
	}
	lc, err := s.ldapConfig(c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return nil, c, false
	}
	a, err := ldap.OpenAdmin(lc)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "LDAP: " + err.Error()})
		return nil, c, false
	}
	return a, c, true
}

func (s *Server) ldapUserFromEntry(c LDAPConfig, e ldap.Entry) takLdapUser {
	cs, col, role := s.ldapAttrNames(c)
	u := takLdapUser{DN: e.DN, CommonName: e.First("cn"), GivenName: e.First("givenName"), Surname: e.First("sn"), Email: e.First("mail"),
		Description: e.First("description"), UID: e.First("uid"), CallSign: e.First(cs), Color: e.First(col), Role: e.First(role),
		Locked: e.First("pwdAccountLockedTime"), Groups: []string{}}
	for _, g := range e.Get("memberOf") {
		u.Groups = append(u.Groups, ldap.CommonName(g))
	}
	return u
}

func (s *Server) ldapFindUser(a *ldap.Admin, c LDAPConfig, uid string) (*ldap.Entry, error) {
	cs, col, role := s.ldapAttrNames(c)
	list, err := a.Search(s.ldapUserBase(c), "(uid="+ldap.EscapeFilter(uid)+")", []string{"uid", "cn", "sn", "givenName", "mail", "description", "memberOf", "pwdAccountLockedTime", cs, col, role}, 2)
	if err != nil {
		return nil, err
	}
	if len(list) != 1 {
		return nil, ldap.ErrUserNotFound
	}
	return &list[0], nil
}

func (s *Server) ldapGroupDN(c LDAPConfig, name string) string {
	return "cn=" + ldap.EscapeDN(name) + "," + s.ldapGroupBase(c)
}

func (s *Server) ldapAddMember(a *ldap.Admin, c LDAPConfig, group, userDN string) error {
	dn := s.ldapGroupDN(c, group)
	if _, err := a.Read(dn, []string{"member"}); err != nil {
		return a.Add(dn, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {group}, "member": {userDN}})
	}
	err := a.Modify(dn, []ldap.Change{{Op: ldap.ModAdd, Attr: "member", Values: []string{userDN}}})
	var le *ldap.Error
	if errors.As(err, &le) && le.Code == 20 {
		return nil
	}
	return err
}

func (s *Server) ldapRemoveMember(a *ldap.Admin, c LDAPConfig, group, userDN string) error {
	dn := s.ldapGroupDN(c, group)
	g, err := a.Read(dn, []string{"member"})
	if err != nil {
		return nil
	}
	left := slices.DeleteFunc(slices.Clone(g.Get("member")), func(m string) bool { return strings.EqualFold(m, userDN) })
	if len(left) == 0 {
		s.log.Info("LDAP group is now empty; deleting it", "group", group)
		return a.Delete(dn)
	}
	return a.Modify(dn, []ldap.Change{{Op: ldap.ModDelete, Attr: "member", Values: []string{userDN}}})
}

func (s *Server) ldapCreateUser(a *ldap.Admin, c LDAPConfig, u takLdapUser) (string, error) {
	if !validName.MatchString(u.UID) {
		return "", fmt.Errorf("invalid uid %q", u.UID)
	}
	if u.Password == "" {
		return "", errors.New("a password is required")
	}
	dn := "uid=" + ldap.EscapeDN(u.UID) + "," + s.ldapUserBase(c)
	cs, col, role := s.ldapAttrNames(c)
	attrs := map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson", "takUser"}, "uid": {u.UID},
		"cn": {firstNonEmpty(u.CommonName, strings.TrimSpace(u.GivenName+" "+u.Surname), u.UID)}, "sn": {firstNonEmpty(u.Surname, u.UID)}, "userPassword": {u.Password}}
	for k, v := range map[string]string{"givenName": u.GivenName, "mail": u.Email, "description": u.Description, cs: u.CallSign, col: u.Color, role: u.Role} {
		if v != "" {
			attrs[k] = []string{v}
		}
	}
	if err := a.Add(dn, attrs); err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && le.Code == 65 {
			attrs["objectClass"] = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
			delete(attrs, cs)
			delete(attrs, col)
			delete(attrs, role)
			if err2 := a.Add(dn, attrs); err2 != nil {
				return "", err2
			}
		} else {
			return "", err
		}
	}
	for _, g := range u.Groups {
		if err := s.ldapAddMember(a, c, g, dn); err != nil {
			return dn, fmt.Errorf("user created, but adding to group %s failed: %w", g, err)
		}
	}
	return dn, nil
}

func (s *Server) ldapUsersList(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	q := r.URL.Query()
	cs, col, role := s.ldapAttrNames(c)
	parts := []string{"(objectClass=person)"}
	for k, attr := range map[string]string{"uid": "uid", "email": "mail", "givenName": "givenName", "surname": "sn", "callsign": cs} {
		if v := q.Get(k); v != "" {
			parts = append(parts, "("+attr+"=*"+ldap.EscapeFilter(v)+"*)")
		}
	}
	list, err := a.Search(s.ldapUserBase(c), "(&"+strings.Join(parts, "")+")", []string{"uid", "cn", "sn", "givenName", "mail", "description", "memberOf", "pwdAccountLockedTime", cs, col, role}, 5000)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	out := []takLdapUser{}
	for _, e := range list {
		out = append(out, s.ldapUserFromEntry(c, e))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ldapUserGet(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	e, err := s.ldapFindUser(a, c, r.PathValue("uid"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "LDAP Resource not found"})
		return
	}
	writeJSON(w, http.StatusOK, s.ldapUserFromEntry(c, *e))
}

func (s *Server) ldapUserCreate(w http.ResponseWriter, r *http.Request) {
	var u takLdapUser
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a user"})
		return
	}
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	if _, err := s.ldapCreateUser(a, c, u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	e, _ := s.ldapFindUser(a, c, u.UID)
	if e == nil {
		writeJSON(w, http.StatusOK, u)
		return
	}
	writeJSON(w, http.StatusOK, s.ldapUserFromEntry(c, *e))
}

func (s *Server) ldapUserUpdate(w http.ResponseWriter, r *http.Request) {
	var u takLdapUser
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&u); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a user"})
		return
	}
	if u.UID != "" && u.UID != r.PathValue("uid") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Changing UID forms an identity mutation and is not permitted after creation."})
		return
	}
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	e, err := s.ldapFindUser(a, c, r.PathValue("uid"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "LDAP Resource not found"})
		return
	}
	cs, col, role := s.ldapAttrNames(c)
	var ch []ldap.Change
	for attr, v := range map[string]string{"cn": u.CommonName, "givenName": u.GivenName, "sn": u.Surname, "mail": u.Email, "description": u.Description, cs: u.CallSign, col: u.Color, role: u.Role, "userPassword": u.Password} {
		if v != "" {
			ch = append(ch, ldap.Change{Op: ldap.ModReplace, Attr: attr, Values: []string{v}})
		}
	}
	if len(ch) > 0 {
		if err := a.Modify(e.DN, ch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if u.Groups != nil {
		if err := s.ldapSyncGroups(a, c, *e, u.Groups); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	e, _ = s.ldapFindUser(a, c, r.PathValue("uid"))
	writeJSON(w, http.StatusOK, s.ldapUserFromEntry(c, *e))
}

func (s *Server) ldapSyncGroups(a *ldap.Admin, c LDAPConfig, e ldap.Entry, want []string) error {
	var have []string
	for _, g := range e.Get("memberOf") {
		have = append(have, ldap.CommonName(g))
	}
	for _, g := range want {
		if !slices.ContainsFunc(have, func(h string) bool { return strings.EqualFold(h, g) }) {
			if err := s.ldapAddMember(a, c, g, e.DN); err != nil {
				return err
			}
		}
	}
	for _, g := range have {
		if !slices.ContainsFunc(want, func(x string) bool { return strings.EqualFold(x, g) }) {
			if err := s.ldapRemoveMember(a, c, g, e.DN); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) ldapUserDelete(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	e, err := s.ldapFindUser(a, c, r.PathValue("uid"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "LDAP Resource not found"})
		return
	}
	for _, g := range e.Get("memberOf") {
		s.ldapRemoveMember(a, c, ldap.CommonName(g), e.DN)
	}
	if err := a.Delete(e.DN); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) ldapUserLock(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	e, err := s.ldapFindUser(a, c, r.PathValue("uid"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "LDAP Resource not found"})
		return
	}
	lock := r.URL.Query().Get("lock") != "false"
	var ch ldap.Change
	if strings.EqualFold(c.Style, "AD") {
		flags := "512"
		if lock {
			flags = "514"
		}
		ch = ldap.Change{Op: ldap.ModReplace, Attr: "userAccountControl", Values: []string{flags}}
	} else if lock {
		ch = ldap.Change{Op: ldap.ModReplace, Attr: "pwdAccountLockedTime", Values: []string{"000001010000Z"}}
	} else {
		ch = ldap.Change{Op: ldap.ModDelete, Attr: "pwdAccountLockedTime"}
	}
	if err := a.Modify(e.DN, []ldap.Change{ch}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("LDAP account lock changed", "uid", r.PathValue("uid"), "locked", lock, "by", identityOf(r).Name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) ldapUserGroups(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var groups []string
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&groups); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of groups"})
			return
		}
		a, c, ok := s.ldapAdmin(w)
		if !ok {
			return
		}
		defer a.Close()
		e, err := s.ldapFindUser(a, c, r.PathValue("uid"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "LDAP Resource not found"})
			return
		}
		switch op {
		case "sync":
			err = s.ldapSyncGroups(a, c, *e, groups)
		case "add":
			for _, g := range groups {
				if err = s.ldapAddMember(a, c, g, e.DN); err != nil {
					break
				}
			}
		case "remove":
			for _, g := range groups {
				if err = s.ldapRemoveMember(a, c, g, e.DN); err != nil {
					break
				}
			}
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) ldapGroupsList(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	list, err := a.Search(s.ldapGroupBase(c), "(|(objectClass=groupOfNames)(objectClass=group)(objectClass=groupOfUniqueNames))", []string{"cn", "description", "member"}, 5000)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	out := []map[string]any{}
	for _, g := range list {
		out = append(out, map[string]any{"dn": g.DN, "name": g.First("cn"), "description": g.First("description"), "memberCount": len(g.Get("member"))})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ldapGroupUsers(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	g, err := a.Read(s.ldapGroupDN(c, r.PathValue("groupName")), []string{"member"})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "LDAP Resource not found"})
		return
	}
	out := []takLdapUser{}
	cs, col, role := s.ldapAttrNames(c)
	for _, m := range g.Get("member") {
		if e, err := a.Read(m, []string{"uid", "cn", "sn", "givenName", "mail", "memberOf", cs, col, role}); err == nil {
			out = append(out, s.ldapUserFromEntry(c, *e))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ldapGroupMembers(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var uids []string
		if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&uids); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON list of uids"})
			return
		}
		a, c, ok := s.ldapAdmin(w)
		if !ok {
			return
		}
		defer a.Close()
		group := r.PathValue("groupName")
		for _, uid := range uids {
			e, err := s.ldapFindUser(a, c, uid)
			if err != nil {
				continue
			}
			if op == "add" {
				err = s.ldapAddMember(a, c, group, e.DN)
			} else {
				err = s.ldapRemoveMember(a, c, group, e.DN)
			}
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) ldapGroupDelete(w http.ResponseWriter, r *http.Request) {
	a, c, ok := s.ldapAdmin(w)
	if !ok {
		return
	}
	defer a.Close()
	if err := a.Delete(s.ldapGroupDN(c, r.PathValue("groupName"))); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func parseLDAPUserCSV(r io.Reader) ([]takLdapUser, []string) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, []string{"CSV is not valid"}
	}
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	col := func(row []string, names ...string) string {
		for _, n := range names {
			if i, ok := idx[strings.ToLower(n)]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	var users []takLdapUser
	var problems []string
	for n, row := range rows[1:] {
		u := takLdapUser{UID: col(row, "uid", "username"), GivenName: col(row, "givenName", "firstName"), Surname: col(row, "surname", "sn", "lastName"),
			Email: col(row, "email", "mail"), Password: col(row, "password"), CallSign: col(row, "callsign", "callSign"), Color: col(row, "color"), Role: col(row, "role"),
			CommonName: col(row, "commonName", "cn"), Description: col(row, "description")}
		for _, g := range strings.FieldsFunc(col(row, "groups"), func(r rune) bool { return r == ';' || r == '|' }) {
			u.Groups = append(u.Groups, strings.TrimSpace(g))
		}
		if !validName.MatchString(u.UID) {
			problems = append(problems, fmt.Sprintf("line %d: invalid uid %q", n+2, u.UID))
			continue
		}
		if u.Password == "" {
			problems = append(problems, fmt.Sprintf("line %d: password missing for %s", n+2, u.UID))
			continue
		}
		users = append(users, u)
	}
	return users, problems
}

func (s *Server) ldapBulk(validateOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Config().LDAP.BulkImport {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Bulk Import is not enabled."})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		f, _, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upload a CSV file as file"})
			return
		}
		defer f.Close()
		users, problems := parseLDAPUserCSV(f)
		if validateOnly || len(problems) > 0 {
			status := http.StatusOK
			if len(problems) > 0 {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, map[string]any{"valid": len(problems) == 0, "users": len(users), "errors": problems})
			return
		}
		a, c, ok := s.ldapAdmin(w)
		if !ok {
			return
		}
		defer a.Close()
		created := 0
		for _, u := range users {
			if _, err := s.ldapCreateUser(a, c, u); err != nil {
				problems = append(problems, u.UID+": "+err.Error())
				continue
			}
			created++
		}
		writeJSON(w, http.StatusOK, map[string]any{"created": created, "errors": problems})
	}
}

func (s *Server) ldapMgmtRoutes(a func(string, http.HandlerFunc)) {
	p := "/Marti/api/ldap-user-management"
	a("GET "+p+"/users", s.ldapUsersList)
	a("POST "+p+"/users", s.ldapUserCreate)
	a("GET "+p+"/users/{uid}", s.ldapUserGet)
	a("PUT "+p+"/users/{uid}", s.ldapUserUpdate)
	a("DELETE "+p+"/users/{uid}", s.ldapUserDelete)
	a("POST "+p+"/users/{uid}/lock", s.ldapUserLock)
	a("POST "+p+"/users/{uid}/groups/add", s.ldapUserGroups("add"))
	a("POST "+p+"/users/{uid}/groups/remove", s.ldapUserGroups("remove"))
	a("POST "+p+"/users/{uid}/groups/sync", s.ldapUserGroups("sync"))
	a("POST "+p+"/users/bulkImport", s.ldapBulk(false))
	a("POST "+p+"/users/validateBulkImport", s.ldapBulk(true))
	a("GET "+p+"/groups", s.ldapGroupsList)
	a("DELETE "+p+"/groups/{groupName}", s.ldapGroupDelete)
	a("GET "+p+"/groups/{groupName}/users", s.ldapGroupUsers)
	a("POST "+p+"/groups/{groupName}/users/add", s.ldapGroupMembers("add"))
	a("POST "+p+"/groups/{groupName}/users/remove", s.ldapGroupMembers("remove"))
	a("GET "+p+"/isBulkImportEnabled", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.Config().LDAP.BulkImport) })
	a("GET "+p+"/isLdapTakComplient", func(w http.ResponseWriter, r *http.Request) {
		c := s.Config().LDAP
		writeJSON(w, http.StatusOK, c.Enabled && c.URL != "" && s.ldapUserBase(c) != "" && s.ldapCheckService(c) == nil)
	})
}
